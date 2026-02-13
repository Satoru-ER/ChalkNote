import json
import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'satoru-secret-key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=2)

# --- ログイン設定 ---
# credentials.json内に一般/管理者/先生のUUID+PINペアを保持する。
CREDENTIALS_FILE = 'credentials.json'

# --- データ保存ファイル ---
BLACKBOARD_FOLDER = 'blackboards'
COMMENTS_FILE = 'comments.json'
ACCESS_CONTROL_FILE = 'access_control.json'
AUDIT_LOG_FILE = 'audit_log.jsonl'

# --- 不正操作の閾値 ---
LOCK_THRESHOLD = 3

# コメント禁止対象の簡易ワード（必要に応じて増やせる）
ABUSIVE_WORDS = [
    'ばか', 'バカ', '死ね', 'しね', '殺す', 'ころす',
    'うざい', 'きもい', 'fuck', 'shit', 'idiot'
]

os.makedirs(BLACKBOARD_FOLDER, exist_ok=True)


# --- 汎用ユーティリティ ---
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_valid_uuid(value: str) -> bool:
    """UUID文字列として妥当かチェックする。"""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def normalize_next_url(raw_next: str, fallback: str) -> str:
    """オープンリダイレクト対策: 相対パスのみ許可。"""
    if raw_next and raw_next.startswith('/'):
        return raw_next
    return fallback


def load_json_file(path: str, default_value):
    """JSONファイルを読み込み、無い/壊れている場合は既定値を返す。"""
    if not os.path.exists(path):
        return default_value
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default_value


def save_json_file(path: str, data) -> None:
    """JSONファイルへUTF-8で保存する。"""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def append_audit_log(event: dict) -> None:
    """監査ログ(JSON Lines)へ1行追記する。"""
    event.setdefault('time', now_iso())
    with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')


def log_operation(action: str, success: bool, detail: str = '', target_uuid: str = '') -> None:
    """ユーザー操作ログを保存する。"""
    append_audit_log(
        {
            'type': 'operation',
            'action': action,
            'success': success,
            'detail': detail,
            'target_uuid': target_uuid,
            'actor_uuid': session.get('login_uuid', ''),
            'role': session.get('role', 'anonymous'),
            'path': request.path,
            'method': request.method,
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        }
    )


def generate_credential_entries(count: int, seed: int):
    """再現可能なUUID+6桁PINの組を生成する。"""
    rng = random.Random(seed)
    entries = []
    for _ in range(count):
        entries.append(
            {
                'uuid': str(uuid.uuid4()),
                'pin': f"{rng.randint(0, 999999):06d}",
            }
        )
    return entries


def ensure_credentials_file():
    """credentials.json が無ければ既定の件数で作成する。"""
    if os.path.exists(CREDENTIALS_FILE):
        return

    data = {
        'users': generate_credential_entries(40, seed=202501),
        'admins': generate_credential_entries(2, seed=909909),
        'teachers': generate_credential_entries(20, seed=707070),
    }
    save_json_file(CREDENTIALS_FILE, data)


def load_credentials():
    """UUID+PINの認証データを読み込む。"""
    ensure_credentials_file()
    raw = load_json_file(CREDENTIALS_FILE, {'users': [], 'admins': [], 'teachers': []})
    raw.setdefault('users', [])
    raw.setdefault('admins', [])
    raw.setdefault('teachers', [])
    return raw


# --- 画像一覧ユーティリティ ---
def list_blackboard_subjects():
    subjects = []
    for name in os.listdir(BLACKBOARD_FOLDER):
        path = os.path.join(BLACKBOARD_FOLDER, name)
        if os.path.isdir(path):
            subjects.append(name)
    return sorted(subjects)


def list_blackboard_entries():
    entries = []
    for subject in list_blackboard_subjects():
        subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
        for filename in os.listdir(subject_path):
            file_path = os.path.join(subject_path, filename)
            if os.path.isfile(file_path):
                entries.append(f'{subject}/{filename}')
    return sorted(entries)


def build_folders_data():
    folders = {}
    total_images = 0
    for folder_name in list_blackboard_subjects():
        folder_path = os.path.join(BLACKBOARD_FOLDER, folder_name)
        files = [
            name for name in os.listdir(folder_path)
            if os.path.isfile(os.path.join(folder_path, name))
        ]
        files = sorted(files)
        folders[folder_name] = files
        total_images += len(files)
    return folders, total_images


# --- UUIDアクセス制御ユーティリティ ---
def load_access_control():
    """アクセス制御設定を読み込む（出禁/許可/コメント禁止/ロック）。"""
    default = {
        'banned': [],
        'comment_banned': [],
        'locked_accounts': [],
        'allowlist_enabled': False,
        'allowlist': [],
        'incident_counts': {},
    }
    data = load_json_file(ACCESS_CONTROL_FILE, default)

    data.setdefault('banned', [])
    data.setdefault('comment_banned', [])
    data.setdefault('locked_accounts', [])
    data.setdefault('allowlist_enabled', False)
    data.setdefault('allowlist', [])
    data.setdefault('incident_counts', {})
    return data


def save_access_control(data):
    save_json_file(ACCESS_CONTROL_FILE, data)


def lock_account_if_needed(user_uuid: str, reason: str) -> tuple[bool, int]:
    """不正回数を加算し、閾値超過でロックする。"""
    ac = load_access_control()
    counts = ac.get('incident_counts', {})
    counts[user_uuid] = int(counts.get(user_uuid, 0)) + 1
    ac['incident_counts'] = counts

    locked = False
    if counts[user_uuid] >= LOCK_THRESHOLD and user_uuid not in ac['locked_accounts']:
        ac['locked_accounts'].append(user_uuid)
        locked = True

    ac['locked_accounts'] = sorted(set(ac['locked_accounts']))
    save_access_control(ac)

    log_operation('security_incident', False, f'{reason} / count={counts[user_uuid]}', target_uuid=user_uuid)
    if locked:
        log_operation('account_locked', False, '閾値超過により一時ロック', target_uuid=user_uuid)
    return locked, counts[user_uuid]


def clear_incidents(user_uuid: str):
    """管理者許可時にインシデント回数をクリアする。"""
    ac = load_access_control()
    ac['incident_counts'].pop(user_uuid, None)
    save_access_control(ac)


def is_session_fresh() -> bool:
    """最終認証から2日以内かを確認する。"""
    login_at = session.get('login_at')
    if not login_at:
        return False
    try:
        dt = datetime.fromisoformat(login_at)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - dt <= timedelta(days=2)


def can_user_login(user_uuid: str) -> tuple[bool, str]:
    """一般ユーザーUUIDがログイン可能か判定する。"""
    ac = load_access_control()

    if user_uuid in ac['locked_accounts']:
        return False, 'このUUIDは一時ロック中です。管理者の許可が必要です。'

    if user_uuid in ac['banned']:
        return False, 'このUUIDはアクセス停止（出禁）されています。'

    if ac['allowlist_enabled'] and user_uuid not in ac['allowlist']:
        return False, 'このUUIDは現在アクセス許可されていません。'

    return True, ''


def contains_abusive_text(text: str) -> bool:
    lowered = text.lower()
    return any(word.lower() in lowered for word in ABUSIVE_WORDS)


# --- リクエスト監査ログ ---
@app.before_request
def on_before_request():
    g.req_started = now_iso()


@app.after_request
def on_after_request(response):
    append_audit_log(
        {
            'type': 'request',
            'started_at': getattr(g, 'req_started', now_iso()),
            'time': now_iso(),
            'path': request.path,
            'method': request.method,
            'status': response.status_code,
            'actor_uuid': session.get('login_uuid', ''),
            'role': session.get('role', 'anonymous'),
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        }
    )
    return response


# --- 認可デコレータ ---
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('app_authenticated') or not is_session_fresh():
            session.clear()
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('app_authenticated') or not is_session_fresh():
            session.clear()
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash('管理者権限が必要です')
            log_operation('admin_access_denied', False, '管理者権限なし')
            return redirect(url_for('app_index'))
        return view_func(*args, **kwargs)

    return wrapped


# --- ルート ---
@app.route('/')
def consent():
    return render_template('consent.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = normalize_next_url(
        request.args.get('next') or request.form.get('next'),
        url_for('app_index')
    )

    if request.method == 'POST':
        qr_uuid = request.form.get('qr_uuid', '').strip().lower()
        pin = request.form.get('pin', '').strip()

        if not is_valid_uuid(qr_uuid):
            log_operation('login_failed', False, 'UUID形式不正', target_uuid=qr_uuid)
            flash('UUID形式が正しくありません')
            return redirect(url_for('login', next=next_url))

        if not pin.isdigit() or len(pin) != 6:
            lock_account_if_needed(qr_uuid, 'PIN形式不正')
            flash('PINは6桁の数字で入力してください')
            return redirect(url_for('login', next=next_url))

        creds = load_credentials()
        admin_map = {row['uuid'].lower(): row['pin'] for row in creds['admins'] if 'uuid' in row and 'pin' in row}
        teacher_map = {row['uuid'].lower(): row['pin'] for row in creds['teachers'] if 'uuid' in row and 'pin' in row}
        user_map = {row['uuid'].lower(): row['pin'] for row in creds['users'] if 'uuid' in row and 'pin' in row}

        # 管理者ログイン
        if qr_uuid in admin_map and pin == str(admin_map[qr_uuid]):
            session.permanent = True
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'admin'
            session['login_at'] = now_iso()
            log_operation('login_admin', True)
            flash('管理者としてログインしました')
            return redirect(url_for('admin_home'))

        # 先生ログイン
        if qr_uuid in teacher_map and pin == str(teacher_map[qr_uuid]):
            session.permanent = True
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'teacher'
            session['login_at'] = now_iso()
            log_operation('login_teacher', True)
            flash('先生としてログインしました')
            return redirect(url_for('teacher'))

        # 一般ユーザーログイン
        if qr_uuid in user_map and pin == str(user_map[qr_uuid]):
            allowed, reason = can_user_login(qr_uuid)
            if not allowed:
                log_operation('login_blocked', False, reason, target_uuid=qr_uuid)
                flash(reason)
                return redirect(url_for('login', next=next_url))

            session.permanent = True
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'user'
            session['login_at'] = now_iso()
            log_operation('login_user', True)
            flash('ログイン成功')
            return redirect(next_url)

        lock_account_if_needed(qr_uuid, '認証失敗')
        flash('UUIDまたはPINが違います')
        return redirect(url_for('login', next=next_url))

    return render_template('login.html', next_url=next_url)


@app.route('/logout')
def logout():
    log_operation('logout', True)
    session.pop('app_authenticated', None)
    session.pop('login_uuid', None)
    session.pop('role', None)
    session.pop('login_at', None)
    flash('ログアウトしました')
    return redirect(url_for('login'))


@app.route('/app')
@login_required
def app_index():
    folders, total_images = build_folders_data()
    return render_template(
        'app_index.html',
        folders=folders,
        total_subjects=len(folders),
        total_images=total_images,
        is_admin=session.get('role') == 'admin'
    )


@app.route('/teacher')
@login_required
def teacher():
    if session.get('role') not in {'teacher', 'admin'}:
        log_operation('teacher_access_denied', False)
        flash('先生ページにアクセスする権限がありません')
        return redirect(url_for('app_index'))
    return render_template('teacher.html')


@app.route('/admin')
@admin_required
def admin():
    return redirect(url_for('admin_home'))


@app.route('/admin/home', methods=['GET', 'POST'])
@admin_required
def admin_home():
    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'upload':
            file = request.files.get('file')
            subject = secure_filename(request.form.get('subject', '').strip())
            if not subject:
                flash('教科名を入力してください')
                log_operation('upload_failed', False, '教科名なし')
                return redirect(url_for('admin_home'))
            if not file or not file.filename:
                flash('アップロードファイルを選択してください')
                log_operation('upload_failed', False, 'ファイルなし')
                return redirect(url_for('admin_home'))

            subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
            os.makedirs(subject_path, exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(subject_path, filename))
            log_operation('upload', True, f'{subject}/{filename}')
            flash(f'{subject}/{filename} をアップロードしました')
            return redirect(url_for('admin_home'))

        if action == 'delete_file':
            delete_file = request.form.get('delete', '').strip()
            if delete_file:
                target_path = os.path.normpath(os.path.join(BLACKBOARD_FOLDER, delete_file))
                abs_target = os.path.abspath(target_path)
                abs_root = os.path.abspath(BLACKBOARD_FOLDER)
                if abs_target.startswith(abs_root) and os.path.isfile(abs_target):
                    os.remove(abs_target)
                    log_operation('delete_file', True, delete_file)
                    flash(f'{delete_file} を削除しました')
                else:
                    log_operation('delete_file', False, '対象なし', target_uuid=session.get('login_uuid', ''))
                    flash('削除対象が見つかりません')
            return redirect(url_for('admin_home'))

        if action in {
            'ban_uuid', 'unban_uuid',
            'allow_uuid', 'disallow_uuid',
            'comment_ban_uuid', 'comment_unban_uuid',
            'lock_uuid', 'unlock_uuid',
            'toggle_allowlist'
        }:
            ac = load_access_control()
            target_uuid = request.form.get('target_uuid', '').strip().lower()

            if action != 'toggle_allowlist' and not is_valid_uuid(target_uuid):
                flash('UUID形式が正しくありません')
                log_operation('uuid_control_failed', False, action, target_uuid=target_uuid)
                return redirect(url_for('admin_home'))

            if action == 'ban_uuid':
                ac['banned'] = sorted(set(ac['banned'] + [target_uuid]))
                flash(f'{target_uuid} を出禁にしました')

            elif action == 'unban_uuid':
                ac['banned'] = [u for u in ac['banned'] if u != target_uuid]
                flash(f'{target_uuid} の出禁を解除しました')

            elif action == 'allow_uuid':
                ac['allowlist'] = sorted(set(ac['allowlist'] + [target_uuid]))
                flash(f'{target_uuid} を許可リストに追加しました')

            elif action == 'disallow_uuid':
                ac['allowlist'] = [u for u in ac['allowlist'] if u != target_uuid]
                flash(f'{target_uuid} を許可リストから削除しました')

            elif action == 'comment_ban_uuid':
                ac['comment_banned'] = sorted(set(ac['comment_banned'] + [target_uuid]))
                flash(f'{target_uuid} をコメント禁止にしました')

            elif action == 'comment_unban_uuid':
                ac['comment_banned'] = [u for u in ac['comment_banned'] if u != target_uuid]
                flash(f'{target_uuid} のコメント禁止を解除しました')

            elif action == 'lock_uuid':
                ac['locked_accounts'] = sorted(set(ac['locked_accounts'] + [target_uuid]))
                flash(f'{target_uuid} を一時ロックしました')

            elif action == 'unlock_uuid':
                ac['locked_accounts'] = [u for u in ac['locked_accounts'] if u != target_uuid]
                ac['incident_counts'].pop(target_uuid, None)
                flash(f'{target_uuid} の一時ロックを解除しました')

            elif action == 'toggle_allowlist':
                ac['allowlist_enabled'] = not ac['allowlist_enabled']
                mode = 'ON' if ac['allowlist_enabled'] else 'OFF'
                flash(f'許可リスト制限を {mode} に変更しました')

            save_access_control(ac)
            log_operation('uuid_control', True, action, target_uuid=target_uuid)
            return redirect(url_for('admin_home'))

    subjects = list_blackboard_subjects()
    boards = list_blackboard_entries()
    folders, total_images = build_folders_data()
    access_control = load_access_control()
    return render_template(
        'admin_home.html',
        boards=boards,
        subjects=subjects,
        folders=folders,
        total_subjects=len(folders),
        total_images=total_images,
        access_control=access_control,
    )


@app.route('/api/comments', methods=['GET'])
@login_required
def comments_list():
    image_key = request.args.get('image', '').strip()
    comments = load_json_file(COMMENTS_FILE, {})
    return jsonify(comments.get(image_key, []))


@app.route('/api/comments', methods=['POST'])
@login_required
def comments_add():
    image_key = request.form.get('image', '').strip()
    text = request.form.get('text', '').strip()
    actor_uuid = session.get('login_uuid', 'unknown')

    if '/' not in image_key:
        lock_account_if_needed(actor_uuid, 'コメント投稿: image不正')
        return jsonify({'ok': False, 'error': 'imageが不正です'}), 400
    if not text:
        return jsonify({'ok': False, 'error': 'コメントを入力してください'}), 400
    if len(text) > 300:
        lock_account_if_needed(actor_uuid, 'コメント投稿: 文字数超過')
        return jsonify({'ok': False, 'error': 'コメントは300文字以内です'}), 400

    ac = load_access_control()

    if session.get('role') != 'admin' and actor_uuid in ac.get('locked_accounts', []):
        return jsonify({'ok': False, 'error': 'このUUIDは一時ロック中です。管理者の許可が必要です。'}), 403

    if session.get('role') != 'admin' and actor_uuid in ac.get('comment_banned', []):
        lock_account_if_needed(actor_uuid, 'コメント禁止中に投稿')
        return jsonify({'ok': False, 'error': 'このUUIDはコメント禁止設定中です'}), 403

    comments = load_json_file(COMMENTS_FILE, {})
    comments.setdefault(image_key, [])

    # 暴言検出: 即時削除表示 + コメント禁止 + インシデント加算
    if contains_abusive_text(text):
        comments[image_key].append(
            {
                'author_uuid': actor_uuid,
                'text': 'このコメントは削除されました',
                'created_at': now_iso(),
                'deleted': True,
                'deleted_reason': 'abusive',
            }
        )
        save_json_file(COMMENTS_FILE, comments)

        ac['comment_banned'] = sorted(set(ac.get('comment_banned', []) + [actor_uuid]))
        save_access_control(ac)
        locked, count = lock_account_if_needed(actor_uuid, '暴言コメント検出')

        log_operation('comment_deleted_by_moderation', False, f'count={count} locked={locked}', target_uuid=actor_uuid)
        return jsonify({'ok': False, 'error': '暴言が検出されたためコメントは削除されました。コメント禁止になりました。'}), 403

    comments[image_key].append(
        {
            'author_uuid': actor_uuid,
            'text': text,
            'created_at': now_iso(),
            'deleted': False,
        }
    )
    save_json_file(COMMENTS_FILE, comments)
    log_operation('comment_add', True, image_key)
    return jsonify({'ok': True})


@app.route('/nas')
def nas():
    flash('NAS機能は廃止されました。黒板一覧をご利用ください。')
    return redirect(url_for('app_index'))


@app.route('/blackboards/<path:filename>')
@login_required
def blackboard_file(filename):
    if not session.get('app_authenticated'):
        return redirect(url_for('login', next=url_for('app_index')))
    return send_from_directory(BLACKBOARD_FOLDER, filename)


if __name__ == '__main__':
    ensure_credentials_file()
    app.run(host='0.0.0.0', port=8080, debug=True)
