import json
import os
import random
import re
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
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('APP_SECRET_KEY', 'stable-v1-default-secret-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=2)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'

CREDENTIALS_FILE = 'credentials.json'
BLACKBOARD_FOLDER = 'blackboards'
COMMENTS_FILE = 'comments.json'
ACCESS_CONTROL_FILE = 'access_control.json'
NICKNAMES_FILE = 'nicknames.json'
AUDIT_LOG_FILE = 'audit_log.jsonl'

APP_NAME = 'BlackBoard-app-Beta-'
APP_VERSION = 'Stable Ver1.0'
APP_RELEASE_DATE = '2026-02-15'

LOCK_THRESHOLD = 3
MAX_NICKNAME_CHANGES = 5
NICKNAME_CHANGE_INTERVAL_DAYS = 7

# より本格的な禁止ワード（単純部分一致 + 正規表現）
ABUSIVE_PATTERNS = [
    r'死ね', r'ころす|殺す', r'消えろ', r'ぶっころ',
    r'ばか|バカ|馬鹿', r'あほ|アホ|阿呆', r'くず|クズ',
    r'きもい|キモい|気持ち悪', r'うざい', r'ゴミ',
    r'fuck', r'shit', r'bitch', r'asshole', r'nigger',
    r'レイプ', r'強姦', r'自殺しろ', r'障害者.*(死ね|消えろ)',
]

os.makedirs(BLACKBOARD_FOLDER, exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str):
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def normalize_next_url(raw_next: str, fallback: str) -> str:
    if raw_next and raw_next.startswith('/'):
        return raw_next
    return fallback


def load_json_file(path: str, default_value):
    if not os.path.exists(path):
        return default_value
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default_value


def save_json_file(path: str, data) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def append_audit_log(event: dict) -> None:
    event.setdefault('time', now_iso())
    with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')


def log_operation(action: str, success: bool, detail: str = '', target_uuid: str = '') -> None:
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
    rng = random.Random(seed)
    return [{'uuid': str(uuid.uuid4()), 'pin': f"{rng.randint(0, 999999):06d}"} for _ in range(count)]


def ensure_credentials_file():
    if os.path.exists(CREDENTIALS_FILE):
        return
    save_json_file(
        CREDENTIALS_FILE,
        {
            'users': generate_credential_entries(40, seed=202501),
            'admins': generate_credential_entries(2, seed=909909),
            'teachers': generate_credential_entries(20, seed=707070),
        },
    )


def load_credentials():
    ensure_credentials_file()
    raw = load_json_file(CREDENTIALS_FILE, {'users': [], 'admins': [], 'teachers': []})
    raw.setdefault('users', [])
    raw.setdefault('admins', [])
    raw.setdefault('teachers', [])
    return raw


def load_nicknames():
    data = load_json_file(NICKNAMES_FILE, {})
    return data if isinstance(data, dict) else {}


def save_nicknames(data):
    save_json_file(NICKNAMES_FILE, data)


def get_nickname_info(user_uuid: str):
    nicknames = load_nicknames()
    return nicknames.get(user_uuid, None)


def get_display_name(user_uuid: str):
    info = get_nickname_info(user_uuid)
    if info and info.get('nickname'):
        return info['nickname']
    return user_uuid[:8]


def nickname_change_status(user_uuid: str):
    info = get_nickname_info(user_uuid)
    if not info:
        return {'exists': False, 'can_change': True, 'remaining': MAX_NICKNAME_CHANGES, 'wait_days': 0}

    change_count = int(info.get('change_count', 0))
    remaining = max(0, MAX_NICKNAME_CHANGES - change_count)
    if change_count >= MAX_NICKNAME_CHANGES:
        return {'exists': True, 'can_change': False, 'remaining': 0, 'wait_days': -1}

    last_dt = parse_iso(info.get('last_changed_at', ''))
    if not last_dt:
        return {'exists': True, 'can_change': True, 'remaining': remaining, 'wait_days': 0}

    delta = datetime.now(timezone.utc) - last_dt
    if delta >= timedelta(days=NICKNAME_CHANGE_INTERVAL_DAYS):
        return {'exists': True, 'can_change': True, 'remaining': remaining, 'wait_days': 0}

    wait = NICKNAME_CHANGE_INTERVAL_DAYS - delta.days
    return {'exists': True, 'can_change': False, 'remaining': remaining, 'wait_days': wait}


def set_nickname(user_uuid: str, nickname: str):
    nicknames = load_nicknames()
    old = nicknames.get(user_uuid, {})
    change_count = int(old.get('change_count', 0))
    if old.get('nickname'):
        change_count += 1
    nicknames[user_uuid] = {
        'nickname': nickname,
        'change_count': change_count,
        'last_changed_at': now_iso(),
    }
    save_nicknames(nicknames)


def list_blackboard_subjects():
    return sorted([name for name in os.listdir(BLACKBOARD_FOLDER) if os.path.isdir(os.path.join(BLACKBOARD_FOLDER, name))])


def list_blackboard_entries():
    entries = []
    for subject in list_blackboard_subjects():
        subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
        for filename in os.listdir(subject_path):
            if os.path.isfile(os.path.join(subject_path, filename)):
                entries.append(f'{subject}/{filename}')
    return sorted(entries)


def build_folders_data():
    """教科フォルダ + 直下ファイル(未分類)をまとめて返す。"""
    folders = {}
    total_images = 0

    for folder_name in list_blackboard_subjects():
        folder_path = os.path.join(BLACKBOARD_FOLDER, folder_name)
        files = sorted([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
        folders[folder_name] = files
        total_images += len(files)

    # 旧構成互換: blackboards直下にある画像ファイルを「未分類」として表示
    root_files = sorted([
        name for name in os.listdir(BLACKBOARD_FOLDER)
        if os.path.isfile(os.path.join(BLACKBOARD_FOLDER, name))
    ])
    if root_files:
        folders['未分類'] = root_files
        total_images += len(root_files)

    return folders, total_images


def load_access_control():
    default = {
        'banned': [],
        'comment_banned': [],
        'locked_accounts': [],
        'allowlist_enabled': False,
        'allowlist': [],
        'incident_counts': {},
    }
    data = load_json_file(ACCESS_CONTROL_FILE, default)
    for k, v in default.items():
        data.setdefault(k, v)
    return data


def save_access_control(data):
    save_json_file(ACCESS_CONTROL_FILE, data)


def lock_account_if_needed(user_uuid: str, reason: str) -> tuple[bool, int]:
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


def is_session_fresh() -> bool:
    login_at = parse_iso(session.get('login_at', ''))
    if not login_at:
        return False
    return datetime.now(timezone.utc) - login_at <= timedelta(days=2)


def can_user_login(user_uuid: str) -> tuple[bool, str]:
    ac = load_access_control()
    if user_uuid in ac['locked_accounts']:
        return False, 'このUUIDは一時ロック中です。管理者の許可が必要です。'
    if user_uuid in ac['banned']:
        return False, 'このUUIDはアクセス停止（出禁）されています。'
    if ac['allowlist_enabled'] and user_uuid not in ac['allowlist']:
        return False, 'このUUIDは現在アクセス許可されていません。'
    return True, ''


def contains_abusive_text(text: str) -> bool:
    for pattern in ABUSIVE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False


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


@app.route('/')
def consent():
    return render_template('consent.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = normalize_next_url(request.args.get('next') or request.form.get('next'), url_for('app_index'))

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

        def login_session(role: str):
            session.permanent = True
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = role
            session['login_at'] = now_iso()

        if qr_uuid in admin_map and pin == str(admin_map[qr_uuid]):
            login_session('admin')
            log_operation('login_admin', True)
            if not get_nickname_info(qr_uuid):
                return redirect(url_for('nickname_setup', next=url_for('admin_home')))
            flash('管理者としてログインしました')
            return redirect(url_for('admin_home'))

        if qr_uuid in teacher_map and pin == str(teacher_map[qr_uuid]):
            login_session('teacher')
            log_operation('login_teacher', True)
            if not get_nickname_info(qr_uuid):
                return redirect(url_for('nickname_setup', next=url_for('teacher')))
            flash('先生としてログインしました')
            return redirect(url_for('teacher'))

        if qr_uuid in user_map and pin == str(user_map[qr_uuid]):
            allowed, reason = can_user_login(qr_uuid)
            if not allowed:
                log_operation('login_blocked', False, reason, target_uuid=qr_uuid)
                flash(reason)
                return redirect(url_for('login', next=next_url))
            login_session('user')
            log_operation('login_user', True)
            if not get_nickname_info(qr_uuid):
                return redirect(url_for('nickname_setup', next=next_url))
            flash('ログイン成功')
            return redirect(next_url)

        lock_account_if_needed(qr_uuid, '認証失敗')
        flash('UUIDまたはPINが違います')
        return redirect(url_for('login', next=next_url))

    return render_template('login.html', next_url=next_url)


@app.route('/profile/nickname', methods=['GET', 'POST'])
@login_required
def nickname_setup():
    user_uuid = session.get('login_uuid', '')
    next_url = normalize_next_url(request.args.get('next') or request.form.get('next'), url_for('app_index'))
    status = nickname_change_status(user_uuid)
    info = get_nickname_info(user_uuid)

    if request.method == 'POST':
        nickname = request.form.get('nickname', '').strip()
        if len(nickname) < 2 or len(nickname) > 20:
            flash('ニックネームは2〜20文字で入力してください')
            log_operation('nickname_change_failed', False, 'length invalid')
            return redirect(url_for('nickname_setup', next=next_url))

        status = nickname_change_status(user_uuid)
        if info and not status['can_change']:
            if status['wait_days'] == -1:
                flash('ニックネーム変更回数の上限（5回）に達しています')
            else:
                flash(f'ニックネーム変更は週1回までです。あと {status["wait_days"]} 日お待ちください')
            log_operation('nickname_change_failed', False, 'policy block')
            return redirect(url_for('nickname_setup', next=next_url))

        set_nickname(user_uuid, nickname)
        session['nickname'] = nickname
        log_operation('nickname_changed', True, nickname)
        flash('ニックネームを保存しました')
        return redirect(next_url)

    return render_template('nickname_setup.html', next_url=next_url, info=info, status=status)


@app.route('/logout')
def logout():
    log_operation('logout', True)
    session.clear()
    flash('ログアウトしました')
    return redirect(url_for('login'))


@app.route('/app')
@login_required
def app_index():
    folders, total_images = build_folders_data()
    return render_template('app_index.html', folders=folders, total_subjects=len(folders), total_images=total_images, is_admin=session.get('role') == 'admin', is_teacher=session.get('role') in {'teacher', 'admin'})


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


@app.route('/admin/logs/download')
@admin_required
def admin_logs_download():
    if not os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('')
    log_operation('admin_download_logs', True)
    return send_file(AUDIT_LOG_FILE, as_attachment=True, download_name='audit_log.jsonl')


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
                    log_operation('delete_file', False, '対象なし')
                    flash('削除対象が見つかりません')
            return redirect(url_for('admin_home'))

        if action in {'ban_uuid','unban_uuid','allow_uuid','disallow_uuid','comment_ban_uuid','comment_unban_uuid','lock_uuid','unlock_uuid','toggle_allowlist'}:
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
                flash(f"許可リスト制限を {'ON' if ac['allowlist_enabled'] else 'OFF'} に変更しました")

            save_access_control(ac)
            log_operation('uuid_control', True, action, target_uuid=target_uuid)
            return redirect(url_for('admin_home'))

    subjects = list_blackboard_subjects()
    boards = list_blackboard_entries()
    folders, total_images = build_folders_data()
    access_control = load_access_control()

    nickname_query = request.args.get('nickname_query', '').strip().lower()
    nickname_results = []
    if nickname_query:
        for uuid_key, info in load_nicknames().items():
            nick = info.get('nickname', '')
            if nickname_query in nick.lower():
                nickname_results.append({'uuid': uuid_key, 'nickname': nick, 'change_count': info.get('change_count', 0)})

    return render_template(
        'admin_home.html',
        boards=boards,
        subjects=subjects,
        folders=folders,
        total_subjects=len(folders),
        total_images=total_images,
        access_control=access_control,
        nickname_query=nickname_query,
        nickname_results=nickname_results,
    )


@app.route('/api/comments', methods=['GET'])
@login_required
def comments_list():
    image_key = request.args.get('image', '').strip()
    comments = load_json_file(COMMENTS_FILE, {})
    rows = comments.get(image_key, [])

    # 旧データ互換: author_nickname が無い場合は現在のニックネームを補完
    for row in rows:
        if not row.get('author_nickname') and row.get('author_uuid'):
            row['author_nickname'] = get_display_name(row['author_uuid'])

    return jsonify(rows)


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
    nickname = get_display_name(actor_uuid)

    if contains_abusive_text(text):
        comments[image_key].append(
            {
                'author_uuid': actor_uuid,
                'author_nickname': nickname,
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
            'author_nickname': nickname,
            'text': text,
            'created_at': now_iso(),
            'deleted': False,
        }
    )
    save_json_file(COMMENTS_FILE, comments)
    log_operation('comment_add', True, image_key)
    return jsonify({'ok': True})




@app.route('/settings')
@login_required
def settings():
    """通常ユーザー/先生向けの共通設定画面。"""
    role = session.get('role', 'user')
    uuid_value = session.get('login_uuid', '')
    status = nickname_change_status(uuid_value)
    info = get_nickname_info(uuid_value)

    ac = load_access_control()
    security_flags = {
        'locked': uuid_value in ac.get('locked_accounts', []),
        'comment_banned': uuid_value in ac.get('comment_banned', []),
        'banned': uuid_value in ac.get('banned', []),
    }

    return render_template(
        'settings.html',
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_release_date=APP_RELEASE_DATE,
        role=role,
        login_uuid=uuid_value,
        nickname_info=info,
        nickname_status=status,
        security_flags=security_flags,
        is_admin=(role == 'admin'),
        is_teacher=(role in {'teacher', 'admin'}),
    )


@app.route('/admin/settings')
@admin_required
def admin_settings():
    """管理者向け設定画面。"""
    ac = load_access_control()
    return render_template(
        'admin_settings.html',
        app_name=APP_NAME,
        app_version=APP_VERSION,
        app_release_date=APP_RELEASE_DATE,
        locked_count=len(ac.get('locked_accounts', [])),
        banned_count=len(ac.get('banned', [])),
        comment_banned_count=len(ac.get('comment_banned', [])),
        allowlist_enabled=ac.get('allowlist_enabled', False),
        allowlist_count=len(ac.get('allowlist', [])),
        incident_count=len(ac.get('incident_counts', {})),
    )

@app.route('/nas')
def nas():
    flash('NAS機能は廃止されました。黒板一覧をご利用ください。')
    return redirect(url_for('app_index'))


@app.route('/blackboards/<path:filename>')
@login_required
def blackboard_file(filename):
    return send_from_directory(BLACKBOARD_FOLDER, filename)


if __name__ == '__main__':
    ensure_credentials_file()
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = os.environ.get('APP_HOST', '0.0.0.0')
    port = int(os.environ.get('APP_PORT', '8080'))
    app.run(host=host, port=port, debug=debug_mode)
