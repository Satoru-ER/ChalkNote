import json
import os
import uuid
import random
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    flash,
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

# --- ログイン設定 ---
# credentials.json内に一般/管理者のUUID+PINペアを保持する。
# 既存ファイルが無ければ40件ずつ自動生成する。
CREDENTIALS_FILE = 'credentials.json'

# --- ディレクトリ/データ保存ファイル ---
BLACKBOARD_FOLDER = 'blackboards'
COMMENTS_FILE = 'comments.json'
ACCESS_CONTROL_FILE = 'access_control.json'

os.makedirs(BLACKBOARD_FOLDER, exist_ok=True)


# --- 汎用ユーティリティ ---
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


def generate_credential_entries(count: int, seed: int):
    """再現可能なUUID+6桁PINの組を生成する。"""
    rng = random.Random(seed)
    entries = []
    for _ in range(count):
        entries.append(
            {
                "uuid": str(uuid.uuid4()),
                "pin": f"{rng.randint(0, 999999):06d}",
            }
        )
    return entries


def ensure_credentials_file():
    """credentials.json が無ければ一般/管理者40件ずつ作成する。"""
    if os.path.exists(CREDENTIALS_FILE):
        return

    data = {
        "users": generate_credential_entries(40, seed=202501),
        "admins": generate_credential_entries(2, seed=909909),
        "teachers": generate_credential_entries(20, seed=707070),
    }
    save_json_file(CREDENTIALS_FILE, data)


def load_credentials():
    """UUID+PINの認証データを読み込む。"""
    ensure_credentials_file()
    raw = load_json_file(CREDENTIALS_FILE, {"users": [], "admins": [], "teachers": []})
    raw.setdefault("users", [])
    raw.setdefault("admins", [])
    raw.setdefault("teachers", [])
    return raw


# --- 画像一覧ユーティリティ ---
def list_blackboard_subjects():
    """blackboards配下の教科フォルダ名だけを返す。"""
    subjects = []
    for name in os.listdir(BLACKBOARD_FOLDER):
        path = os.path.join(BLACKBOARD_FOLDER, name)
        if os.path.isdir(path):
            subjects.append(name)
    return sorted(subjects)


def list_blackboard_entries():
    """削除UI向けに subject/filename 形式の一覧を返す。"""
    entries = []
    for subject in list_blackboard_subjects():
        subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
        for filename in os.listdir(subject_path):
            file_path = os.path.join(subject_path, filename)
            if os.path.isfile(file_path):
                entries.append(f"{subject}/{filename}")
    return sorted(entries)


def build_folders_data():
    """一覧/管理画面で使うフォルダ→画像配列と合計枚数を返す。"""
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
    """アクセス制御設定を読み込む（出禁/許可/コメント禁止）。"""
    default = {
        "banned": [],
        "comment_banned": [],
        "allowlist_enabled": False,
        "allowlist": [],
    }
    data = load_json_file(ACCESS_CONTROL_FILE, default)

    data.setdefault("banned", [])
    data.setdefault("comment_banned", [])
    data.setdefault("allowlist_enabled", False)
    data.setdefault("allowlist", [])
    return data


def save_access_control(data):
    save_json_file(ACCESS_CONTROL_FILE, data)


def can_user_login(user_uuid: str) -> tuple[bool, str]:
    """一般ユーザーUUIDがログイン可能か判定する。"""
    ac = load_access_control()

    if user_uuid in ac["banned"]:
        return False, "このUUIDはアクセス停止（出禁）されています。"

    if ac["allowlist_enabled"] and user_uuid not in ac["allowlist"]:
        return False, "このUUIDは現在アクセス許可されていません。"

    return True, ""


# --- 認可デコレータ ---
def login_required(view_func):
    """ログイン済みユーザーのみ許可。"""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('app_authenticated'):
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """管理者ロールのみ許可。"""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('app_authenticated'):
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash('管理者権限が必要です')
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
            flash("UUID形式が正しくありません")
            return redirect(url_for('login', next=next_url))

        if not pin.isdigit() or len(pin) != 6:
            flash("PINは6桁の数字で入力してください")
            return redirect(url_for('login', next=next_url))

        creds = load_credentials()
        admin_map = {row['uuid'].lower(): row['pin'] for row in creds['admins'] if 'uuid' in row and 'pin' in row}
        teacher_map = {row['uuid'].lower(): row['pin'] for row in creds['teachers'] if 'uuid' in row and 'pin' in row}
        user_map = {row['uuid'].lower(): row['pin'] for row in creds['users'] if 'uuid' in row and 'pin' in row}

        # 管理者ログイン（管理者リストのUUID+PIN一致）
        if qr_uuid in admin_map and pin == str(admin_map[qr_uuid]):
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'admin'
            flash("管理者としてログインしました")
            return redirect(url_for('admin_home'))

        # 先生ログイン（先生リストのUUID+PIN一致）
        if qr_uuid in teacher_map and pin == str(teacher_map[qr_uuid]):
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'teacher'
            flash("先生としてログインしました")
            return redirect(url_for('teacher'))

        # 一般ユーザーログイン（一般リストのUUID+PIN一致 + UUID制限）
        if qr_uuid in user_map and pin == str(user_map[qr_uuid]):
            allowed, reason = can_user_login(qr_uuid)
            if not allowed:
                flash(reason)
                return redirect(url_for('login', next=next_url))

            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            session['role'] = 'user'
            flash("ログイン成功")
            return redirect(next_url)

        flash("UUIDまたはPINが違います")
        return redirect(url_for('login', next=next_url))

    return render_template('login.html', next_url=next_url)


@app.route('/logout')
def logout():
    session.pop('app_authenticated', None)
    session.pop('login_uuid', None)
    session.pop('role', None)
    flash("ログアウトしました")
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
    """先生ロール向けホーム。"""
    if session.get('role') not in {'teacher', 'admin'}:
        flash('先生ページにアクセスする権限がありません')
        return redirect(url_for('app_index'))
    return render_template('teacher.html')

@app.route('/admin')
@admin_required
def admin():
    """旧URL互換: /admin/home へ誘導する。"""
    return redirect(url_for('admin_home'))


@app.route('/admin/home', methods=['GET', 'POST'])
@admin_required
def admin_home():
    """管理者ホーム: 画像管理 + UUIDアクセス制御 + 画像閲覧。"""
    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        # 1) 画像アップロード
        if action == 'upload':
            file = request.files.get('file')
            subject = secure_filename(request.form.get('subject', '').strip())
            if not subject:
                flash("教科名を入力してください")
                return redirect(url_for('admin_home'))
            if not file or not file.filename:
                flash("アップロードファイルを選択してください")
                return redirect(url_for('admin_home'))

            subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
            os.makedirs(subject_path, exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(subject_path, filename))
            flash(f"{subject}/{filename} をアップロードしました")
            return redirect(url_for('admin_home'))

        # 2) 画像削除
        if action == 'delete_file':
            delete_file = request.form.get('delete', '').strip()
            if delete_file:
                target_path = os.path.normpath(os.path.join(BLACKBOARD_FOLDER, delete_file))
                abs_target = os.path.abspath(target_path)
                abs_root = os.path.abspath(BLACKBOARD_FOLDER)
                if abs_target.startswith(abs_root) and os.path.isfile(abs_target):
                    os.remove(abs_target)
                    flash(f"{delete_file} を削除しました")
                else:
                    flash("削除対象が見つかりません")
            return redirect(url_for('admin_home'))

        # 3) UUID制御
        if action in {
            'ban_uuid', 'unban_uuid',
            'allow_uuid', 'disallow_uuid',
            'comment_ban_uuid', 'comment_unban_uuid',
            'toggle_allowlist'
        }:
            ac = load_access_control()
            target_uuid = request.form.get('target_uuid', '').strip().lower()

            if action != 'toggle_allowlist' and not is_valid_uuid(target_uuid):
                flash("UUID形式が正しくありません")
                return redirect(url_for('admin_home'))

            if action == 'ban_uuid':
                if target_uuid not in ac['banned']:
                    ac['banned'].append(target_uuid)
                flash(f"{target_uuid} を出禁にしました")

            elif action == 'unban_uuid':
                ac['banned'] = [u for u in ac['banned'] if u != target_uuid]
                flash(f"{target_uuid} の出禁を解除しました")

            elif action == 'allow_uuid':
                if target_uuid not in ac['allowlist']:
                    ac['allowlist'].append(target_uuid)
                flash(f"{target_uuid} を許可リストに追加しました")

            elif action == 'disallow_uuid':
                ac['allowlist'] = [u for u in ac['allowlist'] if u != target_uuid]
                flash(f"{target_uuid} を許可リストから削除しました")

            elif action == 'comment_ban_uuid':
                if target_uuid not in ac['comment_banned']:
                    ac['comment_banned'].append(target_uuid)
                flash(f"{target_uuid} をコメント禁止にしました")

            elif action == 'comment_unban_uuid':
                ac['comment_banned'] = [u for u in ac['comment_banned'] if u != target_uuid]
                flash(f"{target_uuid} のコメント禁止を解除しました")

            elif action == 'toggle_allowlist':
                ac['allowlist_enabled'] = not ac['allowlist_enabled']
                mode = "ON" if ac['allowlist_enabled'] else "OFF"
                flash(f"許可リスト制限を {mode} に変更しました")

            ac['banned'] = sorted(set(ac['banned']))
            ac['allowlist'] = sorted(set(ac['allowlist']))
            ac['comment_banned'] = sorted(set(ac['comment_banned']))
            save_access_control(ac)
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
    """画像キー(subject/file)に紐づくコメント一覧を返す。"""
    image_key = request.args.get('image', '').strip()
    comments = load_json_file(COMMENTS_FILE, {})
    return jsonify(comments.get(image_key, []))


@app.route('/api/comments', methods=['POST'])
@login_required
def comments_add():
    """ログインUUID名義で画像コメントを追加する。"""
    image_key = request.form.get('image', '').strip()
    text = request.form.get('text', '').strip()

    if '/' not in image_key:
        return jsonify({'ok': False, 'error': 'imageが不正です'}), 400
    if not text:
        return jsonify({'ok': False, 'error': 'コメントを入力してください'}), 400
    if len(text) > 300:
        return jsonify({'ok': False, 'error': 'コメントは300文字以内です'}), 400

    # コメント禁止UUIDは投稿不可（管理者は除外）
    if session.get('role') != 'admin':
        ac = load_access_control()
        if session.get('login_uuid') in ac.get('comment_banned', []):
            return jsonify({'ok': False, 'error': 'このUUIDはコメント禁止設定中です'}), 403

    comments = load_json_file(COMMENTS_FILE, {})
    comments.setdefault(image_key, [])
    comments[image_key].append(
        {
            'author_uuid': session.get('login_uuid', 'unknown'),
            'text': text,
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    )
    save_json_file(COMMENTS_FILE, comments)
    return jsonify({'ok': True})


@app.route('/nas')
def nas():
    flash("NAS機能は廃止されました。黒板一覧をご利用ください。")
    return redirect(url_for('app_index'))


# --- 黒板ファイル表示 ---
@app.route('/blackboards/<path:filename>')
@login_required
def blackboard_file(filename):
    if not session.get('app_authenticated'):
        return redirect(url_for('login', next=url_for('app_index')))
    return send_from_directory(BLACKBOARD_FOLDER, filename)


if __name__ == '__main__':
    ensure_credentials_file()
    app.run(host='0.0.0.0', port=8080, debug=True)
