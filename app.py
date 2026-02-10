import os
import uuid
from flask import Flask, request, redirect, url_for, send_from_directory, render_template, flash, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'satoru-secret-key'

# --- VIPパスワード ---
VIP_PASSWORD = "satoru123"

# --- アプリログイン情報（QR UUID + 6桁PIN） ---
APP_LOGIN_UUID = os.getenv("APP_LOGIN_UUID", "123e4567-e89b-12d3-a456-426614174000")
APP_LOGIN_PIN = os.getenv("APP_LOGIN_PIN", "123456")

# --- ディレクトリ ---
BLACKBOARD_FOLDER = 'blackboards'
os.makedirs(BLACKBOARD_FOLDER, exist_ok=True)

# --- ユーティリティ ---
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
                entries.append(f"{subject}/{filename}")
    return sorted(entries)


def is_valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


# --- ルート ---
@app.route('/')
def consent():
    return render_template('consent.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = request.args.get('next') or request.form.get('next') or url_for('app_index')

    if request.method == 'POST':
        qr_uuid = request.form.get('qr_uuid', '').strip().lower()
        pin = request.form.get('pin', '').strip()

        if not is_valid_uuid(qr_uuid):
            flash("UUID形式が正しくありません")
            return redirect(url_for('login', next=next_url))

        if not pin.isdigit() or len(pin) != 6:
            flash("PINは6桁の数字で入力してください")
            return redirect(url_for('login', next=next_url))

        if qr_uuid == APP_LOGIN_UUID.lower() and pin == APP_LOGIN_PIN:
            session['app_authenticated'] = True
            session['login_uuid'] = qr_uuid
            flash("ログイン成功")
            return redirect(next_url)

        flash("UUIDまたはPINが違います")
        return redirect(url_for('login', next=next_url))

    return render_template('login.html', next_url=next_url)


@app.route('/logout')
def logout():
    session.pop('app_authenticated', None)
    session.pop('login_uuid', None)
    flash("ログアウトしました")
    return redirect(url_for('login'))


@app.route('/app')
def app_index():
    if not session.get('app_authenticated'):
        return redirect(url_for('login', next=url_for('app_index')))

    folders = {}
    total_images = 0
    for folder_name in list_blackboard_subjects():
        folder_path = os.path.join(BLACKBOARD_FOLDER, folder_name)
        files = [
            name for name in os.listdir(folder_path)
            if os.path.isfile(os.path.join(folder_path, name))
        ]
        folders[folder_name] = sorted(files)
        total_images += len(files)

    return render_template(
        'app_index.html',
        folders=folders,
        total_subjects=len(folders),
        total_images=total_images,
    )


# --- Admin ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password != VIP_PASSWORD:
            flash("パスワード違います")
            return redirect(url_for('admin'))

        file = request.files.get('file')
        if file and file.filename:
            subject = secure_filename(request.form.get('subject', '').strip())
            if not subject:
                flash("教科名を入力してください")
                return redirect(url_for('admin'))

            subject_path = os.path.join(BLACKBOARD_FOLDER, subject)
            os.makedirs(subject_path, exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(subject_path, filename))
            flash(f"{subject}/{filename} をアップロードしました")
            return redirect(url_for('admin'))

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
            return redirect(url_for('admin'))

    subjects = list_blackboard_subjects()
    boards = list_blackboard_entries()
    return render_template('admin.html', boards=boards, subjects=subjects)




@app.route('/nas')
def nas():
    flash("NAS機能は廃止されました。黒板一覧をご利用ください。")
    return redirect(url_for('app_index'))

# --- 黒板ファイル表示 ---
@app.route('/blackboards/<path:filename>')
def blackboard_file(filename):
    if not session.get('app_authenticated'):
        return redirect(url_for('login', next=url_for('app_index')))
    return send_from_directory(BLACKBOARD_FOLDER, filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
