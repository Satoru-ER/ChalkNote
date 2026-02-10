import os
from flask import Flask, request, redirect, url_for, send_from_directory, render_template, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'satoru-secret-key'

# --- VIPパスワード ---
VIP_PASSWORD = "satoru123"

# --- ディレクトリ ---
BLACKBOARD_FOLDER = 'blackboards'
NAS_FOLDER = 'nas'
NAS_CAP = 1 * 1024 * 1024 * 1024  # 1GB

os.makedirs(BLACKBOARD_FOLDER, exist_ok=True)
os.makedirs(NAS_FOLDER, exist_ok=True)

# --- ユーティリティ ---
def get_nas_size():
    total = 0
    for f in os.listdir(NAS_FOLDER):
        total += os.path.getsize(os.path.join(NAS_FOLDER, f))
    return total

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

# --- ルート ---
@app.route('/')
def consent():
    return render_template('consent.html')

@app.route('/app')
def app_index():
    # boardsを辞書型にする（フォルダ→ファイルリスト）
    folders = {}
    for folder_name in list_blackboard_subjects():
        folder_path = os.path.join(BLACKBOARD_FOLDER, folder_name)
        folders[folder_name] = [
            name for name in os.listdir(folder_path)
            if os.path.isfile(os.path.join(folder_path, name))
        ]
    return render_template('app_index.html', folders=folders)

# --- Admin ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password != VIP_PASSWORD:
            flash("パスワード違います")
            return redirect(url_for('admin'))

        # ファイルアップロード
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

        # ファイル削除
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

# --- NAS ---
@app.route('/nas', methods=['GET', 'POST'])
def nas():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            size = get_nas_size() + len(file.read())
            if size > NAS_CAP:
                flash("NAS容量オーバー！")
            else:
                file.seek(0)
                file.save(os.path.join(NAS_FOLDER, file.filename))
                flash(f"{file.filename} をNASに保存しました")
        return redirect(url_for('nas'))

    files = os.listdir(NAS_FOLDER)
    return render_template('nas.html', files=files)

@app.route('/nas/download/<filename>')
def nas_download(filename):
    return send_from_directory(NAS_FOLDER, filename, as_attachment=True)

# --- 黒板ファイル表示 ---
@app.route('/blackboards/<path:filename>')
def blackboard_file(filename):
    return send_from_directory(BLACKBOARD_FOLDER, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
