import os
from flask import Flask, request, redirect, url_for, send_from_directory, render_template, flash

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

# --- ルート ---
@app.route('/')
def consent():
    return render_template('consent.html')

@app.route('/app')
def app_index():
    # boardsを辞書型にする（フォルダ→ファイルリスト）
    folders = {}
    for folder_name in os.listdir(BLACKBOARD_FOLDER):
        folder_path = os.path.join(BLACKBOARD_FOLDER, folder_name)
        if os.path.isdir(folder_path):
            folders[folder_name] = os.listdir(folder_path)
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
        if file:
            file.save(os.path.join(BLACKBOARD_FOLDER, file.filename))
            flash(f"{file.filename} をアップロードしました")
            return redirect(url_for('admin'))

        # ファイル削除
        delete_file = request.form.get('delete')
        if delete_file and delete_file in os.listdir(BLACKBOARD_FOLDER):
            os.remove(os.path.join(BLACKBOARD_FOLDER, delete_file))
            flash(f"{delete_file} を削除しました")
            return redirect(url_for('admin'))

    boards = os.listdir(BLACKBOARD_FOLDER)
    return render_template('admin.html', boards=boards)

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
@app.route('/blackboards/<filename>')
def blackboard_file(filename):
    return send_from_directory(BLACKBOARD_FOLDER, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
