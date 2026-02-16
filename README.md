# BlackBoard-app-Beta- (Stable Ver1.0)

黒板写真を教科ごとに管理・閲覧し、コメント共有や管理者制御を行うWebアプリです。

## クイックスタート（公開向け最終調整版）

```bash
pip install -r requirements.txt
python app.py
```

起動後は `http://localhost:8080` にアクセスしてください。

## 任意の環境変数
- `APP_HOST`（既定: `0.0.0.0`）
- `APP_PORT`（既定: `8080`）
- `FLASK_DEBUG`（既定: `0`）
- `APP_SECRET_KEY`（既定あり。本番では必ず強い値に変更推奨）
- `SESSION_COOKIE_SECURE`（HTTPS運用時は `1` 推奨）

- `AI_API_KEY`（設定すると外部AI API連携を有効化）
- `AI_API_BASE`（既定: `https://api.x.ai/v1`）
- `AI_API_MODEL`（既定: `grok-4-latest`）
- `AI_API_TIMEOUT`（既定: `20`秒）
