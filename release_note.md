# Release Note - Chalkly Canary Ver0.9.1

## リリース概要
Canary期間のフィードバックを反映し、**Chalkly Canary Ver0.9.3** として公開可能な状態へ調整しました。

## Canary Ver0.9.3 向けの主な調整
- アプリバージョン表記を `Chalkly Canary Ver0.9.3` に更新。
- 本番向け設定を追加。
  - `APP_SECRET_KEY` の環境変数対応（未設定のまま本番起動を防止）
  - `FLASK_DEBUG` の環境変数制御（デフォルトOFF）
  - セッションCookieの安全設定（`HttpOnly`, `SameSite=Lax`, `Secure`切替）
- 外部依存を減らすため、一覧画面の不要な外部スクリプト読み込みを削除。

## 公開前チェックリスト
1. `APP_SECRET_KEY` を十分に長いランダム値で設定
2. HTTPS配下で `SESSION_COOKIE_SECURE=1` を設定
3. `FLASK_DEBUG=0` を確認
4. `credentials.json` の配布・保管経路を制限
5. `audit_log.jsonl` のローテーション運用を設定

## 既知事項
- コメントモデレーションはルールベース検知です。運用で禁止語調整が必要です。
- `credentials.json` は平文PINのため、将来はハッシュ化移行を推奨します。


## Canary公開向け最終調整（運用性）
- `python app.py` 単体で起動できるように、起動時の必須環境変数チェックを緩和。
- `APP_HOST` / `APP_PORT` 環境変数で公開先を切り替え可能に。
- `requirements.txt` を追加し、依存導入手順を固定化。


## 追加: 軽量AIサポート
- 質問コメントに対するAI自動返信（軽量ルールベース）を追加。
- 画像ごとのAI説明・要点まとめAPI（`GET /api/ai/summary`）を追加。
- 低スペック運用（Celeron N4020 / Raspberry Pi 5）を意識し、重い推論依存なしで動作。

- 外部AI API連携（`AI_API_KEY` 等）を追加し、失敗時はローカル軽量AIへ自動フォールバック。
