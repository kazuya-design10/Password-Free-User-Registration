# FlowDesk: 管理者招待 + Auth0 New Universal Login

## 重要な設計上の事実
Auth0 Database Connectionのユーザーは完全な「password未設定」では作成できません。この実装はサーバー内部で強いランダム一時パスワードを生成して `POST /api/v2/users` へ渡し、値を保存・表示せず、直後に `POST /dbconnections/change_password` でAuth0から本人へ設定メールを送ります。本人が設定するまで管理者はパスワードを知りません。

## Auth0設定
1. M2M ApplicationをAuth0 Management APIへAuthorize
2. Scope: `create:users`, `delete:users`（メール失敗時ロールバック用）
3. SPA Applicationで `Username-Password-Authentication` Connectionを有効化
4. Branding > Universal LoginでNew Universal Loginを有効化
5. Branding > Email TemplatesでChange Passwordテンプレートを有効化
6. Email Providerを設定。未設定のBuilt-in providerは試験用途・送信制限あり
7. SPA Application側のAllowed Callback URLsに `http://localhost:3000`、Allowed Logout URLsに `http://localhost:3000`、Allowed Web Originsに `http://localhost:3000` を設定
8. M2M Application側のCallback URL設定は不要

## 起動
```bash
cp .env.example .env
npm install
npm start
```

## 本番化
`ADMIN_API_KEY`はローカル検証用です。本番では管理者がNew Universal Loginでログインし、API Audience付きAccess TokenとAuth0 RBACの `user:invite` Permissionをバックエンドで検証してください。レート制限、CSRF/Origin検証、監査ログ、招待再送、期限管理も追加してください。
