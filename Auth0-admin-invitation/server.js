import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const required = [
  'AUTH0_DOMAIN',
  'AUTH0_M2M_CLIENT_ID',
  'AUTH0_M2M_CLIENT_SECRET',
  'AUTH0_DB_CONNECTION',
  'AUTH0_APP_CLIENT_ID',
  'AUTH0_APP_CLIENT_SECRET',
  'APP_BASE_URL',
  'ADMIN_API_KEY'
];
for (const key of required) if (!process.env[key]) throw new Error(`${key} is required`);

app.use(express.json({ limit: '16kb' }));
app.use(express.static(__dirname));

let tokenCache = { value: '', expiresAt: 0 };
async function managementToken() {
  if (tokenCache.value && Date.now() < tokenCache.expiresAt - 60_000) return tokenCache.value;
  const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'client_credentials',
      client_id: process.env.AUTH0_M2M_CLIENT_ID,
      client_secret: process.env.AUTH0_M2M_CLIENT_SECRET,
      audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`
    })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error_description || body.message || 'Management API token error');
  tokenCache = { value: body.access_token, expiresAt: Date.now() + Number(body.expires_in || 3600) * 1000 };
  return tokenCache.value;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function adminOnly(req, res, next) {
  if (!safeEqual(req.get('x-admin-key'), process.env.ADMIN_API_KEY)) {
    return res.status(401).json({ message: '管理者認証に失敗しました。' });
  }
  next();
}

async function deleteUserQuietly(token, userId) {
  try {
    await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE', headers: { authorization: `Bearer ${token}` }
    });
  } catch (error) {
    console.error('rollback failed', userId, error);
  }
}

app.post('/api/admin/invitations', adminOnly, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name = String(req.body?.name || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ message: '有効なメールアドレスを入力してください。' });
  }
  if (name.length > 120) return res.status(400).json({ message: '名前は120文字以内で入力してください。' });

  const correlationId = `invite-${crypto.randomUUID()}`.slice(0, 64);
  let createdUserId = '';
  try {
    const token = await managementToken();

    const createResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'x-correlation-id': correlationId
      },
      body: JSON.stringify({
        connection: process.env.AUTH0_DB_CONNECTION,
        email,
        email_verified: false,
        verify_email: false,
        ...(name ? { name } : {}),
        app_metadata: { invitation_status: 'pending', provisioned_by: 'flowdesk-admin' }
      })
    });
    const createBody = await createResponse.json().catch(() => ({}));
    if (!createResponse.ok) {
      const status = createResponse.status === 409 ? 409 : createResponse.status;
      return res.status(status).json({ message: createBody.message || 'ユーザーを作成できませんでした。', correlationId });
    }
    createdUserId = createBody.user_id;

    // Authentication APIによりAuth0のChange Passwordメールを送信。
    const mailResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/dbconnections/change_password`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-correlation-id': correlationId },
      body: JSON.stringify({
        client_id: process.env.AUTH0_APP_CLIENT_ID,
        email,
        connection: process.env.AUTH0_DB_CONNECTION
      })
    });
    const mailText = await mailResponse.text();
    if (!mailResponse.ok) {
      // 招待メールを送れない半端なユーザーを残さない。
      await deleteUserQuietly(token, createdUserId);
      return res.status(mailResponse.status).json({
        message: `招待メールを送信できなかったため、作成ユーザーをロールバックしました。${mailText ? ` ${mailText}` : ''}`,
        correlationId
      });
    }

    return res.status(201).json({
      message: 'ユーザーを作成し、Auth0からパスワード設定メールを送信しました。',
      userId: createdUserId,
      email,
      correlationId
    });
  } catch (error) {
    console.error(correlationId, error);
    return res.status(500).json({ message: '招待処理で内部エラーが発生しました。', correlationId });
  }
});

app.get('/login', (req, res) => {
  const authorizeUrl = new URL(`https://${process.env.AUTH0_DOMAIN}/authorize`);

  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', process.env.AUTH0_APP_CLIENT_ID);
  authorizeUrl.searchParams.set(
    'redirect_uri',
    `${process.env.APP_BASE_URL}/callback`
  );
  authorizeUrl.searchParams.set('scope', 'openid profile email');

  res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
  try {
    const { code, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(
        `Login failed: ${error_description || error}`
      );
    }

    if (!code) {
      return res.status(400).send('Authorization code is missing.');
    }

    const tokenResponse = await fetch(
      `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          client_id: process.env.AUTH0_APP_CLIENT_ID,
          client_secret: process.env.AUTH0_APP_CLIENT_SECRET,
          code,
          redirect_uri: `${process.env.APP_BASE_URL}/callback`
        })
      }
    );

    const tokenBody = await tokenResponse.json();
    if (!tokenResponse.ok) {
      console.error('Token exchange failed:', tokenBody);
      return res.status(500).send('Token exchange failed.');
    }

    return res.send(`
      <h1>ログイン成功</h1>
      <p>Auth0での認証が正常に完了しました。</p>
      <p><a href="/">トップへ戻る</a></p>
    `);

  } catch (err) {
    console.error('Callback error:', err);
    return res.status(500).send('Callback processing failed.');
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`FlowDesk: http://localhost:${port}`));
