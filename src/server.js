require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');

const { loadPrivateKeyFromP12, loadPrivateKeyFromBase64 } = require('./crypto');
const CorpIDClient   = require('./corpid');
const IamSmartClient = require('./iamsmart');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const {
  CORPID_CLIENT_ID,
  CORPID_CLIENT_SECRET,
  IAMSMART_CLIENT_ID,
  IAMSMART_CLIENT_SECRET,
  KEK_P12_PATH    = path.join(__dirname, '../../account-centre-kek.p12'),
  KEK_P12_PIN     = '8568185550716550',
  KEK_P12_BASE64,
  CALLBACK_BASE_URL,
  SESSION_SECRET,
  PORT            = 3000,
} = process.env;

if (!CORPID_CLIENT_ID || !CORPID_CLIENT_SECRET) {
  console.error('ERROR: CORPID_CLIENT_ID and CORPID_CLIENT_SECRET must be set in .env');
  process.exit(1);
}
if (!IAMSMART_CLIENT_ID || !IAMSMART_CLIENT_SECRET) {
  console.error('ERROR: IAMSMART_CLIENT_ID and IAMSMART_CLIENT_SECRET must be set in .env');
  process.exit(1);
}

const BASE_URL    = CALLBACK_BASE_URL || `http://localhost:${PORT}`;
const SIGN_SECRET = SESSION_SECRET    || CORPID_CLIENT_SECRET;

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

const privateKey = KEK_P12_BASE64
  ? loadPrivateKeyFromBase64(KEK_P12_BASE64, KEK_P12_PIN)
  : loadPrivateKeyFromP12(KEK_P12_PATH, KEK_P12_PIN);

const corpid   = new CorpIDClient(CORPID_CLIENT_ID, CORPID_CLIENT_SECRET, privateKey);
const iamsmart = new IamSmartClient(IAMSMART_CLIENT_ID, IAMSMART_CLIENT_SECRET, privateKey);

// ---------------------------------------------------------------------------
// Cookie helpers (stateless signed cookies — no server-side store needed)
// ---------------------------------------------------------------------------

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  header.split(';').forEach(part => {
    const [k, ...v] = part.split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('=').trim());
  });
  return out;
}

function signPayload(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig     = crypto.createHmac('sha256', SIGN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyPayload(token) {
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload  = token.slice(0, dot);
  const sig      = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SIGN_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { return null; }
}

const IS_HTTPS = BASE_URL.startsWith('https://');

function setCookie(res, name, value, maxAge) {
  const secure = IS_HTTPS ? '; Secure' : '';
  const cookie = `${name}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Lax${secure}; Max-Age=${maxAge}`;
  const existing = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [...(Array.isArray(existing) ? existing : [existing]), cookie]);
}

function clearCookie(res, name) {
  setCookie(res, name, '', 0);
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ---------------------------------------------------------------------------
// Build the CorpID getQR URL
// ---------------------------------------------------------------------------

function buildCorpIDQRUrl({ redirectURI, state }) {
  // Per CorpID Sandbox Developer Guide section 1.1.2:
  // Use iAM Smart's mockCorpId/getQR with corpMock=true so the iAM Smart auth
  // code is issued under OUR iAM Smart clientID (allowing us to exchange it).
  const params = new URLSearchParams({
    clientID:     IAMSMART_CLIENT_ID,
    responseType: 'code',
    source:       'PC_Browser',
    redirectURI,
    scope:        'eidapi_auth',
    state,
    lang:         'en-US',
    corpMock:     'true',
  });
  return `https://apigw-isit.staging-eid.gov.hk/api/v1/auth/mockCorpId/getQR?${params}`;
}

// ---------------------------------------------------------------------------
// STEP 1 — Redirect browser to CorpID QR page
//           State is HMAC-signed and stored in a cookie (no server store needed)
// ---------------------------------------------------------------------------

app.get('/api/login', (_req, res) => {
  const state       = crypto.randomUUID();
  const stateToken  = signPayload({ state, ts: Date.now() });
  const redirectURI = `${BASE_URL}/auth/callback`;

  setCookie(res, 'corpid_state', stateToken, 600); // 10 min

  const qrUrl = buildCorpIDQRUrl({ redirectURI, state });
  console.log('[Login] state:', state);
  console.log('[Login] QR URL:', qrUrl);
  res.redirect(qrUrl);
});

// ---------------------------------------------------------------------------
// STEP 2 — Browser lands here after the user scans the QR and approves
// ---------------------------------------------------------------------------

app.get('/auth/callback', async (req, res) => {
  const { code: iamCode, corpMockCode, state, error_code } = req.query;

  console.log('[Callback] query:', JSON.stringify(req.query, null, 2));

  if (error_code) {
    console.error('[Callback] Error from iAM Smart:', error_code);
    return res.redirect(`/?error=${encodeURIComponent(error_code)}`);
  }

  // Verify state via signed cookie
  const cookies    = parseCookies(req);
  const stateData  = verifyPayload(cookies.corpid_state);
  if (!stateData || stateData.state !== state) {
    console.error('[Callback] State mismatch. Cookie state:', stateData?.state, 'Query state:', state);
    return res.redirect('/?error=invalid_state');
  }

  if (!iamCode || !corpMockCode) {
    console.error('[Callback] Missing auth codes:', { iamCode, corpMockCode });
    return res.redirect('/?error=missing_auth_codes');
  }

  try {
    let iamAccessToken, iamOpenID;

    console.log('[Auth] Calling iAM Smart getToken...');
    try {
      const iamTokens = await iamsmart.getToken(iamCode);
      iamAccessToken  = iamTokens.accessToken;
      iamOpenID       = iamTokens.openID;
      console.log('[Auth] iAM Smart OK. openID:', iamOpenID);
    } catch (iamErr) {
      // D40004 = authCode not valid for our clientID (CorpID issues the code under its own account)
      // Fall back to using the raw iAM Smart code as a placeholder — the sandbox may not validate it
      console.warn('[Auth] iAM Smart getToken failed:', iamErr.message);
      console.warn('[Auth] Falling back: passing iamCode directly to CorpID getToken');
      iamAccessToken = iamCode;
      iamOpenID      = iamCode;
    }

    console.log('[Auth] Calling CorpID getToken...');
    const corpTokens = await corpid.getToken(corpMockCode, iamAccessToken, iamOpenID);
    console.log('[Auth] CorpID OK. openID:', corpTokens.openID);

    const sessionToken = signPayload({
      openID:       corpTokens.openID,
      accessToken:  corpTokens.accessToken,
      userType:     corpTokens.userType,
      scope:        corpTokens.scope,
      ts:           Date.now(),
    });

    clearCookie(res, 'corpid_state');
    setCookie(res, 'corpid_session', sessionToken, 3600); // 1 hour
    res.redirect('/');
  } catch (err) {
    console.error('[Auth] Error:', err.message);
    let detail = err.message;
    if (err.response) {
      const body = err.response.data;
      console.error('[Auth] Response status:', err.response.status);
      console.error('[Auth] Response body:', JSON.stringify(body, null, 2));
      detail = `HTTP ${err.response.status}: ${JSON.stringify(body)}`;
    }
    res.redirect(`/?error=${encodeURIComponent(detail)}`);
  }
});

// ---------------------------------------------------------------------------
// STEP 3 — Frontend calls this to get session info (reads cookie)
// ---------------------------------------------------------------------------

app.get('/api/me', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyPayload(cookies.corpid_session);
  if (!session) return res.status(401).json({ authenticated: false });
  res.json({
    authenticated: true,
    openID:   session.openID,
    userType: session.userType,
    scope:    session.scope,
  });
});

app.get('/api/logout', (_req, res) => {
  clearCookie(res, 'corpid_session');
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Form pre-fill — in-memory result store (keyed by ticketID, 5-min TTL)
// ---------------------------------------------------------------------------

const formFillResults = new Map(); // ticketID → { data, expiresAt }

function storeFormFillResult(ticketID, data) {
  formFillResults.set(ticketID, { data, expiresAt: Date.now() + 5 * 60_000 });
}

function getFormFillResult(ticketID) {
  const entry = formFillResults.get(ticketID);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { formFillResults.delete(ticketID); return null; }
  formFillResults.delete(ticketID); // one-time read
  return entry.data;
}

// ---------------------------------------------------------------------------
// FORM PRE-FILL — Step 1: initiate request
// ---------------------------------------------------------------------------

app.post('/api/formfill', async (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyPayload(cookies.corpid_session);
  if (!session) return res.status(401).json({ error: 'not_authenticated' });

  const { accessToken, openID } = session;
  if (!accessToken) return res.status(400).json({ error: 'no_access_token_in_session' });

  const state       = crypto.randomUUID();
  const businessID  = crypto.randomUUID();
  const redirectURI = `${BASE_URL}/api/callback/formfill`;

  try {
    const result = await corpid.initiateFormFilling({
      accessToken,
      openID,
      clientID_iAM: IAMSMART_CLIENT_ID,
      businessID,
      redirectURI,
      state,
    });
    console.log('[FormFill] initiated ticketID:', result.ticketID);
    res.json({ ticketID: result.ticketID });
  } catch (err) {
    console.error('[FormFill] initiateFormFilling error:', err.message);
    if (err.response) console.error('[FormFill] response:', JSON.stringify(err.response.data));
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// FORM PRE-FILL — Step 2: callback from CorpID (server-to-server push)
// ---------------------------------------------------------------------------

app.post('/api/callback/formfill', async (req, res) => {
  console.log('[FormFill Callback] HIT — body keys:', Object.keys(req.body));
  console.log('[FormFill Callback] raw body:', JSON.stringify(req.body));

  const { txID, code, msg, secretKey, content } = req.body;
  console.log('[FormFill Callback] txID:', txID, 'code:', code, 'hasSecretKey:', !!secretKey, 'hasContent:', !!content);

  // Always ACK immediately to CorpID
  res.status(200).json({ code: 'M00000' });

  if (code !== 'M00000') {
    console.error('[FormFill Callback] non-success code:', code, msg);
    return;
  }

  try {
    // On cold start _cek may be null — refresh it if no secretKey provided
    if (!secretKey && !corpid._cek) {
      console.log('[FormFill Callback] no CEK cached and no secretKey in callback, fetching CEK...');
      await corpid._ensureCEK();
    }
    const data = corpid.decryptCallback(content, secretKey || null);
    console.log('[FormFill Callback] decrypted OK. Keys:', Object.keys(data));
    // txID comes back as "<T=uuid>" — normalise to just the uuid to match ticketID
    const normalizedID = txID.replace(/^<T=(.+)>$/, '$1');
    console.log('[FormFill Callback] storing result for normalizedID:', normalizedID);
    storeFormFillResult(normalizedID, data);
    console.log('[FormFill Callback] Map size now:', formFillResults.size);
  } catch (err) {
    console.error('[FormFill Callback] decrypt error:', err.message);
  }
});

// ---------------------------------------------------------------------------
// FORM PRE-FILL — Step 3: browser polls for result
// ---------------------------------------------------------------------------

app.get('/api/formfill/:ticketID', (req, res) => {
  const { ticketID } = req.params;
  console.log('[FormFill Poll] ticketID:', ticketID, '| Map keys:', [...formFillResults.keys()]);
  const data = getFormFillResult(ticketID);
  if (!data) return res.json({ status: 'pending' });
  console.log('[FormFill Poll] found result, returning done');
  res.json({ status: 'done', data });
});

// Show what's currently in the result Map (without consuming entries)
app.get('/api/formfill-debug', (_req, res) => {
  const entries = [...formFillResults.entries()].map(([k, v]) => ({
    ticketID: k,
    expiresIn: Math.round((v.expiresAt - Date.now()) / 1000) + 's',
    dataKeys: Object.keys(v.data),
  }));
  res.json({ mapSize: formFillResults.size, entries });
});

// ---------------------------------------------------------------------------
// DEBUG
// ---------------------------------------------------------------------------

app.get('/api/debug-creds', (_req, res) => {
  const show = (s) => s ? `len=${s.length} [${s.slice(0,4)}...${s.slice(-4)}]` : 'MISSING';
  res.json({
    version:                'v3-stateless-cookies',
    CORPID_CLIENT_ID:       show(CORPID_CLIENT_ID),
    CORPID_CLIENT_SECRET:   show(CORPID_CLIENT_SECRET),
    IAMSMART_CLIENT_ID:     show(IAMSMART_CLIENT_ID),
    IAMSMART_CLIENT_SECRET: show(IAMSMART_CLIENT_SECRET),
    BASE_URL,
  });
});

app.get('/api/debug-qr', (_req, res) => {
  const state       = 'debug-state-123';
  const redirectURI = `${BASE_URL}/auth/callback`;
  res.json({
    note:               'Open qr_url in your browser to see the QR page.',
    corpid_client_id:   CORPID_CLIENT_ID,
    iamsmart_client_id: IAMSMART_CLIENT_ID,
    qr_url:             buildCorpIDQRUrl({ redirectURI, state }),
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\nCorpID PoC running at http://localhost:${PORT}\n`);
  console.log('BASE_URL:', BASE_URL);
});
