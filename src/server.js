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

const IAM_SMART_BASE_URL = process.env.IAM_SMART_BASE_URL || 'https://apigw-isit.staging-eid.gov.hk';
const IAM_SCOPES    = 'eidapi_auth eidapi_formFilling';
const CORPID_SCOPES = 'corpidapi_auth corpidapi_formFilling';

// iAM Smart API Spec for CorpID v0.1.2 §1.4.1 (the "corpId/getQR" in its example block is stale)
function buildCorpIDQRUrl({ redirectURI, state }) {
  const params = new URLSearchParams({
    clientID:     IAMSMART_CLIENT_ID,
    responseType: 'code',
    source:       'PC_Browser',
    redirectURI,
    scope:        IAM_SCOPES,
    cScope:       CORPID_SCOPES,
    state,
    lang:         'en-US',
  });
  return `${IAM_SMART_BASE_URL}/api/v1/auth/getCQR?${params}`;
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
  const { code: iamCode, cCode, state, error_code, cError_code } = req.query;

  console.log('[Callback] query:', JSON.stringify(req.query, null, 2));

  if (error_code || cError_code) {
    const detail = [cError_code && `CorpID ${cError_code}`, error_code && `iAM Smart ${error_code}`].filter(Boolean).join(', ');
    console.error('[Callback] Error from callback:', detail);
    return res.redirect(`/?error=${encodeURIComponent(detail)}`);
  }

  // Verify state via signed cookie
  const cookies    = parseCookies(req);
  const stateData  = verifyPayload(cookies.corpid_state);
  if (!stateData || stateData.state !== state) {
    console.error('[Callback] State mismatch. Cookie state:', stateData?.state, 'Query state:', state);
    return res.redirect('/?error=invalid_state');
  }

  // `code` (iAM Smart) is conditional — absent for non-HK-resident CorpID users
  if (!cCode) {
    console.error('[Callback] Missing cCode:', { iamCode, cCode });
    return res.redirect('/?error=missing_auth_codes');
  }

  try {
    // CorpID first: cCode expires 30 s after issuance
    console.log('[Auth] Calling CorpID getToken...');
    const corpTokens = await corpid.getToken(cCode);
    console.log('[Auth] CorpID OK. cOpenID:', corpTokens.cOpenID, 'corpCount:', corpTokens.corpCount);

    // iAM Smart tokens are needed later to build iAMToken for form filling
    let iamTokens = null;
    if (iamCode) {
      try {
        iamTokens = await iamsmart.getToken(iamCode);
        console.log('[Auth] iAM Smart OK. openID:', iamTokens.openID);
      } catch (iamErr) {
        console.warn('[Auth] iAM Smart getToken failed (form filling will be unavailable):', iamErr.message);
      }
    }

    const sessionToken = signPayload({
      cOpenID:        corpTokens.cOpenID,
      cAccessToken:   corpTokens.cAccessToken,
      corpCount:      corpTokens.corpCount,
      corpInfo:       corpTokens.corpInfo,
      iamAccessToken: iamTokens?.accessToken,
      iamOpenID:      iamTokens?.openID,
      ts:             Date.now(),
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
    cOpenID:   session.cOpenID,
    corpCount: session.corpCount,
    corpInfo:  session.corpInfo,
  });
});

app.get('/api/logout', (_req, res) => {
  clearCookie(res, 'corpid_session');
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Form pre-fill — in-memory result store (keyed by businessID, 5-min TTL)
// ---------------------------------------------------------------------------

const formFillResults = new Map(); // in-memory (same instance)
const fs = require('fs');
const FORMFILL_TTL_MS = 5 * 60_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function storeFormFillResult(businessID, data) {
  const entry = { data, expiresAt: Date.now() + FORMFILL_TTL_MS };
  formFillResults.set(businessID, entry);
  try { fs.writeFileSync(`/tmp/ff_${businessID}.json`, JSON.stringify(entry)); } catch (_) {}
}

function getFormFillResult(businessID) {
  // Try in-memory first, then /tmp (survives across warm Vercel instances)
  let entry = formFillResults.get(businessID);
  if (!entry) {
    try {
      entry = JSON.parse(fs.readFileSync(`/tmp/ff_${businessID}.json`, 'utf8'));
    } catch (_) {}
  }
  if (!entry) return null;
  formFillResults.delete(businessID);
  try { fs.unlinkSync(`/tmp/ff_${businessID}.json`); } catch (_) {}
  if (Date.now() > entry.expiresAt) return null;
  return entry.data;
}

// ---------------------------------------------------------------------------
// FORM PRE-FILL — Step 1: initiate request
// ---------------------------------------------------------------------------

app.post('/api/formfill', async (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyPayload(cookies.corpid_session);
  if (!session) return res.status(401).json({ error: 'not_authenticated' });

  const { cAccessToken, cOpenID, iamAccessToken, iamOpenID } = session;
  if (!cAccessToken) return res.status(400).json({ error: 'no_access_token_in_session' });

  const state       = crypto.randomUUID();
  const businessID  = crypto.randomUUID();
  const redirectURI = `${BASE_URL}/api/callback/formfill`;

  try {
    // API Spec §2.3.2.1: iAM Smart accessToken + openID, encrypted with the iAM Smart CEK
    const iAMToken = iamAccessToken
      ? await iamsmart.encryptWithCEK({ accessToken: iamAccessToken, openID: iamOpenID })
      : undefined;

    const result = await corpid.initiateFormFilling({
      cAccessToken,
      cOpenID,
      iAMToken,
      businessID,
      redirectURI,
      state,
    });
    console.log('[FormFill] initiated businessID:', businessID, 'ticketID:', result.ticketID, 'authByQR:', result.authByQR);
    res.json({ businessID });
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

    // API Spec §2.3.5 / §4.7: iAM Smart part may sit at top level or inside content
    const iamContent   = req.body.iAMContent   ?? data.iAMContent;
    const iamSecretKey = req.body.iAMSecretKey ?? data.iAMSecretKey;
    const iam = iamContent ? await iamsmart.decryptContent(iamContent, iamSecretKey) : null;

    if (!data.businessID) {
      console.error('[FormFill Callback] no businessID in decrypted content');
      return;
    }
    storeFormFillResult(data.businessID, { corp: data.corp, iam });
    console.log('[FormFill Callback] stored result for businessID:', data.businessID);
  } catch (err) {
    console.error('[FormFill Callback] decrypt error:', err.message);
  }
});

// ---------------------------------------------------------------------------
// FORM PRE-FILL — Step 3: browser polls for result
// ---------------------------------------------------------------------------

app.get('/api/formfill/:businessID', (req, res) => {
  const { businessID } = req.params;
  if (!UUID_RE.test(businessID)) return res.status(400).json({ error: 'invalid_business_id' });
  const data = getFormFillResult(businessID);
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
