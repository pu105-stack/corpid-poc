require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');

const { loadPrivateKeyFromP12 } = require('./crypto');
const CorpIDClient              = require('./corpid');
const IamSmartClient            = require('./iamsmart');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const {
  CORPID_CLIENT_ID,
  CORPID_CLIENT_SECRET,
  IAMSMART_CLIENT_ID,
  IAMSMART_CLIENT_SECRET,
  KEK_P12_PATH = path.join(__dirname, '../../account-centre-kek.p12'),
  KEK_P12_PIN  = '8568185550716550',
  PORT         = 3000,
} = process.env;

if (!CORPID_CLIENT_ID || !CORPID_CLIENT_SECRET) {
  console.error('ERROR: CORPID_CLIENT_ID and CORPID_CLIENT_SECRET must be set in .env');
  process.exit(1);
}
if (!IAMSMART_CLIENT_ID || !IAMSMART_CLIENT_SECRET) {
  console.error('ERROR: IAMSMART_CLIENT_ID and IAMSMART_CLIENT_SECRET must be set in .env');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

const privateKey = loadPrivateKeyFromP12(KEK_P12_PATH, KEK_P12_PIN);
const corpid     = new CorpIDClient(CORPID_CLIENT_ID, CORPID_CLIENT_SECRET, privateKey);
const iamsmart   = new IamSmartClient(IAMSMART_CLIENT_ID, IAMSMART_CLIENT_SECRET, privateKey);

// In-memory session store (demo only)
const sessions = new Map();

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ---------------------------------------------------------------------------
// DEBUG — show the generated QR URL without redirecting
// ---------------------------------------------------------------------------

app.get('/api/debug-qr', (req, res) => {
  const state       = 'debug-state-123';
  const redirectURI = `http://localhost:${PORT}/auth/callback`;
  const qrUrl       = buildCorpIDQRUrl({ redirectURI, state });

  res.json({
    note:         'Open qr_url in your browser to see the QR page.',
    corpid_client_id:   CORPID_CLIENT_ID,
    iamsmart_client_id: IAMSMART_CLIENT_ID,
    qr_url:       qrUrl,
  });
});

// ---------------------------------------------------------------------------
// Build the CorpID getQR URL
// CorpID's own /api/v1/auth/getQR handles the iAM Smart integration internally —
// it redirects to iAM Smart using CorpID's own iAM Smart account, so you don't
// need a separate iAM Smart client ID for the QR step.
// ---------------------------------------------------------------------------

function buildCorpIDQRUrl({ redirectURI, state }) {
  const params = new URLSearchParams({
    clientID:     CORPID_CLIENT_ID,
    clientID_iAM: IAMSMART_CLIENT_ID,
    responseType: 'code',
    source:       'PC_Browser',
    redirectURI,
    scope:        'eidapi_auth',
    state,
    lang:         'en-US',
  });
  return `https://corpid.cyberport.hk/api/v1/auth/getQR?${params}`;
}

// ---------------------------------------------------------------------------
// STEP 1 — Redirect browser to CorpID QR page
// ---------------------------------------------------------------------------

app.get('/api/login', (req, res) => {
  const state       = crypto.randomUUID();
  const redirectURI = `http://localhost:${PORT}/auth/callback`;

  sessions.set(state, { phase: 'pending', createdAt: Date.now() });

  const qrUrl = buildCorpIDQRUrl({ redirectURI, state });

  console.log('[Login] state:', state);
  console.log('[Login] QR URL:', qrUrl);
  res.redirect(qrUrl);
});

// ---------------------------------------------------------------------------
// STEP 2 — Browser lands here after the user scans the QR and approves
//           GET /auth/callback?code=<iamCode>&corpMockCode=<corpidCode>&state=<state>
// ---------------------------------------------------------------------------

app.get('/auth/callback', async (req, res) => {
  const { code: iamCode, corpMockCode, state, error_code } = req.query;

  console.log('[Callback] ALL query params:', JSON.stringify(req.query, null, 2));

  if (error_code) {
    console.error('[Callback] Error from iAM Smart:', error_code);
    return res.redirect(`/?error=${encodeURIComponent(error_code)}`);
  }

  const session = sessions.get(state);
  if (!session) {
    console.error('[Callback] Unknown state:', state);
    return res.redirect('/?error=invalid_state');
  }
  if (!iamCode || !corpMockCode) {
    console.error('[Callback] Missing auth codes. Got:', { iamCode, corpMockCode });
    return res.redirect('/?error=missing_auth_codes');
  }

  try {
    // --- iAM Smart: exchange authCode → accessToken + openID ---
    console.log('[Auth] Calling iAM Smart getToken...');
    const iamTokens = await iamsmart.getToken(iamCode);
    console.log('[Auth] iAM Smart OK. openID:', iamTokens.openID);

    // --- CorpID: exchange corpMockCode + iAM tokens → CorpID accessToken + openID ---
    console.log('[Auth] Calling CorpID getToken...');
    const corpTokens = await corpid.getToken(corpMockCode, iamTokens.accessToken, iamTokens.openID);
    console.log('[Auth] CorpID OK. openID:', corpTokens.openID);

    sessions.set(state, {
      phase:        'authenticated',
      accessToken:  corpTokens.accessToken,
      openID:       corpTokens.openID,
      tokenType:    corpTokens.tokenType,
      scope:        corpTokens.scope,
      userType:     corpTokens.userType,
    });

    res.redirect(`/?session=${encodeURIComponent(state)}`);
  } catch (err) {
    console.error('[Auth] Error:', err.message);
    if (err.response) {
      console.error('[Auth] Response data:', JSON.stringify(err.response.data, null, 2));
    }
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// ---------------------------------------------------------------------------
// STEP 3 — Frontend fetches session details after redirect
// ---------------------------------------------------------------------------

app.get('/api/session/:state', (req, res) => {
  const session = sessions.get(req.params.state);
  if (!session || session.phase !== 'authenticated') {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({
    authenticated: true,
    openID:        session.openID,
    scope:         session.scope,
    userType:      session.userType,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\nCorpID PoC running at http://localhost:${PORT}\n`);
});
