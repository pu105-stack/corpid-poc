/**
 * iAM Smart ITE client (sandbox environment)
 *
 * Uses the same CEK/KEK + AES-256-GCM encryption pattern as CorpID.
 * The same p12 KEK certificate is used for both systems.
 */

const axios = require('axios');
const {
  generateNonce,
  buildAuthHeaders,
  encryptBody,
  decryptBody,
  decryptCEK,
} = require('./crypto');

const IAM_BASE = 'https://apigw-isit.staging-eid.gov.hk';

class IamSmartClient {
  constructor(clientID, clientSecret, privateKey) {
    this.clientID     = clientID;
    this.clientSecret = clientSecret;
    this.privateKey   = privateKey;
    this._cek         = null;
    this._cekExpiresAt = 0;
  }

  // -------------------------------------------------------------------------
  // CEK management (same pattern as CorpID)
  // -------------------------------------------------------------------------

  async _ensureCEK() {
    if (this._cek && Date.now() < this._cekExpiresAt - 60_000) return;
    await this._requestCEK();
  }

  async _requestCEK() {
    const timestamp = Date.now();
    const nonce     = generateNonce();
    const headers   = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, '', true);

    const signMsg = this.clientID + 'HmacSHA256' + timestamp + nonce + '';
    console.log('[iAM CEK] clientID       :', this.clientID);
    console.log('[iAM CEK] clientSecret   :', this.clientSecret.slice(0,4) + '...' + this.clientSecret.slice(-4), 'len=' + this.clientSecret.length);
    console.log('[iAM CEK] timestamp      :', timestamp);
    console.log('[iAM CEK] nonce          :', nonce);
    console.log('[iAM CEK] sign message   :', signMsg);
    console.log('[iAM CEK] headers sent   :', JSON.stringify(headers));

    const res = await axios.post(`${IAM_BASE}/api/v1/security/getKey`, null, { headers });
    console.log('[iAM CEK] response       :', JSON.stringify(res.data));

    if (res.data.code !== 'D00000') {
      throw new Error(`iAM Smart CEK request failed [${res.data.code}]: ${res.data.msg || res.data.message}`);
    }

    const { secretKey, issueAt, expiresIn } = res.data.content;
    this._cek          = decryptCEK(secretKey, this.privateKey);
    this._cekExpiresAt = issueAt + expiresIn;
    console.log('[iAM Smart] CEK refreshed, expires in', Math.round(expiresIn / 1000), 's');
  }

  async _post(path, bodyObj) {
    await this._ensureCEK();

    const timestamp        = Date.now();
    const nonce            = generateNonce();
    const encryptedContent = encryptBody(bodyObj, this._cek);
    const requestBody      = { content: encryptedContent };
    const bodyStr          = JSON.stringify(requestBody);

    // Try full JSON body string as the "encrypted_request_body" in the signature message
    const headers = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, bodyStr, true);

    console.log('[iAM POST] path          :', path);
    console.log('[iAM POST] encContent len:', encryptedContent.length);
    console.log('[iAM POST] bodyStr len   :', bodyStr.length);
    console.log('[iAM POST] headers sent  :', JSON.stringify(headers));

    const res  = await axios.post(`${IAM_BASE}${path}`, requestBody, { headers });
    console.log('[iAM POST] response      :', JSON.stringify(res.data).slice(0, 300));
    const data = res.data;

    if (data.content && typeof data.content === 'string') {
      data.content = decryptBody(data.content, this._cek);
    }
    return data;
  }

  // -------------------------------------------------------------------------
  // Token exchange
  // -------------------------------------------------------------------------

  async getToken(authCode) {
    const res = await this._post('/api/v1/auth/getToken', {
      code:      authCode,
      grantType: 'authorization_code',
    });

    if (res.code !== 'D00000') {
      throw new Error(`iAM Smart getToken failed [${res.code}]: ${res.message || res.msg}`);
    }

    return res.content; // { accessToken, openID, userType, scope, ... }
  }
}

module.exports = IamSmartClient;
