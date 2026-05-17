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
    // iAM Smart expects common params in headers (not body) for all endpoints
    const timestamp = Date.now();
    const nonce     = generateNonce();
    const headers   = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, '', false);

    const res = await axios.post(`${IAM_BASE}/api/v1/security/getKey`, null, { headers });

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
    // iAM Smart does not include the encrypted body in the HMAC message (unlike CorpID)
    const headers          = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, '', false);

    const res  = await axios.post(`${IAM_BASE}${path}`, { content: encryptedContent }, { headers });
    const data = res.data;

    if (data.content && typeof data.content === 'string') {
      data.content = decryptBody(data.content, this._cek);
    }
    return data;
  }

  // -------------------------------------------------------------------------
  // Token exchange
  // Doc example shows: unencrypted body + URL-encoded signature (unlike _post)
  // -------------------------------------------------------------------------

  async getToken(authCode) {
    const timestamp = Date.now();
    const nonce     = generateNonce();
    // No encrypted body in the signature message for getToken
    const headers   = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, '', true);

    const res = await axios.post(`${IAM_BASE}/api/v1/auth/getToken`, {
      code:      authCode,
      grantType: 'authorization_code',
    }, { headers });

    const data = res.data;
    if (data.content && typeof data.content === 'string') {
      data.content = decryptBody(data.content, await this._getOrFetchCEK());
    }

    if (data.code !== 'D00000') {
      throw new Error(`iAM Smart getToken failed [${data.code}]: ${data.message || data.msg}`);
    }

    return data.content; // { accessToken, openID, userType, scope, ... }
  }

  async _getOrFetchCEK() {
    await this._ensureCEK();
    return this._cek;
  }
}

module.exports = IamSmartClient;
