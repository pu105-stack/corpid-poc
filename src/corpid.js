/**
 * CorpID UAT API client
 *
 * Handles:
 *   - CEK lifecycle: request, cache, auto-renew on expiry
 *   - Encrypting POST request bodies + decrypting responses
 *   - getToken   (EXT-002): exchange cAuthCode for cAccessToken + cOpenID
 *   - initiateFormFilling (EXT-006): request corporate profile data
 *   - decryptCallback: decrypt the pushed form-filling callback (CLB-002)
 */

const axios  = require('axios');
const {
  decryptCEK,
  encryptBody,
  decryptBody,
  buildAuthHeaders,
  buildGetKeyBody,
} = require('./crypto');

const CORPID_BASE = process.env.CORPID_BASE_URL || 'https://isit-apigw.corpid-np.gov.hk';

// Spec §2.4.2 names the field "message"; older examples and the sandbox used "msg"
const errorText = (data) => data.message ?? data.msg;

class CorpIDClient {
  constructor(clientID, clientSecret, privateKey) {
    this.clientID     = clientID;
    this.clientSecret = clientSecret;
    this.privateKey   = privateKey;
    this._cek         = null;
    this._cekExpiresAt = 0;
  }

  // -------------------------------------------------------------------------
  // CEK management
  // -------------------------------------------------------------------------

  async _ensureCEK() {
    // Renew 60 s before actual expiry to avoid races
    if (this._cek && Date.now() < this._cekExpiresAt - 60_000) return;
    await this._requestCEK();
  }

  async _requestCEK() {
    // CorpID getKey requires auth params in headers (body-based auth rejected by sandbox)
    const { clientID, signatureMethod, signature, timestamp, nonce } = buildGetKeyBody(this.clientID, this.clientSecret);
    const headers = { clientID, signatureMethod, signature, timestamp: String(timestamp), nonce };
    const res = await axios.post(`${CORPID_BASE}/api/eservice/v1/security/getKey`, null, { headers });

    console.log('[CorpID] getKey response code:', res.data.code);

    if (res.data.code !== 'M00000') {
      throw new Error(`CEK request failed [${res.data.code}]: ${errorText(res.data)}`);
    }

    const { secretKey, issueAt, expiresIn } = res.data.content;
    this._cek          = decryptCEK(secretKey, this.privateKey);
    this._cekExpiresAt = issueAt + expiresIn;
    console.log('[CorpID] CEK refreshed, expires in', Math.round(expiresIn / 1000), 's');
  }

  // -------------------------------------------------------------------------
  // Encrypted POST helper
  // -------------------------------------------------------------------------

  async _post(path, bodyObj) {
    await this._ensureCEK();

    const timestamp        = Date.now();
    const nonce            = require('crypto').randomUUID();
    const encryptedContent = encryptBody(bodyObj, this._cek);
    const requestBody      = { content: encryptedContent };
    // Signature uses full JSON body string — same pattern as iAM Smart _post
    const bodyStr          = JSON.stringify(requestBody);
    const headers          = buildAuthHeaders(this.clientID, this.clientSecret, timestamp, nonce, bodyStr);

    console.log('[CorpID] POST', path, 'clientID:', this.clientID?.slice(0, 8));

    const res = await axios.post(`${CORPID_BASE}${path}`, requestBody, { headers });

    const data = res.data;
    console.log('[CorpID] POST', path, 'HTTP', res.status, 'code:', data.code);
    if (data.content && typeof data.content === 'string') {
      data.content = decryptBody(data.content, this._cek);
    }
    return data;
  }

  // -------------------------------------------------------------------------
  // EXT-002: Get Access Token
  // -------------------------------------------------------------------------

  /**
   * Exchange the CorpID cAuthCode (from callback cCode param) for cAccessToken + cOpenID.
   * Returns: { cAccessToken, cOpenID, tokenType, corpCount, corpInfo, ... }
   */
  async getToken(cAuthCode) {
    console.log('[CorpID] getToken cAuthCode:', cAuthCode?.slice(0, 8));
    const res = await this._post('/api/eservice/v1/auth/getToken', {
      cAuthCode,
      grantType: 'authorization_code',
    });

    console.log('[CorpID] getToken response code:', res.code, 'message:', errorText(res));
    if (res.code !== 'M00000') {
      throw new Error(`CorpID getToken failed [${res.code}]: ${errorText(res)}`);
    }
    return res.content; // { cAccessToken, cOpenID, tokenType, corpCount, corpInfo, ... }
  }

  // -------------------------------------------------------------------------
  // EXT-006: Initiate Form Pre-filling (web e-service)
  // -------------------------------------------------------------------------

  /**
   * Request corporate + personal profile data.
   * CorpID will push the decrypted data to redirectURI (CLB-002 callback).
   * Returns: { ticketID, authByQR }
   */
  async initiateFormFilling({ cAccessToken, cOpenID, iAMToken, businessID, redirectURI, state }) {
    // Field names per CorpID API Spec §4.6 + Appendix A (5.1–5.3)
    const res = await this._post('/api/eservice/v1/formFilling/initiateRequest', {
      businessID,
      cAccessToken,
      cOpenID,
      ...(iAMToken && { iAMToken }),
      source:              'PC_Browser',
      redirectURI,
      state,
      formName:            'CorpID PoC – Account Registration',
      formNum:             'POC-001',
      formDesc:            'Demo form pre-filling via CorpID UAT',
      callbackContentType: 'application/json',
      authorisationToken:  false,

      corpProfileFields: [
        'ubi', 'crn', 'type', 'status', 'engName', 'chiName',
        'engAddress', 'chiAddress', 'commencementDate', 'brcExpiryDate',
      ],
      nonHKResidentFields: ['enName', 'chName', 'email', 'countryCode', 'passport'],
      eCorpFields:         ['eCorpAddr', 'eCorpEmailAddr', 'eCorpTelNo', 'eCorpFaxNo', 'eCorpWebsite'],
      ...(iAMToken && {
        profileFields: ['idNo', 'enName', 'chName', 'birthDate', 'gender'],
        eMEFields:     ['idNo', 'enName', 'chName', 'birthDate', 'gender'],
      }),
    });

    if (res.code !== 'M00000') {
      throw new Error(`initiateFormFilling failed [${res.code}]: ${errorText(res)}`);
    }
    return res.content; // { ticketID, authByQR }
  }

  // -------------------------------------------------------------------------
  // CBL-002: Decrypt pushed callback
  // -------------------------------------------------------------------------

  /**
   * Called when CorpID POSTs the form-filling result to your server.
   * The callback body contains:
   *   { txID, code, msg, secretKey (optional), content (encrypted) }
   *
   * If `secretKey` is present, CorpID has re-keyed: decrypt it to get the new CEK.
   * Otherwise use the cached CEK.
   */
  decryptCallback(encryptedContent, encryptedSecretKey) {
    const cek = encryptedSecretKey
      ? decryptCEK(encryptedSecretKey, this.privateKey)
      : this._cek;

    if (!cek) throw new Error('No CEK available to decrypt callback');
    return decryptBody(encryptedContent, cek);
  }
}

module.exports = CorpIDClient;
