/**
 * CorpID Sandbox API client
 *
 * Handles:
 *   - CEK lifecycle: request, cache, auto-renew on expiry
 *   - Encrypting POST request bodies + decrypting responses
 *   - getToken   (CORPID-2): exchange authCode for accessToken + openID
 *   - initiateFormFilling (CORPID-3): request corporate profile data
 *   - decryptCallback: decrypt the pushed form-filling callback (CORPID-4)
 */

const axios  = require('axios');
const {
  decryptCEK,
  encryptBody,
  decryptBody,
  buildAuthHeaders,
  buildGetKeyBody,
} = require('./crypto');

const CORPID_BASE = 'https://corpid.cyberport.hk';

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
    const res = await axios.post(`${CORPID_BASE}/api/v1/security/getKey`, null, { headers });

    console.log('[CorpID] getKey response code:', res.data.code);

    if (res.data.code !== 'M00000') {
      throw new Error(`CEK request failed [${res.data.code}]: ${res.data.msg}`);
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
  // CORPID-2: Get Access Token
  // -------------------------------------------------------------------------

  /**
   * Exchange the CorpID authCode (corpMockCode) for an accessToken + openID.
   * Requires the iAM Smart accessToken and openID from iamsmart.getToken().
   * Returns: { accessToken, openID, tokenType, scope, ... }
   */
  async getToken(corpidAuthCode, iamAccessToken, iamOpenID) {
    console.log('[CorpID] getToken corpMockCode:', corpidAuthCode?.slice(0, 8), 'iamTokenLen:', iamAccessToken?.length);
    const res = await this._post('/api/v1/auth/getToken', {
      ticketID:              corpidAuthCode,
      grantType:             'authorization_code',
      iAMSmart_AccessToken:  iamAccessToken,
      iAMSmart_TokenizedID:  iamOpenID,
    });

    console.log('[CorpID] getToken response code:', res.code, 'msg:', res.msg);
    if (res.code !== 'M00000') {
      throw new Error(`CorpID getToken failed [${res.code}]: ${res.msg}`);
    }
    return res.content; // { accessToken, openID, tokenType, expiresIn, scope, ... }
  }

  // -------------------------------------------------------------------------
  // CORPID-3: Initiate Form Pre-filling (web e-service)
  // -------------------------------------------------------------------------

  /**
   * Request corporate + personal profile data.
   * CorpID will push the decrypted data to redirectURI (CORPID-4 callback).
   * Returns: { ticketID, authByQR }
   */
  async initiateFormFilling({ accessToken, openID, clientID_iAM, businessID, redirectURI, state }) {
    const res = await this._post('/api/v1/formFilling/initiateRequest', {
      businessID,
      accessToken,
      openID,
      clientID_iAM,
      source:              'PC_Browser',
      iamFormfill:         false,
      redirectURI,
      state,
      formName:            'CorpID PoC – Account Registration',
      formNum:             'POC-001',
      formDesc:            'Demo form pre-filling via CorpID Sandbox',
      callbackContentType: 'application/json',

      corpProfileFields:     ['corpID', 'brn', 'corpNameEN', 'corpNameTC', 'corpAddr'],
      corpUserProfileFields: ['id_cty_issue', 'id_type'],
      eCorpFields: [
        'corpID', 'brn', 'corpNameEN', 'corpNameTC', 'corpAddr',
        'corpTypeEN', 'corpTel', 'corpStatusEN', 'placeOfIncorp', 'dateOfReg',
      ],
    });

    if (res.code !== 'M00000') {
      throw new Error(`initiateFormFilling failed [${res.code}]: ${res.msg}`);
    }
    return res.content; // { ticketID, authByQR }
  }

  // -------------------------------------------------------------------------
  // CORPID-4: Decrypt pushed callback
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
