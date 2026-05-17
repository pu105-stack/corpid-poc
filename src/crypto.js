/**
 * Crypto utilities for CorpID Sandbox:
 *   - Load private key from PKCS#12 (.p12)
 *   - RSA-decrypt the CEK returned by /api/v1/security/getKey
 *   - AES-256-GCM encrypt/decrypt request/response bodies
 *   - Build HMAC-SHA256 request headers
 *
 * Wire format for AES-256-GCM payloads (per API spec section 2.3.5):
 *   [4-byte big-endian IV length][12-byte IV][ciphertext + 16-byte GCM auth tag]
 *   → Base64-encode the whole buffer → put in the "content" field
 */

const crypto = require('crypto');
const forge  = require('node-forge');
const fs     = require('fs');

// ---------------------------------------------------------------------------
// PKCS#12 / KEK
// ---------------------------------------------------------------------------

function _extractKeyFromP12(raw, pin) {
  const asn1 = forge.asn1.fromDer(raw);
  const p12  = forge.pkcs12.pkcs12FromAsn1(asn1, false, pin);
  for (const bagType of [forge.pki.oids.pkcs8ShroudedKeyBag, forge.pki.oids.keyBag]) {
    const bags = p12.getBags({ bagType });
    const list  = bags[bagType];
    if (list && list.length > 0) return list[0].key;
  }
  throw new Error('No private key found in P12 file');
}

function loadPrivateKeyFromP12(p12Path, pin) {
  const raw = fs.readFileSync(p12Path).toString('binary');
  return _extractKeyFromP12(raw, pin);
}

function loadPrivateKeyFromBase64(base64, pin) {
  const raw = Buffer.from(base64, 'base64').toString('binary');
  return _extractKeyFromP12(raw, pin);
}

/**
 * Decrypt the CEK (secretKey field from getKey response).
 * The spec says RSA is used; we try OAEP/SHA-256 first, then OAEP/SHA-1 as fallback.
 */
function decryptCEK(encryptedSecretKeyBase64, privateKey) {
  const encrypted = forge.util.decode64(encryptedSecretKeyBase64);

  const attempts = [
    () => privateKey.decrypt(encrypted, 'RSA-OAEP', {
      md:   forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    }),
    () => privateKey.decrypt(encrypted, 'RSA-OAEP'),           // SHA-1 OAEP
    () => privateKey.decrypt(encrypted, 'RSAES-PKCS1-V1_5'),   // PKCS#1 v1.5 fallback
  ];

  for (let i = 0; i < attempts.length; i++) {
    try {
      const plain = attempts[i]();
      const buf = Buffer.from(plain, 'binary');
      if (buf.length === 32) return buf;
      // Callback secretKey decrypts to a base64-encoded 32-byte key (44 chars)
      if (buf.length === 44) {
        const decoded = Buffer.from(buf.toString('utf8'), 'base64');
        if (decoded.length === 32) return decoded;
      }
    } catch (_) { /* try next */ }
  }
  throw new Error('Failed to decrypt CEK with any RSA variant');
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

function encryptBody(jsonObj, cekBuffer) {
  const iv        = crypto.randomBytes(12);
  const cipher    = crypto.createCipheriv('aes-256-gcm', cekBuffer, iv);
  const plaintext = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag       = cipher.getAuthTag(); // 16 bytes

  // [4-byte IV length][IV][ciphertext][tag]
  const ivLenBuf = Buffer.allocUnsafe(4);
  ivLenBuf.writeInt32BE(iv.length, 0);
  return Buffer.concat([ivLenBuf, iv, encrypted, tag]).toString('base64');
}

function decryptBody(base64Content, cekBuffer) {
  const buf   = Buffer.from(base64Content, 'base64');
  const ivLen = buf.readInt32BE(0);
  if (ivLen !== 12) throw new Error(`Unexpected IV length: ${ivLen}`);

  const iv         = buf.slice(4, 4 + ivLen);
  const cipherData = buf.slice(4 + ivLen);
  const tag        = cipherData.slice(-16);
  const ciphertext = cipherData.slice(0, -16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', cekBuffer, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

// ---------------------------------------------------------------------------
// Request signing (common headers)
// ---------------------------------------------------------------------------

/**
 * Builds the five common headers required on every CorpID / iAM Smart POST.
 * signature = URLEncode(Base64(HMAC-SHA256(clientID + "HmacSHA256" + timestamp + nonce + encryptedBody, clientSecret)))
 * Both CorpID and iAM Smart require urlEncode=true (URL-encoded signature in headers).
 */
function buildAuthHeaders(clientID, clientSecret, timestamp, nonce, encryptedBody = '', urlEncode = true) {
  const message = clientID + 'HmacSHA256' + timestamp + nonce + encryptedBody;
  const sig     = crypto.createHmac('sha256', clientSecret).update(message).digest('base64');
  return {
    clientID,
    signatureMethod: 'HmacSHA256',
    signature:       urlEncode ? encodeURIComponent(sig) : sig,
    timestamp:       String(timestamp),
    nonce,
  };
}

/**
 * Builds the body for /api/v1/security/getKey (no business content to encrypt —
 * the common params go in the body rather than headers for this endpoint).
 */
function buildGetKeyBody(clientID, clientSecret) {
  const timestamp = Date.now();
  const nonce     = generateNonce();
  // No encrypted body component in the signature for getKey
  const message   = clientID + 'HmacSHA256' + timestamp + nonce;
  const sig       = crypto.createHmac('sha256', clientSecret).update(message).digest('base64');
  return {
    clientID,
    signatureMethod: 'HmacSHA256',
    signature:       encodeURIComponent(sig),
    timestamp,
    nonce,
  };
}


function generateNonce() {
  return crypto.randomUUID();
}

module.exports = {
  loadPrivateKeyFromP12,
  loadPrivateKeyFromBase64,
  decryptCEK,
  encryptBody,
  decryptBody,
  buildAuthHeaders,
  buildGetKeyBody,
  generateNonce,
};
