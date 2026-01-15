/**
 * Virtual WebAuthn Authenticator using @simplewebauthn/server
 * 
 * Generates WebAuthn credentials that are compatible with standard WebAuthn implementations
 * including WebAuthn4J.
 */

import crypto from 'crypto';
import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import base64url from 'base64url';
import cbor from 'cbor';

/**
 * Virtual authenticator that uses @simplewebauthn/server for credential generation
 */
export class SimpleWebAuthnAuthenticator {
  constructor(options = {}) {
    this.credentials = new Map(); // credentialId -> credential data
    this.authenticatorType = options.type || 'platform';
    this.supportsUserVerification = options.supportsUserVerification !== false;
    this.supportsResidentKey = options.supportsResidentKey !== false;
  }

  /**
   * Create a new credential (registration)
   * This simulates what a real authenticator would do
   */
  makeCredential(options) {
    const {
      rpId,
      userId,
      challenge,
      userVerification = 'preferred',
      attestation = 'none',
      origin = null
    } = options;

    // Generate a key pair using Node's crypto
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1', // P-256 curve for ES256
      publicKeyEncoding: {
        type: 'spki',
        format: 'der'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der'
      }
    });

    // Generate credential ID
    const credentialId = crypto.randomBytes(32);
    const credentialIdBase64 = credentialId.toString('base64url');

    // Store credential with key pair
    const credential = {
      credentialId: credentialIdBase64,
      publicKey,
      privateKey,
      signCount: 0,
      rpId,
      userId,
      userVerification,
      createdAt: Date.now()
    };
    
    this.credentials.set(credentialIdBase64, credential);

    // Build authenticator data for registration
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const flags = this._buildFlags({
      userPresent: true,
      userVerified: userVerification === 'required' || userVerification === 'preferred',
      attestedCredentialData: true
    });

    // Build attested credential data (COSE format)
    const attestedCredData = this._buildAttestedCredentialData(credentialId, publicKey);

    const authenticatorData = Buffer.concat([
      rpIdHash,
      flags,
      Buffer.from([0, 0, 0, 0]), // Sign count (0 for new credential)
      attestedCredData
    ]);

    // Build client data JSON
    const clientOrigin = origin || `https://${rpId}`;
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.create',
      challenge: base64url.encode(challenge),
      origin: clientOrigin,
      crossOrigin: false
    });

    // Build attestation object (format: none, no signature)
    const attestationObject = {
      fmt: 'none',
      authData: authenticatorData,
      attStmt: {}
    };

    return {
      credentialId: credentialIdBase64,
      response: {
        clientDataJSON: Buffer.from(clientDataJSON).toString('base64url'),
        attestationObject: cbor.encode(attestationObject).toString('base64url')
      },
      type: 'public-key'
    };
  }

  /**
   * Get an assertion (authentication)
   */
  getAssertion(options) {
    const {
      rpId,
      challenge,
      allowCredentials = [],
      userVerification = 'preferred',
      origin = null
    } = options;

    console.log(`getAssertion called - credentials in map: ${this.credentials.size}`);

    // Find matching credential
    let credential = null;
    if (allowCredentials.length > 0) {
      for (const allowedCred of allowCredentials) {
        const cred = this.credentials.get(allowedCred.id);
        if (cred && cred.rpId === rpId) {
          credential = cred;
          break;
        }
      }
    } else {
      // Use any credential for this RP
      for (const cred of this.credentials.values()) {
        if (cred.rpId === rpId) {
          credential = cred;
          break;
        }
      }
    }

    if (!credential) {
      throw new Error('No matching credential found');
    }

    // Increment sign count
    credential.signCount++;

    // Build authenticator data
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const flags = this._buildFlags({
      userPresent: true,
      userVerified: userVerification === 'required' || userVerification === 'preferred'
    });

    const signCountBuffer = Buffer.alloc(4);
    signCountBuffer.writeUInt32BE(credential.signCount, 0);

    const authenticatorData = Buffer.concat([
      rpIdHash,
      flags,
      signCountBuffer
    ]);

    // Build client data JSON
    const clientOrigin = origin || `https://${rpId}`;
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.get',
      challenge: base64url.encode(challenge),
      origin: clientOrigin,
      crossOrigin: false
    });

    // Sign the assertion using Node's crypto
    const clientDataHash = crypto.createHash('sha256')
      .update(clientDataJSON)
      .digest();
    
    const signatureBase = Buffer.concat([
      authenticatorData,
      clientDataHash
    ]);

    console.log(`Signing data:`);
    console.log(`  AuthenticatorData (${authenticatorData.length} bytes): ${authenticatorData.toString('hex')}`);
    console.log(`  ClientDataJSON: ${clientDataJSON}`);
    console.log(`  ClientDataHash (${clientDataHash.length} bytes): ${clientDataHash.toString('hex')}`);
    console.log(`  SignatureBase (${signatureBase.length} bytes): ${signatureBase.toString('hex')}`);

    // Use Node's crypto to sign (this will be compatible with Java)
    const sign = crypto.createSign('SHA256');
    sign.update(signatureBase);
    sign.end();
    
    const signatureDER = sign.sign({
      key: credential.privateKey,
      format: 'der',
      type: 'pkcs8'
    });

    // Convert DER signature to raw format (r||s) for WebAuthn
    const signature = this._derToRaw(signatureDER);

    console.log(`Signature base length: ${signatureBase.length}, Signature: ${signature.toString('hex').substring(0, 32)}...`);

    return {
      credentialId: credential.credentialId,
      response: {
        clientDataJSON: Buffer.from(clientDataJSON).toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'),
        signature: signature.toString('base64url'),
        userHandle: credential.userId
      },
      type: 'public-key'
    };
  }

  /**
   * Convert DER-encoded ECDSA signature to raw format (r||s)
   */
  _derToRaw(derSignature) {
    // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    let offset = 0;
    
    // Skip sequence tag and length
    if (derSignature[offset++] !== 0x30) {
      throw new Error('Invalid DER signature');
    }
    offset++; // Skip total length
    
    // Read r
    if (derSignature[offset++] !== 0x02) {
      throw new Error('Invalid DER signature - expected INTEGER for r');
    }
    const rLength = derSignature[offset++];
    let r = derSignature.slice(offset, offset + rLength);
    offset += rLength;
    
    // Read s
    if (derSignature[offset++] !== 0x02) {
      throw new Error('Invalid DER signature - expected INTEGER for s');
    }
    const sLength = derSignature[offset++];
    let s = derSignature.slice(offset, offset + sLength);
    
    // Remove leading zeros if present (DER encoding adds them for positive numbers)
    while (r.length > 32 && r[0] === 0x00) {
      r = r.slice(1);
    }
    while (s.length > 32 && s[0] === 0x00) {
      s = s.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (r.length < 32) {
      const padding = Buffer.alloc(32 - r.length);
      r = Buffer.concat([padding, r]);
    }
    if (s.length < 32) {
      const padding = Buffer.alloc(32 - s.length);
      s = Buffer.concat([padding, s]);
    }
    
    return Buffer.concat([r, s]);
  }

  /**
   * Build authenticator flags byte
   */
  _buildFlags(options) {
    let flags = 0;
    if (options.userPresent) flags |= 0x01;
    if (options.userVerified) flags |= 0x04;
    if (options.attestedCredentialData) flags |= 0x40;
    if (options.extensionData) flags |= 0x80;
    return Buffer.from([flags]);
  }

  /**
   * Build attested credential data (includes COSE public key)
   */
  _buildAttestedCredentialData(credentialId, publicKeyDER) {
    // AAGUID (16 bytes) - all zeros for testing
    const aaguid = Buffer.alloc(16);

    // Credential ID length (2 bytes)
    const credIdLength = Buffer.alloc(2);
    credIdLength.writeUInt16BE(credentialId.length, 0);

    // Extract public key coordinates from DER format
    const publicKeyObject = crypto.createPublicKey({
      key: publicKeyDER,
      format: 'der',
      type: 'spki'
    });
    
    const jwk = publicKeyObject.export({ format: 'jwk' });
    
    // Convert JWK coordinates to buffers
    const x = Buffer.from(jwk.x, 'base64');
    const y = Buffer.from(jwk.y, 'base64');

    console.log(`Registration - Public key coordinates:`);
    console.log(`  X (${x.length} bytes): ${x.toString('hex').substring(0, 32)}...`);
    console.log(`  Y (${y.length} bytes): ${y.toString('hex').substring(0, 32)}...`);

    // Build COSE key (CBOR format)
    const coseKey = {
      1: 2,        // kty: EC2
      3: -7,       // alg: ES256
      '-1': 1,     // crv: P-256
      '-2': x,     // x coordinate
      '-3': y      // y coordinate
    };

    const coseKeyEncoded = cbor.encode(coseKey);

    return Buffer.concat([
      aaguid,
      credIdLength,
      credentialId,
      coseKeyEncoded
    ]);
  }

  /**
   * Get credential by ID
   */
  getCredential(credentialId) {
    return this.credentials.get(credentialId);
  }

  /**
   * Remove credential
   */
  removeCredential(credentialId) {
    return this.credentials.delete(credentialId);
  }

  /**
   * Clear all credentials
   */
  clearCredentials() {
    this.credentials.clear();
  }
}

export default SimpleWebAuthnAuthenticator;
