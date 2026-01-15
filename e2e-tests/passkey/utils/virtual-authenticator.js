/**
 * Virtual WebAuthn Authenticator for Testing
 * 
 * Simulates a hardware security key or platform authenticator for testing purposes.
 * Generates key pairs, creates attestation objects, and signs authentication assertions.
 */

import crypto from 'crypto';
import elliptic from 'elliptic';
import cbor from 'cbor';
import base64url from 'base64url';

const EC = elliptic.ec;
const ec = new EC('p256');

/**
 * Virtual authenticator that simulates WebAuthn operations
 */
export class VirtualAuthenticator {
  constructor(options = {}) {
    this.aaguid = options.aaguid || Buffer.alloc(16); // All zeros for testing
    this.credentials = new Map(); // credentialId -> { keyPair, signCount, ... }
    this.authenticatorType = options.type || 'platform'; // 'platform' or 'cross-platform'
    this.supportsUserVerification = options.supportsUserVerification !== false;
    this.supportsResidentKey = options.supportsResidentKey !== false;
  }

  /**
   * Create a new credential (registration)
   */
  makeCredential(options) {
    const {
      rpId,
      userId,
      challenge,
      userVerification = 'preferred',
      attestation = 'none',
      origin = null  // Allow specifying origin
    } = options;

    // Generate new key pair
    const keyPair = ec.genKeyPair();
    const credentialId = crypto.randomBytes(32);
    
    // Store credential
    const credential = {
      credentialId: credentialId.toString('base64url'),
      keyPair,
      signCount: 0,
      rpId,
      userId,
      userVerification,
      createdAt: Date.now()
    };
    
    this.credentials.set(credential.credentialId, credential);

    // Build authenticator data
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const flags = this._buildFlags({
      userPresent: true,
      userVerified: userVerification === 'required' || userVerification === 'preferred',
      attestedCredentialData: true
    });

    // Build attested credential data
    const attestedCredData = this._buildAttestedCredentialData(
      credentialId,
      keyPair
    );

    const authenticatorData = Buffer.concat([
      rpIdHash,
      flags,
      Buffer.from([0, 0, 0, 0]), // Sign count (0 for new credential)
      attestedCredData
    ]);

    // Build client data JSON
    // Use provided origin or construct from rpId
    const clientOrigin = origin || `https://${rpId}`;
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.create',
      challenge: base64url.encode(challenge),
      origin: clientOrigin,
      crossOrigin: false
    });

    // Build attestation object
    const attestationObject = {
      fmt: 'none',
      authData: authenticatorData,
      attStmt: {}
    };

    return {
      credentialId: credential.credentialId,
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
      origin = null  // Allow specifying origin
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

    // Sign the assertion
    const clientDataHash = crypto.createHash('sha256')
      .update(clientDataJSON)
      .digest();
    
    const signatureBase = Buffer.concat([
      authenticatorData,
      clientDataHash
    ]);

    const signature = this._signData(signatureBase, credential.keyPair);

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
   * Build attested credential data
   */
  _buildAttestedCredentialData(credentialId, keyPair) {
    // AAGUID (16 bytes)
    const aaguid = this.aaguid;

    // Credential ID length (2 bytes)
    const credIdLength = Buffer.alloc(2);
    credIdLength.writeUInt16BE(credentialId.length, 0);

    // Credential ID
    const credId = credentialId;

    // Credential public key (COSE format)
    const publicKey = this._buildCOSEPublicKey(keyPair);

    return Buffer.concat([
      aaguid,
      credIdLength,
      credId,
      publicKey
    ]);
  }

  /**
   * Build COSE-encoded public key
   */
  _buildCOSEPublicKey(keyPair) {
    const pubKey = keyPair.getPublic();
    const x = pubKey.getX().toBuffer('be', 32);
    const y = pubKey.getY().toBuffer('be', 32);

    // COSE key format for ES256
    const coseKey = {
      1: 2,        // kty: EC2
      3: -7,       // alg: ES256
      '-1': 1,     // crv: P-256
      '-2': x,     // x coordinate
      '-3': y      // y coordinate
    };

    return cbor.encode(coseKey);
  }

  /**
   * Sign data with private key
   */
  _signData(data, keyPair) {
    const hash = crypto.createHash('sha256').update(data).digest();
    const signature = keyPair.sign(hash);
    
    // Convert to raw format (r||s) for ES256
    const r = signature.r.toBuffer('be', 32);
    const s = signature.s.toBuffer('be', 32);
    
    const result = Buffer.concat([r, s]);
    console.log(`Signature generated: ${result.length} bytes (r: ${r.length}, s: ${s.length})`);
    
    return result;
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

export default VirtualAuthenticator;
