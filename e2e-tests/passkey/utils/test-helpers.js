/**
 * Test Helper Utilities
 * 
 * Common utilities for passkey e2e tests.
 */

import crypto from 'crypto';
import base64url from 'base64url';

/**
 * Generate random username for testing
 */
export function generateUsername(prefix = 'testuser') {
  const random = crypto.randomBytes(4).toString('hex');
  return `${prefix}_${random}`;
}

/**
 * Generate random challenge
 */
export function generateChallenge(length = 32) {
  return crypto.randomBytes(length);
}

/**
 * Decode base64url string
 */
export function decodeBase64Url(str) {
  return base64url.toBuffer(str);
}

/**
 * Encode buffer to base64url
 */
export function encodeBase64Url(buffer) {
  return base64url.encode(buffer);
}

/**
 * Parse client data JSON
 */
export function parseClientDataJSON(clientDataJSON) {
  const decoded = decodeBase64Url(clientDataJSON);
  return JSON.parse(decoded.toString('utf8'));
}

/**
 * Parse authenticator data
 */
export function parseAuthenticatorData(authData) {
  const buffer = decodeBase64Url(authData);
  
  const rpIdHash = buffer.slice(0, 32);
  const flags = buffer[32];
  const signCount = buffer.readUInt32BE(33);
  
  return {
    rpIdHash,
    flags: {
      userPresent: !!(flags & 0x01),
      userVerified: !!(flags & 0x04),
      attestedCredentialData: !!(flags & 0x40),
      extensionData: !!(flags & 0x80)
    },
    signCount,
    raw: buffer
  };
}

/**
 * Wait for condition with timeout
 */
export async function waitFor(condition, timeout = 5000, interval = 100) {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return true;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error('Condition not met within timeout');
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry operation with exponential backoff
 */
export async function retry(operation, maxAttempts = 3, baseDelay = 1000) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await sleep(delay);
      }
    }
  }
  
  throw lastError;
}

/**
 * Assert response status
 */
export function assertStatus(response, expectedStatus, message) {
  if (response.status !== expectedStatus) {
    const errorDetails = response.data ? JSON.stringify(response.data) : response.statusText;
    const error = new Error(
      message || `Expected status ${expectedStatus}, got ${response.status}. Response: ${errorDetails}`
    );
    error.response = response;
    throw error;
  }
}

/**
 * Assert response contains field
 */
export function assertHasField(obj, field, message) {
  if (!(field in obj)) {
    throw new Error(message || `Expected object to have field: ${field}`);
  }
}

/**
 * Assert array contains item
 */
export function assertContains(array, item, message) {
  if (!array.includes(item)) {
    throw new Error(message || `Expected array to contain: ${item}`);
  }
}

/**
 * Assert array length
 */
export function assertLength(array, expectedLength, message) {
  if (array.length !== expectedLength) {
    throw new Error(
      message || `Expected length ${expectedLength}, got ${array.length}`
    );
  }
}

/**
 * Create test credential data
 */
export function createTestCredential(options = {}) {
  return {
    credentialId: options.credentialId || encodeBase64Url(crypto.randomBytes(32)),
    username: options.username || generateUsername(),
    friendlyName: options.friendlyName || 'Test Credential',
    createdAt: options.createdAt || new Date().toISOString(),
    lastUsedAt: options.lastUsedAt || null
  };
}

/**
 * Verify credential structure
 */
export function verifyCredentialStructure(credential) {
  assertHasField(credential, 'credentialId', 'Credential missing credentialId');
  assertHasField(credential, 'username', 'Credential missing username');
  assertHasField(credential, 'createdAt', 'Credential missing createdAt');
}

/**
 * Verify registration options structure
 */
export function verifyRegistrationOptions(options) {
  assertHasField(options, 'challenge', 'Options missing challenge');
  assertHasField(options, 'rp', 'Options missing rp');
  assertHasField(options, 'user', 'Options missing user');
  assertHasField(options, 'pubKeyCredParams', 'Options missing pubKeyCredParams');
}

/**
 * Verify authentication options structure
 */
export function verifyAuthenticationOptions(options) {
  assertHasField(options, 'challenge', 'Options missing challenge');
  assertHasField(options, 'rpId', 'Options missing rpId');
}

/**
 * Extract error message from response
 */
export function extractErrorMessage(response) {
  if (response.data && typeof response.data === 'object') {
    return response.data.reason || response.data.error || response.data.message || 'Unknown error';
  }
  return response.statusText || 'Unknown error';
}

/**
 * Log test info
 */
export function logTestInfo(message, data = null) {
  console.log(`[TEST] ${message}`);
  if (data) {
    console.log(JSON.stringify(data, null, 2));
  }
}

/**
 * Log test error
 */
export function logTestError(message, error) {
  console.error(`[TEST ERROR] ${message}`);
  if (error) {
    console.error(error);
  }
}

export default {
  generateUsername,
  generateChallenge,
  decodeBase64Url,
  encodeBase64Url,
  parseClientDataJSON,
  parseAuthenticatorData,
  waitFor,
  sleep,
  retry,
  assertStatus,
  assertHasField,
  assertContains,
  assertLength,
  createTestCredential,
  verifyCredentialStructure,
  verifyRegistrationOptions,
  verifyAuthenticationOptions,
  extractErrorMessage,
  logTestInfo,
  logTestError
};
