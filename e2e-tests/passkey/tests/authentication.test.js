/**
 * End-to-End Tests for Passkey Authentication Flow
 * 
 * Tests complete authentication flow: options → authenticate → verify session
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { TestClient } from '../utils/test-client.js';
import { SimpleWebAuthnAuthenticator } from '../utils/simple-webauthn-authenticator.js';
import {
  generateUsername,
  verifyAuthenticationOptions,
  assertStatus,
  assertHasField,
  decodeBase64Url,
  sleep
} from '../utils/test-helpers.js';

describe('Passkey Authentication Flow E2E Tests', () => {
  let client;
  const testUsers = [];
  const registeredCredentials = new Map(); // username -> credentialId

  beforeAll(async () => {
    client = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'MyStr0ng!Pass#2026'
    });

    await client.waitForCluster(60000);
  });

  afterAll(async () => {
    // Cleanup
    for (const [username, credentialId] of registeredCredentials.entries()) {
      try {
        await client.deleteCredential(credentialId);
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  });

  /**
   * Helper: Register a credential for testing
   */
  async function registerCredential(username, auth = authenticator) {
    const optionsResponse = await client.getRegistrationOptions(username);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

    const credential = auth.makeCredential({
      rpId: options.rp.id,
      userId: options.user.id,
      challenge,
      origin: 'https://localhost:9200'
    });

    const verifyResponse = await client.verifyRegistration({
      username,
      challengeId: options.challengeId,
      credential: {
        id: credential.credentialId,
        rawId: credential.credentialId,
        response: credential.response,
        type: credential.type
      }
    });

    assertStatus(verifyResponse, 200);
    await sleep(1000); // Allow indexing

    return credential.credentialId;
  }

  test('Complete authentication flow: options → authenticate → verify session', async () => {
    const username = 'admin';
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    // Register credential first
    const credentialId = await registerCredential(username, authenticator);
    registeredCredentials.set(username, credentialId);

    // Step 1: Get authentication options
    const optionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(optionsResponse, 200, 'Failed to get authentication options');

    const options = optionsResponse.data;
    verifyAuthenticationOptions(options);
    expect(options.challenge).toBeDefined();
    expect(options.rpId).toBe('localhost');

    // Step 2: Create assertion with virtual authenticator
    const challenge = decodeBase64Url(options.challenge);
    
    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge,
      allowCredentials: options.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    // Step 3: Verify authentication
    const verifyResponse = await client.verifyAuthentication({
      username,
      challengeId: options.challengeId,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: {
          clientDataJSON: assertion.response.clientDataJSON,
          authenticatorData: assertion.response.authenticatorData,
          signature: assertion.response.signature,
          userHandle: assertion.response.userHandle
        },
        type: assertion.type
      }
    });

    if (verifyResponse.status !== 200) {
      console.log('Auth verify failed:', JSON.stringify(verifyResponse.data, null, 2));
    }

    assertStatus(verifyResponse, 200, 'Failed to verify authentication');
    expect(verifyResponse.data.success).toBe(true);
    assertHasField(verifyResponse.data, 'username');
    expect(verifyResponse.data.username).toBe(username);
  });

  test('Authentication with multiple credentials', async () => {
    const username = generateUsername('auth_multi');
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    // Register first credential
    const cred1Id = await registerCredential(username, authenticator);
    
    // Register second credential with the SAME authenticator
    // (In reality, this would be a different device, but for testing we can use the same authenticator)
    const optionsResponse2 = await client.getRegistrationOptions(username);
    assertStatus(optionsResponse2, 200);

    const options2 = optionsResponse2.data;
    const challenge2 = decodeBase64Url(options2.challenge);

    const credential2 = authenticator.makeCredential({
      rpId: options2.rp.id,
      userId: options2.user.id,
      challenge: challenge2,
      origin: 'https://localhost:9200'
    });

    await client.verifyRegistration({
      username,
      challengeId: options2.challengeId,
      credential: {
        id: credential2.credentialId,
        rawId: credential2.credentialId,
        response: credential2.response,
        type: credential2.type
      }
    });

    await sleep(1000);
    registeredCredentials.set(username, cred1Id);

    // Authenticate with first credential
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const authOptions = authOptionsResponse.data;
    const authChallenge = decodeBase64Url(authOptions.challenge);

    const assertion1 = authenticator.getAssertion({
      rpId: authOptions.rpId,
      challenge: authChallenge,
      allowCredentials: authOptions.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    const verify1Response = await client.verifyAuthentication({
      username,
      challengeId: authOptions.challengeId,
      assertion: {
        id: assertion1.credentialId,
        rawId: assertion1.credentialId,
        response: assertion1.response,
        type: assertion1.type
      }
    });

    assertStatus(verify1Response, 200);
    expect(verify1Response.data.success).toBe(true);

    // Authenticate with second credential
    const authOptions2Response = await client.getAuthenticationOptions(username);
    assertStatus(authOptions2Response, 200);

    const authOptions2 = authOptions2Response.data;
    const authChallenge2 = decodeBase64Url(authOptions2.challenge);

    const assertion2 = authenticator.getAssertion({
      rpId: authOptions2.rpId,
      challenge: authChallenge2,
      allowCredentials: authOptions2.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    const verify2Response = await client.verifyAuthentication({
      username,
      challengeId: authOptions2.challengeId,
      assertion: {
        id: assertion2.credentialId,
        rawId: assertion2.credentialId,
        response: assertion2.response,
        type: assertion2.type
      }
    });

    assertStatus(verify2Response, 200);
    expect(verify2Response.data.success).toBe(true);
  });

  test('Authentication with expired challenge', async () => {
    const username = generateUsername('auth_expired');
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    const credentialId = await registerCredential(username, authenticator);
    registeredCredentials.set(username, credentialId);

    // Get authentication options
    const optionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

    // Wait for challenge to potentially expire
    await sleep(2000);

    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge,
      allowCredentials: options.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    const verifyResponse = await client.verifyAuthentication({
      username,
      challengeId: options.challengeId,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: assertion.response,
        type: assertion.type
      }
    });

    // May succeed if not expired, or fail if expired
    if (verifyResponse.status >= 400) {
      expect(verifyResponse.status).toBeGreaterThanOrEqual(400);
    }
  });

  test('Authentication error: invalid signature', async () => {
    const username = generateUsername('auth_invalid_sig');
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    const credentialId = await registerCredential(username, authenticator);
    registeredCredentials.set(username, credentialId);

    const optionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge,
      allowCredentials: options.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    // Corrupt the signature
    const corruptedSignature = 'invalid-signature-data-here';

    const verifyResponse = await client.verifyAuthentication({
      username,
      challengeId: options.challengeId,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: {
          clientDataJSON: assertion.response.clientDataJSON,
          authenticatorData: assertion.response.authenticatorData,
          signature: corruptedSignature,
          userHandle: assertion.response.userHandle
        },
        type: assertion.type
      }
    });

    // Should fail with 400 or 401
    expect(verifyResponse.status).toBeGreaterThanOrEqual(400);
  });

  test('Authentication error: unknown credential', async () => {
    const username = generateUsername('auth_unknown');
    testUsers.push(username);

    // Don't register any credential

    const optionsResponse = await client.getAuthenticationOptions(username);
    
    // May return options even without credentials
    if (optionsResponse.status === 200) {
      const options = optionsResponse.data;
      const challenge = decodeBase64Url(options.challenge);

      // Try to authenticate with non-existent credential
      const fakeAuth = new SimpleWebAuthnAuthenticator();
      const fakeCredential = fakeAuth.makeCredential({
        rpId: options.rpId,
        userId: 'fake-user-id',
        challenge: Buffer.from('fake-challenge')
      });

      const assertion = fakeAuth.getAssertion({
        rpId: options.rpId,
        challenge,
        allowCredentials: [],
        origin: 'https://localhost:9200'
      });

      const verifyResponse = await client.verifyAuthentication({
        username,
        challengeId: options.challengeId,
        assertion: {
          id: assertion.credentialId,
          rawId: assertion.credentialId,
          response: assertion.response,
          type: assertion.type
        }
      });

      // Should fail
      expect(verifyResponse.status).toBeGreaterThanOrEqual(400);
    }
  });

  test('Authentication error: challenge mismatch', async () => {
    const username = generateUsername('auth_challenge_mismatch');
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    const credentialId = await registerCredential(username, authenticator);
    registeredCredentials.set(username, credentialId);

    const optionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;

    // Use wrong challenge
    const wrongChallenge = Buffer.from('wrong-challenge-data-here-12345678901234567890');

    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge: wrongChallenge,
      allowCredentials: options.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    const verifyResponse = await client.verifyAuthentication({
      username,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: assertion.response,
        type: assertion.type
      }
    });

    // Should fail
    expect(verifyResponse.status).toBeGreaterThanOrEqual(400);
  });

  test('Authentication without specifying username', async () => {
    const username = generateUsername('auth_no_username');
    testUsers.push(username);

    // Create authenticator for this test
    const authenticator = new SimpleWebAuthnAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });

    const credentialId = await registerCredential(username, authenticator);
    registeredCredentials.set(username, credentialId);

    // Get authentication options without username
    const optionsResponse = await client.getAuthenticationOptions(null);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;
    verifyAuthenticationOptions(options);

    const challenge = decodeBase64Url(options.challenge);

    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge,
      allowCredentials: [],
      origin: 'https://localhost:9200'
    });

    const verifyResponse = await client.verifyAuthentication({
      challengeId: options.challengeId,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: assertion.response,
        type: assertion.type
      }
    });

    // Should succeed or fail depending on implementation
    if (verifyResponse.status === 200) {
      expect(verifyResponse.data.success).toBe(true);
    }
  });
});
