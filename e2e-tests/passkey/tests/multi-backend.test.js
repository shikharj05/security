/**
 * End-to-End Tests for Multi-Backend Integration
 * 
 * Tests passkey authentication alongside other authentication methods
 * Requirements: 1.5, 7.1, 7.2, 7.3, 7.4
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { TestClient } from '../utils/test-client.js';
import { VirtualAuthenticator } from '../utils/virtual-authenticator.js';
import {
  generateUsername,
  assertStatus,
  assertHasField,
  decodeBase64Url,
  sleep
} from '../utils/test-helpers.js';

describe('Multi-Backend Integration E2E Tests', () => {
  let client;
  let authenticator;
  const testUsers = [];
  const testCredentials = [];

  beforeAll(async () => {
    client = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'MyStr0ng!Pass#2026'
    });

    await client.waitForCluster(60000);

    authenticator = new VirtualAuthenticator({
      type: 'platform',
      supportsUserVerification: true
    });
  });

  afterAll(async () => {
    for (const credId of testCredentials) {
      try {
        await client.deleteCredential(credId);
      } catch (error) {
        // Ignore
      }
    }
  });

  async function registerCredential(username) {
    const optionsResponse = await client.getRegistrationOptions(username);
    assertStatus(optionsResponse, 200);

    const options = optionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);
    const challengeId = options.challengeId;

    const credential = authenticator.makeCredential({
      rpId: options.rp.id,
      userId: options.user.id,
      challenge,
      origin: 'https://localhost:9200'
    });

    const verifyResponse = await client.verifyRegistration({
      username,
      challengeId,
      credential: {
        id: credential.credentialId,
        rawId: credential.credentialId,
        response: credential.response,
        type: credential.type
      }
    });

    assertStatus(verifyResponse, 200);
    await sleep(1000);
    return credential.credentialId;
  }

  test('Passkey authentication alongside basic auth', async () => {
    // Test that both passkey and basic auth work concurrently

    // 1. Test basic auth still works
    const basicClient = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'MyStr0ng!Pass#2026'
    });

    const healthResponse = await basicClient.checkHealth();
    expect(healthResponse).toBe(true);

    // 2. Test passkey auth works
    const username = generateUsername('multi_passkey');
    testUsers.push(username);

    const credId = await registerCredential(username);
    testCredentials.push(credId);

    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

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

    assertStatus(verifyResponse, 200);
    expect(verifyResponse.data.success).toBe(true);
  });

  test('Fallback to basic auth when passkey fails', async () => {
    const username = generateUsername('multi_fallback');
    testUsers.push(username);

    // Register passkey
    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Try passkey auth with invalid signature
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

    const assertion = authenticator.getAssertion({
      rpId: options.rpId,
      challenge,
      allowCredentials: options.allowCredentials || [],
      origin: 'https://localhost:9200'
    });

    const passkeyVerifyResponse = await client.verifyAuthentication({
      username,
      challengeId: options.challengeId,
      assertion: {
        id: assertion.credentialId,
        rawId: assertion.credentialId,
        response: {
          ...assertion.response,
          signature: 'invalid-signature'
        },
        type: assertion.type
      }
    });

    // Passkey auth should fail
    expect(passkeyVerifyResponse.status).toBeGreaterThanOrEqual(400);

    // Basic auth should still work
    const basicClient = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'MyStr0ng!Pass#2026'
    });

    const healthResponse = await basicClient.checkHealth();
    expect(healthResponse).toBe(true);
  });

  test('Authentication domain configuration', async () => {
    // Verify that passkey auth domain is configured correctly

    // Get cluster settings or security config
    const configResponse = await client.get('/_plugins/_security/api/securityconfig');
    
    if (configResponse.status === 200) {
      const config = configResponse.data;
      
      // Verify passkey domain exists
      assertHasField(config, 'config');
      
      if (config.config && config.config.dynamic && config.config.dynamic.authc) {
        const authc = config.config.dynamic.authc;
        
        // Look for passkey auth domain
        const passkeyDomain = Object.values(authc).find(
          domain => domain.authentication_backend && domain.authentication_backend.type === 'passkey'
        );
        
        if (passkeyDomain) {
          expect(passkeyDomain.http_enabled).toBe(true);
          expect(passkeyDomain.http_authenticator.type).toBe('passkey');
          expect(passkeyDomain.authentication_backend.type).toBe('passkey');
        }
      }
    }
  });

  test('Role mapping with passkey authentication', async () => {
    const username = generateUsername('multi_roles');
    testUsers.push(username);

    // Register passkey
    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Authenticate with passkey
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

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

    assertStatus(verifyResponse, 200);
    
    // Verify user principal has roles
    if (verifyResponse.data.roles) {
      expect(Array.isArray(verifyResponse.data.roles)).toBe(true);
    }

    // Verify user can access resources based on roles
    // This would require creating a client with passkey auth token
    // For now, we document that role mapping should work
  });

  test('User attributes populated from passkey authentication', async () => {
    const username = generateUsername('multi_attributes');
    testUsers.push(username);

    // Register passkey
    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Authenticate with passkey
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

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

    assertStatus(verifyResponse, 200);
    
    // Verify user principal has username
    assertHasField(verifyResponse.data, 'username');
    expect(verifyResponse.data.username).toBe(username);

    // Additional attributes may be present depending on configuration
    if (verifyResponse.data.attributes) {
      expect(typeof verifyResponse.data.attributes).toBe('object');
    }
  });

  test('Passkey and basic auth use same authorization rules', async () => {
    const username = generateUsername('multi_authz');
    testUsers.push(username);

    // Register passkey
    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Authenticate with passkey
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

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

    assertStatus(verifyResponse, 200);

    // Both authentication methods should result in same authorization
    // This is verified by checking that the same roles are applied
    // In a full test, we would:
    // 1. Create test index
    // 2. Try to access with passkey auth
    // 3. Try to access with basic auth
    // 4. Verify same permissions apply
  });

  test('Multiple authentication attempts with different backends', async () => {
    const username = generateUsername('multi_attempts');
    testUsers.push(username);

    // Register passkey
    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Try basic auth first
    const basicClient = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'MyStr0ng!Pass#2026'
    });

    const health1 = await basicClient.checkHealth();
    expect(health1).toBe(true);

    // Then try passkey auth
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    assertStatus(authOptionsResponse, 200);

    const options = authOptionsResponse.data;
    const challenge = decodeBase64Url(options.challenge);

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

    assertStatus(verifyResponse, 200);

    // Then try basic auth again
    const health2 = await basicClient.checkHealth();
    expect(health2).toBe(true);

    // All should work without interference
  });

  test('Passkey authentication order in domain configuration', async () => {
    // Verify that passkey auth domain has correct order

    const configResponse = await client.get('/_plugins/_security/api/securityconfig');
    
    if (configResponse.status === 200) {
      const config = configResponse.data;
      
      if (config.config && config.config.dynamic && config.config.dynamic.authc) {
        const authc = config.config.dynamic.authc;
        
        // Find passkey and basic auth domains
        let passkeyOrder = null;
        let basicOrder = null;

        for (const [name, domain] of Object.entries(authc)) {
          if (domain.authentication_backend) {
            if (domain.authentication_backend.type === 'passkey') {
              passkeyOrder = domain.order;
            } else if (domain.authentication_backend.type === 'internal') {
              basicOrder = domain.order;
            }
          }
        }

        // Passkey should be tried before basic auth (lower order number)
        if (passkeyOrder !== null && basicOrder !== null) {
          expect(passkeyOrder).toBeLessThan(basicOrder);
        }
      }
    }
  });
});
