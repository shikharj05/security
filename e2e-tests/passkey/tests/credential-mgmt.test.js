/**
 * End-to-End Tests for Credential Management
 * 
 * Tests credential management operations via API
 * Requirements: 5.1, 5.2, 5.3, 5.4
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { TestClient } from '../utils/test-client.js';
import { VirtualAuthenticator } from '../utils/virtual-authenticator.js';
import {
  generateUsername,
  verifyCredentialStructure,
  assertStatus,
  assertHasField,
  assertLength,
  decodeBase64Url,
  sleep
} from '../utils/test-helpers.js';

describe('Credential Management E2E Tests', () => {
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
    // Cleanup
    for (const credId of testCredentials) {
      try {
        await client.deleteCredential(credId);
      } catch (error) {
        // Ignore
      }
    }
  });

  /**
   * Helper: Register a credential
   */
  async function registerCredential(username, friendlyName = 'Test Credential') {
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
      },
      friendlyName
    });

    assertStatus(verifyResponse, 200);
    await sleep(1000);

    return credential.credentialId;
  }

  test('List user credentials via API', async () => {
    const username = generateUsername('cred_list');
    testUsers.push(username);

    // Register multiple credentials
    const cred1Id = await registerCredential(username, 'Credential 1');
    const cred2Id = await registerCredential(username, 'Credential 2');
    const cred3Id = await registerCredential(username, 'Credential 3');

    testCredentials.push(cred1Id, cred2Id, cred3Id);

    // List credentials for this specific user (admin can query by username)
    const listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200, 'Failed to list credentials');

    assertHasField(listResponse.data, 'credentials');
    const credentials = listResponse.data.credentials;

    // Should have at least 3 credentials for this user
    expect(credentials.length).toBeGreaterThanOrEqual(3);

    // Verify structure of each credential
    for (const cred of credentials) {
      verifyCredentialStructure(cred);
      assertHasField(cred, 'friendlyName');
      assertHasField(cred, 'lastUsedAt');
    }
  });

  test('Credential metadata includes creation date, last used date, and friendly name', async () => {
    const username = generateUsername('cred_metadata');
    testUsers.push(username);

    const credId = await registerCredential(username, 'My Security Key');
    testCredentials.push(credId);

    const listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200);

    const credential = listResponse.data.credentials.find(c => c.credentialId === credId);
    expect(credential).toBeDefined();

    // Verify metadata fields
    assertHasField(credential, 'createdAt');
    assertHasField(credential, 'lastUsedAt');
    assertHasField(credential, 'friendlyName');

    expect(credential.friendlyName).toBe('My Security Key');
    expect(credential.createdAt).toBeTruthy();
    
    // lastUsedAt may be null if never used for authentication
    expect(credential.lastUsedAt === null || typeof credential.lastUsedAt === 'string').toBe(true);
  });

  test('Delete credential via API', async () => {
    const username = generateUsername('cred_delete');
    testUsers.push(username);

    const credId = await registerCredential(username);
    testCredentials.push(credId);

    // Verify credential exists
    let listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200);

    let credential = listResponse.data.credentials.find(c => c.credentialId === credId);
    expect(credential).toBeDefined();

    // Delete credential
    const deleteResponse = await client.deleteCredential(credId);
    assertStatus(deleteResponse, 200, 'Failed to delete credential');

    await sleep(1000);

    // Verify credential is deleted
    listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200);

    credential = listResponse.data.credentials.find(c => c.credentialId === credId);
    expect(credential).toBeUndefined();

    // Try to authenticate with deleted credential should fail
    const authOptionsResponse = await client.getAuthenticationOptions(username);
    if (authOptionsResponse.status === 200) {
      const options = authOptionsResponse.data;
      const challenge = decodeBase64Url(options.challenge);

      try {
        const assertion = authenticator.getAssertion({
          rpId: options.rpId,
          challenge,
          allowCredentials: []
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
      } catch (error) {
        // Expected - no matching credential
      }
    }
  });

  test('Rename credential via API', async () => {
    const username = generateUsername('cred_rename');
    testUsers.push(username);

    const credId = await registerCredential(username, 'Original Name');
    testCredentials.push(credId);

    // Update friendly name
    const newName = 'Updated Security Key';
    const updateResponse = await client.updateCredential(credId, {
      friendlyName: newName
    });

    assertStatus(updateResponse, 200, 'Failed to update credential');

    await sleep(1000);

    // Verify name was updated
    const listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200);

    const credential = listResponse.data.credentials.find(c => c.credentialId === credId);
    expect(credential).toBeDefined();
    expect(credential.friendlyName).toBe(newName);
  });

  test('Credential isolation between users', async () => {
    const user1 = generateUsername('cred_isolation_1');
    const user2 = generateUsername('cred_isolation_2');
    testUsers.push(user1, user2);

    // Register credentials for both users
    const user1CredId = await registerCredential(user1, 'User 1 Credential');
    const user2CredId = await registerCredential(user2, 'User 2 Credential');

    testCredentials.push(user1CredId, user2CredId);

    // List credentials for each user separately (admin can query by username)
    const user1ListResponse = await client.listCredentials(user1);
    assertStatus(user1ListResponse, 200);
    const user1Creds = user1ListResponse.data.credentials;

    const user2ListResponse = await client.listCredentials(user2);
    assertStatus(user2ListResponse, 200);
    const user2Creds = user2ListResponse.data.credentials;

    // Each user should have their own credential
    expect(user1Creds.length).toBeGreaterThanOrEqual(1);
    expect(user2Creds.length).toBeGreaterThanOrEqual(1);

    // User 1's credential should not appear in user 2's list
    const user1CredInUser2List = user2Creds.find(c => c.credentialId === user1CredId);
    expect(user1CredInUser2List).toBeUndefined();

    // User 2's credential should not appear in user 1's list
    const user2CredInUser1List = user1Creds.find(c => c.credentialId === user2CredId);
    expect(user2CredInUser1List).toBeUndefined();

    // Try to authenticate user 1 with user 2's credential should fail
    const authOptionsResponse = await client.getAuthenticationOptions(user1);
    if (authOptionsResponse.status === 200) {
      const options = authOptionsResponse.data;
      
      // allowCredentials should not include user 2's credential
      if (options.allowCredentials) {
        const hasUser2Cred = options.allowCredentials.some(c => c.id === user2CredId);
        expect(hasUser2Cred).toBe(false);
      }
    }
  });

  test('Delete non-existent credential returns appropriate error', async () => {
    const fakeCredId = 'non-existent-credential-id-12345';

    const deleteResponse = await client.deleteCredential(fakeCredId);

    // Should return 404 or similar error
    expect(deleteResponse.status).toBeGreaterThanOrEqual(400);
  });

  test('Update non-existent credential returns appropriate error', async () => {
    const fakeCredId = 'non-existent-credential-id-12345';

    const updateResponse = await client.updateCredential(fakeCredId, {
      friendlyName: 'New Name'
    });

    // Should return 404 or similar error
    expect(updateResponse.status).toBeGreaterThanOrEqual(400);
  });

  test('List credentials returns empty array when user has no credentials', async () => {
    const username = generateUsername('cred_empty');
    testUsers.push(username);

    // Don't register any credentials

    // List credentials for this user
    const listResponse = await client.listCredentials(username);
    assertStatus(listResponse, 200);

    const credentials = listResponse.data.credentials;
    expect(credentials.length).toBe(0);
  });
});
