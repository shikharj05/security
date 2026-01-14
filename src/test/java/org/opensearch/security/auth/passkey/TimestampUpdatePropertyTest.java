/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for timestamp update on credential use.
 * 
 * **Feature: passkey-authentication, Property 27: Timestamp update on use**
 * **Validates: Requirements 6.4**
 * 
 * For any successful authentication, the credential's last used timestamp 
 * should be updated to reflect the authentication event.
 */
public class TimestampUpdatePropertyTest {

    private PasskeyAuthenticationBackend backend;
    private InMemoryChallengeStore challengeStore;
    private MockPasskeyCredentialRepository credentialRepository;
    private MockWebAuthnManager webAuthnManager;

    @Before
    public void setUp() {
        challengeStore = new InMemoryChallengeStore();
        credentialRepository = new MockPasskeyCredentialRepository();
        
        RelyingPartyConfig rpConfig = new RelyingPartyConfig(
            "opensearch.example.com",
            "OpenSearch",
            List.of("https://opensearch.example.com"),
            300000L,
            com.webauthn4j.data.UserVerificationRequirement.PREFERRED,
            com.webauthn4j.data.AttestationConveyancePreference.NONE,
            null,
            com.webauthn4j.data.ResidentKeyRequirement.PREFERRED,
            List.of()
        );
        
        webAuthnManager = new MockWebAuthnManager(rpConfig);
        
        backend = new PasskeyAuthenticationBackend(
            Settings.EMPTY,
            Paths.get("/tmp"),
            webAuthnManager,
            credentialRepository,
            challengeStore,
            org.mockito.Mockito.mock(org.opensearch.security.auditlog.AuditLog.class)
        );
    }

    /**
     * Property 27: Timestamp update on use
     * 
     * For any successful authentication, the updateLastUsed method should be called
     * on the credential repository with the credential ID.
     * 
     * This test runs 100 iterations to verify that every successful authentication
     * triggers a timestamp update.
     */
    @Test
    public void timestampUpdateOnUse() {
        for (int i = 0; i < 100; i++) {
            String username = "user_" + i;
            String credentialId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("cred_" + i).getBytes());
            
            // Create credential
            PasskeyCredential credential = createCredential(username, credentialId);
            credentialRepository.storeCredential(credential);
            
            // Record the initial update count
            int initialUpdateCount = credentialRepository.getUpdateLastUsedCount(credentialId);
            
            // Create challenge
            String challengeId = UUID.randomUUID().toString();
            byte[] challengeBytes = new byte[32];
            Challenge challenge = new Challenge(
                challengeId,
                challengeBytes,
                username,
                Challenge.ChallengeType.AUTHENTICATION,
                Instant.now(),
                Instant.now().plusSeconds(300),
                null
            );
            challengeStore.storeChallenge(challengeId, challenge);
            
            // Configure mock
            webAuthnManager.setNextAuthenticationResult(
                WebAuthnManager.AuthenticationResult.success(credential.getSignatureCounter() + 1)
            );
            
            // Create assertion
            HTTPPasskeyAuthenticator.PasskeyAssertion assertion = new HTTPPasskeyAuthenticator.PasskeyAssertion(
                credentialId,
                "clientDataJSON",
                "authenticatorData",
                "signature",
                challengeId,
                null
            );
            
            // Create auth credentials
            AuthCredentials authCredentials = new AuthCredentials(credentialId, assertion);
            authCredentials.markComplete();
            
            // Authenticate
            AuthenticationContext context = new AuthenticationContext(authCredentials);
            User user = backend.authenticate(context);
            
            // Assert: User should be created successfully
            assertNotNull("User should not be null (iteration " + i + ")", user);
            
            // Assert: updateLastUsed should have been called exactly once more
            int finalUpdateCount = credentialRepository.getUpdateLastUsedCount(credentialId);
            assertTrue(
                "updateLastUsed should be called on successful authentication (iteration " + i + ")",
                finalUpdateCount == initialUpdateCount + 1
            );
        }
    }

    /**
     * Property 27: Multiple authentications update timestamp multiple times
     * 
     * For any credential used multiple times, the timestamp should be updated
     * each time it's used for authentication.
     */
    @Test
    public void multipleAuthenticationsUpdateTimestamp() {
        String username = "multi_auth_user";
        String credentialId = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("multi_auth_cred".getBytes());
        
        // Create credential
        PasskeyCredential credential = createCredential(username, credentialId);
        credentialRepository.storeCredential(credential);
        
        // Authenticate multiple times (100 iterations)
        for (int i = 0; i < 100; i++) {
            // Record the current update count
            int currentUpdateCount = credentialRepository.getUpdateLastUsedCount(credentialId);
            
            // Create a new challenge for each authentication
            String challengeId = UUID.randomUUID().toString();
            byte[] challengeBytes = new byte[32];
            Challenge challenge = new Challenge(
                challengeId,
                challengeBytes,
                username,
                Challenge.ChallengeType.AUTHENTICATION,
                Instant.now(),
                Instant.now().plusSeconds(300),
                null
            );
            challengeStore.storeChallenge(challengeId, challenge);
            
            // Configure mock
            webAuthnManager.setNextAuthenticationResult(
                WebAuthnManager.AuthenticationResult.success(credential.getSignatureCounter() + i + 1)
            );
            
            // Create assertion
            HTTPPasskeyAuthenticator.PasskeyAssertion assertion = new HTTPPasskeyAuthenticator.PasskeyAssertion(
                credentialId,
                "clientDataJSON",
                "authenticatorData",
                "signature",
                challengeId,
                null
            );
            
            // Create auth credentials
            AuthCredentials authCredentials = new AuthCredentials(credentialId, assertion);
            authCredentials.markComplete();
            
            // Authenticate
            AuthenticationContext context = new AuthenticationContext(authCredentials);
            User user = backend.authenticate(context);
            
            // Assert: User should be created successfully
            assertNotNull("User should not be null (iteration " + i + ")", user);
            
            // Assert: updateLastUsed should have been called one more time
            int newUpdateCount = credentialRepository.getUpdateLastUsedCount(credentialId);
            assertTrue(
                "updateLastUsed should be called on each authentication (iteration " + i + ")",
                newUpdateCount == currentUpdateCount + 1
            );
            
            // Assert: Total update count should equal iteration number + 1
            assertTrue(
                "Total update count should match number of authentications (iteration " + i + ")",
                newUpdateCount == i + 1
            );
        }
    }

    // Helper methods

    private PasskeyCredential createCredential(String username, String credentialId) {
        byte[] publicKey = new byte[65];
        return new PasskeyCredential(
            credentialId,
            username,
            publicKey,
            0L,
            "00000000-0000-0000-0000-000000000000",
            List.of("internal"),
            new PasskeyMetadata("Test Device", "platform", "Test Agent"),
            Instant.now(),
            null,
            false,
            false
        );
    }

    // Mock implementations

    private static class MockPasskeyCredentialRepository implements PasskeyCredentialRepository {
        private final List<PasskeyCredential> credentials = new ArrayList<>();
        private final Map<String, Integer> updateLastUsedCalls = new HashMap<>();

        @Override
        public void storeCredential(PasskeyCredential credential) {
            credentials.add(credential);
            updateLastUsedCalls.put(credential.getCredentialId(), 0);
        }

        @Override
        public Optional<PasskeyCredential> findByCredentialId(String credentialId) {
            return credentials.stream()
                .filter(c -> c.getCredentialId().equals(credentialId))
                .findFirst();
        }

        @Override
        public List<PasskeyCredential> findByUsername(String username) {
            return credentials.stream()
                .filter(c -> c.getUsername().equals(username))
                .toList();
        }

        @Override
        public void deleteCredential(String credentialId) {
            credentials.removeIf(c -> c.getCredentialId().equals(credentialId));
        }

        @Override
        public void updateCredentialMetadata(String credentialId, PasskeyMetadata metadata) {
        }

        @Override
        public void updateSignatureCounter(String credentialId, long counter) {
        }

        @Override
        public void updateLastUsed(String credentialId) {
            // Track how many times this method is called for each credential
            updateLastUsedCalls.merge(credentialId, 1, Integer::sum);
        }

        public int getUpdateLastUsedCount(String credentialId) {
            return updateLastUsedCalls.getOrDefault(credentialId, 0);
        }
    }

    private static class MockWebAuthnManager extends WebAuthnManager {
        private WebAuthnManager.AuthenticationResult nextResult;

        public MockWebAuthnManager(RelyingPartyConfig relyingPartyConfig) {
            super(relyingPartyConfig);
        }

        public void setNextAuthenticationResult(WebAuthnManager.AuthenticationResult result) {
            this.nextResult = result;
        }

        @Override
        public WebAuthnManager.AuthenticationResult verifyAuthenticationResponse(
            String clientDataJSON,
            String authenticatorData,
            String signature,
            byte[] challenge,
            String origin,
            byte[] credentialId,
            byte[] publicKey,
            long currentSignatureCounter
        ) {
            return nextResult != null ? nextResult : AuthenticationResult.success(currentSignatureCounter + 1);
        }
    }
}
