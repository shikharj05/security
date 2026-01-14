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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for multi-credential authentication.
 * 
 * **Feature: passkey-authentication, Property 24: Multi-credential authentication**
 * **Validates: Requirements 5.5**
 * 
 * For any user with multiple registered passkeys, authentication should succeed 
 * with any of the registered passkeys.
 */
public class MultiCredentialAuthenticationPropertyTest {

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
     * Property 24: Multi-credential authentication
     * 
     * For any user with multiple registered passkeys, authentication should succeed
     * with any of the registered passkeys.
     * 
     * This test runs 100 iterations where each user has a random number of credentials
     * (1 to 5), and verifies that authentication succeeds with each credential.
     */
    @Test
    public void multiCredentialAuthentication() {
        for (int i = 0; i < 100; i++) {
            String username = "user_" + i;
            
            // Create a random number of credentials for this user (1 to 5)
            int numCredentials = (i % 5) + 1;
            List<String> credentialIds = new ArrayList<>();
            
            for (int j = 0; j < numCredentials; j++) {
                String credentialId = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("cred_" + i + "_" + j).getBytes());
                credentialIds.add(credentialId);
                
                // Create and store credential
                PasskeyCredential credential = createCredential(username, credentialId);
                credentialRepository.storeCredential(credential);
            }
            
            // Verify that the user has the expected number of credentials
            List<PasskeyCredential> userCredentials = credentialRepository.findByUsername(username);
            assertEquals(
                "User should have " + numCredentials + " credentials (iteration " + i + ")",
                numCredentials,
                userCredentials.size()
            );
            
            // Try authenticating with each credential
            for (int j = 0; j < numCredentials; j++) {
                String credentialId = credentialIds.get(j);
                
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
                    WebAuthnManager.AuthenticationResult.success(1L)
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
                
                // Assert: Authentication should succeed
                assertNotNull(
                    "Authentication should succeed with credential " + j + " (iteration " + i + ")",
                    user
                );
                
                // Assert: User should have the correct username
                assertEquals(
                    "User should have correct username (iteration " + i + ", credential " + j + ")",
                    username,
                    user.getName()
                );
            }
        }
    }

    /**
     * Property 24: Authentication with any credential returns same user
     * 
     * For any user with multiple credentials, authenticating with different
     * credentials should return a User object with the same username.
     */
    @Test
    public void authenticationWithAnyCredentialReturnsSameUser() {
        for (int i = 0; i < 100; i++) {
            String username = "consistent_user_" + i;
            
            // Create 3 credentials for this user
            List<String> credentialIds = new ArrayList<>();
            for (int j = 0; j < 3; j++) {
                String credentialId = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("consistent_cred_" + i + "_" + j).getBytes());
                credentialIds.add(credentialId);
                
                PasskeyCredential credential = createCredential(username, credentialId);
                credentialRepository.storeCredential(credential);
            }
            
            // Authenticate with each credential and collect usernames
            List<String> authenticatedUsernames = new ArrayList<>();
            
            for (String credentialId : credentialIds) {
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
                    WebAuthnManager.AuthenticationResult.success(1L)
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
                
                authenticatedUsernames.add(user.getName());
            }
            
            // Assert: All authentications should return the same username
            for (String authenticatedUsername : authenticatedUsernames) {
                assertEquals(
                    "All credentials should authenticate to the same username (iteration " + i + ")",
                    username,
                    authenticatedUsername
                );
            }
            
            // Assert: We should have 3 successful authentications
            assertEquals(
                "Should have 3 successful authentications (iteration " + i + ")",
                3,
                authenticatedUsernames.size()
            );
        }
    }

    /**
     * Property 24: Each credential is independent
     * 
     * For any user with multiple credentials, using one credential should not
     * affect the ability to use other credentials.
     */
    @Test
    public void credentialsAreIndependent() {
        String username = "independent_user";
        
        // Create 5 credentials
        List<String> credentialIds = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            String credentialId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("independent_cred_" + i).getBytes());
            credentialIds.add(credentialId);
            
            PasskeyCredential credential = createCredential(username, credentialId);
            credentialRepository.storeCredential(credential);
        }
        
        // Use each credential multiple times in random order
        for (int iteration = 0; iteration < 100; iteration++) {
            // Pick a random credential
            int credIndex = iteration % 5;
            String credentialId = credentialIds.get(credIndex);
            
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
                WebAuthnManager.AuthenticationResult.success(iteration + 1L)
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
            
            // Assert: Authentication should always succeed
            assertNotNull(
                "Authentication should succeed with credential " + credIndex + " (iteration " + iteration + ")",
                user
            );
            assertEquals(
                "User should have correct username (iteration " + iteration + ")",
                username,
                user.getName()
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

        @Override
        public void storeCredential(PasskeyCredential credential) {
            credentials.add(credential);
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
