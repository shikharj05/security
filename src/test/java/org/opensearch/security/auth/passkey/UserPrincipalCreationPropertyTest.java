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

import com.google.common.collect.ImmutableSet;
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
 * Property-based tests for user principal creation.
 * 
 * **Feature: passkey-authentication, Property 14: User principal creation**
 * **Feature: passkey-authentication, Property 29: User principal creation with username**
 * **Validates: Requirements 3.5, 7.1**
 * 
 * For any successful passkey authentication, a User Principal should be created 
 * with the authenticated username and appropriate roles.
 */
public class UserPrincipalCreationPropertyTest {

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
            null, // authenticatorAttachment can be null
            com.webauthn4j.data.ResidentKeyRequirement.PREFERRED,
            List.of() // empty list for pubKeyCredParams
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
     * Property 14 & 29: User principal creation with username
     * 
     * For any successful authentication, the created User Principal should have 
     * the authenticated username.
     * 
     * This test runs 100 iterations with random usernames to verify that the
     * User object returned from authenticate() always contains the correct username.
     */
    @Test
    public void userPrincipalCreationWithUsername() {
        for (int i = 0; i < 100; i++) {
            // Generate random username
            String username = "user_" + UUID.randomUUID().toString().substring(0, 8);
            String credentialId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(UUID.randomUUID().toString().getBytes());
            
            // Create and store a credential for this user
            PasskeyCredential credential = createCredential(username, credentialId);
            credentialRepository.storeCredential(credential);
            
            // Create a challenge
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
            
            // Configure mock to return successful authentication
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
            
            // Assert: User should not be null
            assertNotNull("User should not be null (iteration " + i + ")", user);
            
            // Assert: User should have the correct username
            assertEquals(
                "User principal should have the authenticated username (iteration " + i + ")",
                username,
                user.getName()
            );
            
            // Assert: User should not be injected
            assertTrue(
                "User should not be marked as injected (iteration " + i + ")",
                !user.isInjected()
            );
        }
    }

    /**
     * Property 14: User principal creation
     * 
     * For any successful authentication, the User Principal should be created
     * and not be null.
     */
    @Test
    public void userPrincipalCreation() {
        for (int i = 0; i < 100; i++) {
            String username = "user_" + i;
            String credentialId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("cred_" + i).getBytes());
            
            // Create credential
            PasskeyCredential credential = createCredential(username, credentialId);
            credentialRepository.storeCredential(credential);
            
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
            
            // Assert: User should not be null
            assertNotNull("User should not be null (iteration " + i + ")", user);
            assertEquals("User should have correct username (iteration " + i + ")", username, user.getName());
            assertTrue("User should not be injected (iteration " + i + ")", !user.isInjected());
        }
    }

    // Helper methods

    private PasskeyCredential createCredential(String username, String credentialId) {
        byte[] publicKey = new byte[65]; // Dummy public key
        return new PasskeyCredential(
            credentialId,
            username,
            publicKey,
            0L, // signature counter
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
            // Not needed for this test
        }

        @Override
        public void updateSignatureCounter(String credentialId, long counter) {
            // Update in-memory
            findByCredentialId(credentialId).ifPresent(cred -> {
                // Would update counter here
            });
        }

        @Override
        public void updateLastUsed(String credentialId) {
            // Not needed for this test
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
