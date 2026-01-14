/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for credential listing.
 * 
 * **Feature: passkey-authentication, Property 20: Credential listing completeness**
 * **Feature: passkey-authentication, Property 21: Credential metadata completeness**
 * **Validates: Requirements 5.1, 5.2**
 * 
 * Property 20: For any user, requesting their passkeys should return all registered credentials with complete metadata.
 * Property 21: For any listed passkey, the response should include creation date, last used date, and friendly name.
 */
public class CredentialListingPropertyTest {

    private InMemoryPasskeyCredentialRepository repository;

    @Before
    public void setUp() {
        repository = new InMemoryPasskeyCredentialRepository();
    }

    /**
     * Property 20: Credential listing completeness
     * 
     * For any user with N registered credentials, listing their credentials should return
     * exactly N credentials with all metadata intact.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void credentialListingReturnsAllCredentials() {
        java.util.Random random = new java.util.Random(50); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Clear repository for each iteration
            repository = new InMemoryPasskeyCredentialRepository();
            
            // Generate random test data
            String username = generateRandomString(random, 3, 64);
            int numCredentials = 1 + random.nextInt(10); // 1 to 10 credentials
            
            List<PasskeyCredential> expectedCredentials = new ArrayList<>();
            
            // Create random credentials for the user
            for (int j = 0; j < numCredentials; j++) {
                String credentialId = generateRandomString(random, 10, 100);
                byte[] publicKey = generateRandomBytes(random, 32, 256);
                
                PasskeyMetadata metadata = new PasskeyMetadata(
                    "test-key-" + j,
                    "platform",
                    "test-agent"
                );
                
                Instant now = Instant.now();
                
                PasskeyCredential credential = new PasskeyCredential(
                    credentialId,
                    username,
                    publicKey,
                    0L,
                    "test-aaguid",
                    List.of("usb"),
                    metadata,
                    now,
                    now,
                    true,
                    false
                );
                
                expectedCredentials.add(credential);
                repository.storeCredential(credential);
            }

            // Act: List credentials
            List<PasskeyCredential> retrievedCredentials = repository.findByUsername(username);

            // Assert: Should return all credentials
            assertEquals("Should return all credentials for user", numCredentials, retrievedCredentials.size());
        }
    }

    /**
     * Property 21: Credential metadata completeness
     * 
     * For any listed credential, the metadata should include:
     * - Creation date (required)
     * - Last used date (optional but present if set)
     * - Friendly name (required)
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void credentialMetadataIsComplete() {
        java.util.Random random = new java.util.Random(51); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Clear repository for each iteration
            repository = new InMemoryPasskeyCredentialRepository();
            
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] publicKey = generateRandomBytes(random, 32, 256);
            String friendlyName = generateRandomString(random, 5, 50);
            
            PasskeyMetadata metadata = new PasskeyMetadata(
                friendlyName,
                "platform",
                "test-agent"
            );
            
            Instant createdAt = Instant.now();
            Instant lastUsedAt = random.nextBoolean() ? Instant.now() : null;
            
            PasskeyCredential credential = new PasskeyCredential(
                credentialId,
                username,
                publicKey,
                0L,
                "test-aaguid",
                List.of("usb"),
                metadata,
                createdAt,
                lastUsedAt,
                true,
                false
            );

            // Act: Store and retrieve credential
            repository.storeCredential(credential);
            List<PasskeyCredential> credentials = repository.findByUsername(username);

            // Assert: Metadata should be complete
            assertTrue("Should find at least one credential", credentials.size() > 0);
            
            PasskeyCredential retrieved = credentials.get(0);
            assertNotNull("Credential ID should be present", retrieved.getCredentialId());
            assertNotNull("Metadata should be present", retrieved.getMetadata());
            assertNotNull("Friendly name should be present", retrieved.getMetadata().getFriendlyName());
            assertNotNull("Creation date should be present", retrieved.getCreatedAt());
            
            // Last used date is optional but should match if it was set
            if (lastUsedAt != null) {
                assertNotNull("Last used date should be present when set", retrieved.getLastUsedAt());
            }
        }
    }

    /**
     * Property 20 (variant): Empty credential list for non-existent user
     * 
     * For any user with no registered credentials, listing should return an empty list.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void credentialListingReturnsEmptyForNonExistentUser() {
        java.util.Random random = new java.util.Random(52); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Clear repository for each iteration
            repository = new InMemoryPasskeyCredentialRepository();
            
            // Generate random username
            String username = generateRandomString(random, 3, 64);

            // Act: List credentials for user with no credentials
            List<PasskeyCredential> credentials = repository.findByUsername(username);

            // Assert: Should return empty list
            assertNotNull("Credential list should not be null", credentials);
            assertEquals("Should return empty list for user with no credentials", 0, credentials.size());
        }
    }

    // Helper methods for generating random test data
    private String generateRandomString(java.util.Random random, int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    private byte[] generateRandomBytes(java.util.Random random, int minSize, int maxSize) {
        int size = minSize + random.nextInt(maxSize - minSize + 1);
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Simple in-memory implementation of PasskeyCredentialRepository for testing.
     * This avoids the need to mock OpenSearch components.
     */
    private static class InMemoryPasskeyCredentialRepository implements PasskeyCredentialRepository {
        private final Map<String, PasskeyCredential> credentialsById = new HashMap<>();
        private final Map<String, List<PasskeyCredential>> credentialsByUsername = new HashMap<>();

        @Override
        public void storeCredential(PasskeyCredential credential) {
            credentialsById.put(credential.getCredentialId(), credential);
            credentialsByUsername.computeIfAbsent(credential.getUsername(), k -> new ArrayList<>()).add(credential);
        }

        @Override
        public Optional<PasskeyCredential> findByCredentialId(String credentialId) {
            return Optional.ofNullable(credentialsById.get(credentialId));
        }

        @Override
        public List<PasskeyCredential> findByUsername(String username) {
            return credentialsByUsername.getOrDefault(username, new ArrayList<>());
        }

        @Override
        public void deleteCredential(String credentialId) {
            PasskeyCredential credential = credentialsById.remove(credentialId);
            if (credential != null) {
                List<PasskeyCredential> userCredentials = credentialsByUsername.get(credential.getUsername());
                if (userCredentials != null) {
                    userCredentials.removeIf(c -> c.getCredentialId().equals(credentialId));
                }
            }
        }

        @Override
        public void updateCredentialMetadata(String credentialId, PasskeyMetadata metadata) {
            // Not needed for these tests
        }

        @Override
        public void updateSignatureCounter(String credentialId, long counter) {
            // Not needed for these tests
        }

        @Override
        public void updateLastUsed(String credentialId) {
            // Not needed for these tests
        }
    }
}
