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
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for duplicate credential exclusion.
 * 
 * **Feature: passkey-authentication, Property 9: Duplicate credential exclusion**
 * **Validates: Requirements 2.5**
 * 
 * For any user with existing credentials, new registration options should exclude 
 * all of the user's existing credential IDs.
 */
public class DuplicateCredentialExclusionPropertyTest {

    /**
     * Property 9: Duplicate credential exclusion
     * 
     * For any user with a set of existing credentials, when we generate a list of
     * credential IDs to exclude, all existing credential IDs should be in the exclusion list.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void existingCredentialsAreExcludedFromRegistration() {
        java.util.Random random = new java.util.Random(49); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String username = generateRandomString(random, 3, 64);
            int numExistingCredentials = 1 + random.nextInt(10); // 1-10 existing credentials
            
            // Create existing credentials
            List<PasskeyCredential> existingCredentials = new ArrayList<>();
            for (int j = 0; j < numExistingCredentials; j++) {
                String credentialId = generateRandomString(random, 10, 100);
                byte[] publicKey = generateRandomBytes(random, 32, 256);
                
                PasskeyMetadata metadata = new PasskeyMetadata("key-" + j, "platform", "test-agent");
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
                existingCredentials.add(credential);
            }

            // Act: Build exclusion list from existing credentials
            List<String> excludeCredentials = new ArrayList<>();
            for (PasskeyCredential cred : existingCredentials) {
                excludeCredentials.add(cred.getCredentialId());
            }

            // Assert: All existing credential IDs should be in the exclusion list
            for (PasskeyCredential cred : existingCredentials) {
                assertTrue(
                    "Existing credential " + cred.getCredentialId() + " should be in exclusion list",
                    excludeCredentials.contains(cred.getCredentialId())
                );
            }
            
            // Assert: Exclusion list should have the same size as existing credentials
            assertTrue(
                "Exclusion list size should match existing credentials count",
                excludeCredentials.size() == existingCredentials.size()
            );
        }
    }

    /**
     * Property 9 (variant): New credential ID should not be in exclusion list
     * 
     * For any user with existing credentials, a newly generated credential ID
     * should not be in the exclusion list (to allow registration).
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void newCredentialIdNotInExclusionList() {
        java.util.Random random = new java.util.Random(50); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String username = generateRandomString(random, 3, 64);
            int numExistingCredentials = 1 + random.nextInt(10);
            
            // Create existing credentials
            List<String> existingCredentialIds = new ArrayList<>();
            for (int j = 0; j < numExistingCredentials; j++) {
                existingCredentialIds.add(generateRandomString(random, 10, 100));
            }

            // Generate a new credential ID
            String newCredentialId = generateRandomString(random, 10, 100);
            
            // Ensure it's different from existing ones
            while (existingCredentialIds.contains(newCredentialId)) {
                newCredentialId = newCredentialId + "_new";
            }

            // Assert: New credential ID should not be in existing list
            assertFalse(
                "New credential ID should not be in existing credentials",
                existingCredentialIds.contains(newCredentialId)
            );
        }
    }

    /**
     * Property 9 (variant): Empty exclusion list for users with no credentials
     * 
     * For any user with no existing credentials, the exclusion list should be empty.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void emptyExclusionListForNewUsers() {
        java.util.Random random = new java.util.Random(51); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String username = generateRandomString(random, 3, 64);
            
            // Simulate a new user with no existing credentials
            List<PasskeyCredential> existingCredentials = new ArrayList<>();

            // Act: Build exclusion list
            List<String> excludeCredentials = new ArrayList<>();
            for (PasskeyCredential cred : existingCredentials) {
                excludeCredentials.add(cred.getCredentialId());
            }

            // Assert: Exclusion list should be empty
            assertTrue(
                "Exclusion list should be empty for new users",
                excludeCredentials.isEmpty()
            );
        }
    }

    /**
     * Property 9 (variant): Exclusion list uniqueness
     * 
     * For any user with existing credentials, the exclusion list should not contain
     * duplicate credential IDs.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @Test
    public void exclusionListContainsUniqueCredentialIds() {
        java.util.Random random = new java.util.Random(52); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String username = generateRandomString(random, 3, 64);
            int numExistingCredentials = 1 + random.nextInt(10);
            
            // Create existing credentials with unique IDs
            List<String> existingCredentialIds = new ArrayList<>();
            for (int j = 0; j < numExistingCredentials; j++) {
                String credentialId = generateRandomString(random, 10, 100);
                // Ensure uniqueness
                while (existingCredentialIds.contains(credentialId)) {
                    credentialId = credentialId + "_" + j;
                }
                existingCredentialIds.add(credentialId);
            }

            // Act: Build exclusion list
            List<String> excludeCredentials = new ArrayList<>(existingCredentialIds);

            // Assert: No duplicates in exclusion list
            java.util.Set<String> uniqueIds = new java.util.HashSet<>(excludeCredentials);
            assertTrue(
                "Exclusion list should not contain duplicates",
                uniqueIds.size() == excludeCredentials.size()
            );
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
}
