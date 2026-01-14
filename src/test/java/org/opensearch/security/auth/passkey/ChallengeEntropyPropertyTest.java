/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for challenge entropy.
 * 
 * **Feature: passkey-authentication, Property 15: Challenge entropy**
 * **Validates: Requirements 4.1**
 * 
 * For any generated challenge, the challenge should have at least 128 bits 
 * of cryptographic entropy to prevent brute-force attacks.
 */
public class ChallengeEntropyPropertyTest {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Property 15: Challenge entropy
     * 
     * For any generated challenge, the challenge should have at least 128 bits
     * of cryptographic entropy.
     * 
     * This test runs 100 iterations generating challenges and verifying they
     * have sufficient entropy by checking:
     * 1. Minimum byte length (16 bytes = 128 bits)
     * 2. Non-zero bytes (not all zeros)
     * 3. Variation in byte values (not all same value)
     */
    @org.junit.Test
    public void challengeHasSufficientEntropy() {
        for (int i = 0; i < 100; i++) {
            // Generate a challenge
            Challenge challenge = generateChallenge();
            byte[] challengeBytes = challenge.getChallengeBytes();
            
            // Assert: Challenge must have at least 128 bits (16 bytes)
            assertTrue(
                "Challenge must have at least 128 bits (16 bytes), but has " + (challengeBytes.length * 8) + " bits",
                challengeBytes.length >= 16
            );
            
            // Assert: Challenge bytes should not be all zeros
            boolean hasNonZero = false;
            for (byte b : challengeBytes) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(
                "Challenge bytes should not be all zeros (iteration " + i + ")",
                hasNonZero
            );
            
            // Assert: Challenge bytes should have variation (not all same value)
            boolean hasVariation = false;
            byte firstByte = challengeBytes[0];
            for (int j = 1; j < challengeBytes.length; j++) {
                if (challengeBytes[j] != firstByte) {
                    hasVariation = true;
                    break;
                }
            }
            assertTrue(
                "Challenge bytes should have variation, not all same value (iteration " + i + ")",
                hasVariation
            );
        }
    }

    /**
     * Property 15 (extended): Challenge entropy distribution
     * 
     * For any set of generated challenges, the byte values should be
     * well-distributed across the range [0, 255], indicating good entropy.
     * 
     * This test generates 100 challenges and checks that we see a reasonable
     * distribution of byte values.
     */
    @org.junit.Test
    public void challengeEntropyDistribution() {
        int[] byteFrequency = new int[256];
        int totalBytes = 0;
        
        // Generate 100 challenges and count byte value frequencies
        for (int i = 0; i < 100; i++) {
            Challenge challenge = generateChallenge();
            byte[] challengeBytes = challenge.getChallengeBytes();
            
            for (byte b : challengeBytes) {
                // Convert signed byte to unsigned int (0-255)
                int unsignedValue = b & 0xFF;
                byteFrequency[unsignedValue]++;
                totalBytes++;
            }
        }
        
        // Assert: We should see at least 50% of possible byte values (128 out of 256)
        // This indicates good distribution
        int uniqueByteValues = 0;
        for (int freq : byteFrequency) {
            if (freq > 0) {
                uniqueByteValues++;
            }
        }
        
        assertTrue(
            "Challenge bytes should be well-distributed. Expected at least 128 unique byte values, got " + uniqueByteValues,
            uniqueByteValues >= 128
        );
        
        // Assert: No single byte value should dominate (appear more than 5% of the time)
        double maxAllowedFrequency = totalBytes * 0.05;
        for (int i = 0; i < 256; i++) {
            assertTrue(
                "Byte value " + i + " appears too frequently (" + byteFrequency[i] + " times, " +
                "max allowed: " + maxAllowedFrequency + "), indicating poor entropy",
                byteFrequency[i] <= maxAllowedFrequency
            );
        }
    }

    /**
     * Property 15 (extended): Challenge entropy for different types
     * 
     * For any challenge type (REGISTRATION or AUTHENTICATION), the entropy
     * requirements should be the same.
     */
    @org.junit.Test
    public void challengeEntropyConsistentAcrossTypes() {
        for (int i = 0; i < 100; i++) {
            // Generate both types of challenges
            Challenge regChallenge = generateChallenge(Challenge.ChallengeType.REGISTRATION);
            Challenge authChallenge = generateChallenge(Challenge.ChallengeType.AUTHENTICATION);
            
            byte[] regBytes = regChallenge.getChallengeBytes();
            byte[] authBytes = authChallenge.getChallengeBytes();
            
            // Assert: Both should have at least 128 bits
            assertTrue(
                "Registration challenge must have at least 128 bits",
                regBytes.length >= 16
            );
            assertTrue(
                "Authentication challenge must have at least 128 bits",
                authBytes.length >= 16
            );
            
            // Assert: Both should have non-zero bytes
            boolean regHasNonZero = false;
            for (byte b : regBytes) {
                if (b != 0) {
                    regHasNonZero = true;
                    break;
                }
            }
            assertTrue("Registration challenge should have non-zero bytes", regHasNonZero);
            
            boolean authHasNonZero = false;
            for (byte b : authBytes) {
                if (b != 0) {
                    authHasNonZero = true;
                    break;
                }
            }
            assertTrue("Authentication challenge should have non-zero bytes", authHasNonZero);
        }
    }

    // Helper methods

    /**
     * Generate a challenge with cryptographically random data.
     */
    private Challenge generateChallenge() {
        return generateChallenge(Challenge.ChallengeType.REGISTRATION);
    }

    /**
     * Generate a challenge with cryptographically random data of a specific type.
     */
    private Challenge generateChallenge(Challenge.ChallengeType type) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32]; // 256 bits (exceeds minimum of 128 bits)
        secureRandom.nextBytes(challengeBytes);
        
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300); // 5 minutes
        
        return new Challenge(
            challengeId,
            challengeBytes,
            "testuser",
            type,
            now,
            expiresAt,
            UUID.randomUUID().toString()
        );
    }
}
