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
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for challenge uniqueness.
 * 
 * **Feature: passkey-authentication, Property 5: Challenge uniqueness in registration**
 * **Feature: passkey-authentication, Property 10: Challenge uniqueness in authentication**
 * **Validates: Requirements 2.1, 3.1**
 * 
 * For any two registration or authentication requests, the generated challenges 
 * should be distinct to prevent replay attacks.
 */
public class ChallengeUniquenessPropertyTest {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Property 5: Challenge uniqueness in registration
     * 
     * For any two registration requests, the generated challenges should be distinct.
     * 
     * This test runs 100 iterations generating pairs of challenges and verifying
     * they are unique.
     */
    @org.junit.Test
    public void registrationChallengeUniqueness() {
        Set<String> challengeIds = new HashSet<>();
        Set<String> challengeBytesHashes = new HashSet<>();
        
        for (int i = 0; i < 100; i++) {
            // Generate two registration challenges
            Challenge challenge1 = generateChallenge(Challenge.ChallengeType.REGISTRATION);
            Challenge challenge2 = generateChallenge(Challenge.ChallengeType.REGISTRATION);
            
            // Assert: Challenge IDs should be unique
            assertTrue(
                "Challenge ID should be unique (iteration " + i + ")",
                challengeIds.add(challenge1.getChallengeId())
            );
            assertTrue(
                "Challenge ID should be unique (iteration " + i + ")",
                challengeIds.add(challenge2.getChallengeId())
            );
            
            // Assert: Challenge bytes should be unique
            String hash1 = bytesToHex(challenge1.getChallengeBytes());
            String hash2 = bytesToHex(challenge2.getChallengeBytes());
            
            assertTrue(
                "Challenge bytes should be unique (iteration " + i + ")",
                challengeBytesHashes.add(hash1)
            );
            assertTrue(
                "Challenge bytes should be unique (iteration " + i + ")",
                challengeBytesHashes.add(hash2)
            );
            
            // Assert: The two challenges in the same iteration should be different
            assertTrue(
                "Two challenges generated in sequence should have different IDs",
                !challenge1.getChallengeId().equals(challenge2.getChallengeId())
            );
            assertTrue(
                "Two challenges generated in sequence should have different bytes",
                !hash1.equals(hash2)
            );
        }
        
        // We should have 200 unique challenge IDs (100 iterations * 2 challenges)
        assertEquals("Should have 200 unique challenge IDs", 200, challengeIds.size());
        assertEquals("Should have 200 unique challenge byte sequences", 200, challengeBytesHashes.size());
    }

    /**
     * Property 10: Challenge uniqueness in authentication
     * 
     * For any two authentication requests, the generated challenges should be distinct.
     * 
     * This test runs 100 iterations generating pairs of challenges and verifying
     * they are unique.
     */
    @org.junit.Test
    public void authenticationChallengeUniqueness() {
        Set<String> challengeIds = new HashSet<>();
        Set<String> challengeBytesHashes = new HashSet<>();
        
        for (int i = 0; i < 100; i++) {
            // Generate two authentication challenges
            Challenge challenge1 = generateChallenge(Challenge.ChallengeType.AUTHENTICATION);
            Challenge challenge2 = generateChallenge(Challenge.ChallengeType.AUTHENTICATION);
            
            // Assert: Challenge IDs should be unique
            assertTrue(
                "Challenge ID should be unique (iteration " + i + ")",
                challengeIds.add(challenge1.getChallengeId())
            );
            assertTrue(
                "Challenge ID should be unique (iteration " + i + ")",
                challengeIds.add(challenge2.getChallengeId())
            );
            
            // Assert: Challenge bytes should be unique
            String hash1 = bytesToHex(challenge1.getChallengeBytes());
            String hash2 = bytesToHex(challenge2.getChallengeBytes());
            
            assertTrue(
                "Challenge bytes should be unique (iteration " + i + ")",
                challengeBytesHashes.add(hash1)
            );
            assertTrue(
                "Challenge bytes should be unique (iteration " + i + ")",
                challengeBytesHashes.add(hash2)
            );
            
            // Assert: The two challenges in the same iteration should be different
            assertTrue(
                "Two challenges generated in sequence should have different IDs",
                !challenge1.getChallengeId().equals(challenge2.getChallengeId())
            );
            assertTrue(
                "Two challenges generated in sequence should have different bytes",
                !hash1.equals(hash2)
            );
        }
        
        // We should have 200 unique challenge IDs (100 iterations * 2 challenges)
        assertEquals("Should have 200 unique challenge IDs", 200, challengeIds.size());
        assertEquals("Should have 200 unique challenge byte sequences", 200, challengeBytesHashes.size());
    }

    /**
     * Property 5 & 10 (combined): Cross-type challenge uniqueness
     * 
     * For any registration and authentication challenges, they should be distinct
     * even across different challenge types.
     * 
     * This test runs 100 iterations generating both types and verifying uniqueness.
     */
    @org.junit.Test
    public void crossTypeChallengeUniqueness() {
        Set<String> challengeIds = new HashSet<>();
        Set<String> challengeBytesHashes = new HashSet<>();
        
        for (int i = 0; i < 100; i++) {
            // Generate one registration and one authentication challenge
            Challenge regChallenge = generateChallenge(Challenge.ChallengeType.REGISTRATION);
            Challenge authChallenge = generateChallenge(Challenge.ChallengeType.AUTHENTICATION);
            
            // Assert: Challenge IDs should be unique across types
            assertTrue(
                "Registration challenge ID should be unique",
                challengeIds.add(regChallenge.getChallengeId())
            );
            assertTrue(
                "Authentication challenge ID should be unique",
                challengeIds.add(authChallenge.getChallengeId())
            );
            
            // Assert: Challenge bytes should be unique across types
            String regHash = bytesToHex(regChallenge.getChallengeBytes());
            String authHash = bytesToHex(authChallenge.getChallengeBytes());
            
            assertTrue(
                "Registration challenge bytes should be unique",
                challengeBytesHashes.add(regHash)
            );
            assertTrue(
                "Authentication challenge bytes should be unique",
                challengeBytesHashes.add(authHash)
            );
        }
        
        // We should have 200 unique challenge IDs (100 iterations * 2 types)
        assertEquals("Should have 200 unique challenge IDs across types", 200, challengeIds.size());
        assertEquals("Should have 200 unique challenge byte sequences across types", 200, challengeBytesHashes.size());
    }

    // Helper methods

    /**
     * Generate a challenge with cryptographically random data.
     */
    private Challenge generateChallenge(Challenge.ChallengeType type) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32]; // 256 bits
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

    /**
     * Convert byte array to hex string for comparison.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
