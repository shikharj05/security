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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for challenge cleanup.
 * 
 * **Feature: passkey-authentication, Property 19: Challenge cleanup**
 * **Validates: Requirements 4.5**
 * 
 * For any challenge that is used or expired, the challenge should be removed 
 * from the valid challenge store to prevent memory leaks and maintain security.
 */
public class ChallengeCleanupPropertyTest {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Property 19: Challenge cleanup
     * 
     * For any challenge that is used or expired, the challenge should be removed
     * from the valid challenge store.
     * 
     * This test runs 100 iterations storing expired challenges and verifying
     * that cleanup removes them from the store.
     */
    @org.junit.Test
    public void expiredChallengesAreCleanedUp() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store a mix of expired and valid challenges
            List<Challenge> expiredChallenges = new ArrayList<>();
            List<Challenge> validChallenges = new ArrayList<>();
            
            // Create 5 expired challenges
            for (int j = 0; j < 5; j++) {
                Challenge expired = generateExpiredChallenge();
                expiredChallenges.add(expired);
                store.storeChallenge(expired.getChallengeId(), expired);
            }
            
            // Create 5 valid challenges
            for (int j = 0; j < 5; j++) {
                Challenge valid = generateValidChallenge();
                validChallenges.add(valid);
                store.storeChallenge(valid.getChallengeId(), valid);
            }
            
            // Assert: Store should have 10 challenges before cleanup
            assertEquals("Store should have 10 challenges before cleanup", 10, store.size());
            
            // Perform cleanup
            store.cleanupExpiredChallenges();
            
            // Assert: Store should have only 5 challenges after cleanup (valid ones)
            assertEquals(
                "Store should have 5 challenges after cleanup (iteration " + i + ")",
                5,
                store.size()
            );
            
            // Clear for next iteration
            store.clear();
        }
    }

    /**
     * Property 19 (extended): Challenge cleanup with consumed challenges
     * 
     * For any challenge that is consumed, it should be automatically removed
     * from the store (no explicit cleanup needed).
     */
    @org.junit.Test
    public void consumedChallengesAreAutomaticallyRemoved() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store 10 valid challenges
            List<Challenge> challenges = new ArrayList<>();
            for (int j = 0; j < 10; j++) {
                Challenge challenge = generateValidChallenge();
                challenges.add(challenge);
                store.storeChallenge(challenge.getChallengeId(), challenge);
            }
            
            // Assert: Store should have 10 challenges
            assertEquals("Store should have 10 challenges", 10, store.size());
            
            // Consume 5 challenges
            for (int j = 0; j < 5; j++) {
                store.consumeChallenge(challenges.get(j).getChallengeId());
            }
            
            // Assert: Store should have 5 challenges (consumed ones removed)
            assertEquals(
                "Store should have 5 challenges after consuming 5 (iteration " + i + ")",
                5,
                store.size()
            );
            
            // Clear for next iteration
            store.clear();
        }
    }

    /**
     * Property 19 (extended): Challenge cleanup preserves valid challenges
     * 
     * For any set of challenges, cleanup should only remove expired ones
     * and preserve all valid challenges.
     */
    @org.junit.Test
    public void cleanupPreservesValidChallenges() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store challenges with various expiration times
            List<Challenge> validChallenges = new ArrayList<>();
            
            // Add 3 expired challenges
            for (int j = 0; j < 3; j++) {
                Challenge expired = generateExpiredChallenge();
                store.storeChallenge(expired.getChallengeId(), expired);
            }
            
            // Add 7 valid challenges with different expiration times
            for (int j = 0; j < 7; j++) {
                Challenge valid = generateChallengeWithTimeout(60 + (j * 60)); // 1-7 minutes
                validChallenges.add(valid);
                store.storeChallenge(valid.getChallengeId(), valid);
            }
            
            // Perform cleanup
            store.cleanupExpiredChallenges();
            
            // Assert: All valid challenges should still be consumable
            for (Challenge valid : validChallenges) {
                assertTrue(
                    "Valid challenge should still be consumable after cleanup (iteration " + i + ")",
                    store.consumeChallenge(valid.getChallengeId()).isPresent()
                );
            }
            
            // Assert: Store should now be empty (all valid ones consumed)
            assertEquals("Store should be empty after consuming all valid challenges", 0, store.size());
        }
    }

    /**
     * Property 19 (extended): Challenge cleanup with large numbers
     * 
     * For any large number of expired challenges, cleanup should efficiently
     * remove all of them.
     */
    @org.junit.Test
    public void cleanupHandlesLargeNumbersOfExpiredChallenges() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 10; i++) { // Reduced iterations for performance
            // Store 100 expired challenges
            for (int j = 0; j < 100; j++) {
                Challenge expired = generateExpiredChallenge();
                store.storeChallenge(expired.getChallengeId(), expired);
            }
            
            // Store 10 valid challenges
            for (int j = 0; j < 10; j++) {
                Challenge valid = generateValidChallenge();
                store.storeChallenge(valid.getChallengeId(), valid);
            }
            
            // Assert: Store should have 110 challenges
            assertEquals("Store should have 110 challenges", 110, store.size());
            
            // Perform cleanup
            store.cleanupExpiredChallenges();
            
            // Assert: Store should have only 10 challenges (valid ones)
            assertEquals(
                "Store should have 10 challenges after cleanup (iteration " + i + ")",
                10,
                store.size()
            );
            
            // Clear for next iteration
            store.clear();
        }
    }

    /**
     * Property 19 (extended): Challenge cleanup is idempotent
     * 
     * For any store state, running cleanup multiple times should have the
     * same effect as running it once.
     */
    @org.junit.Test
    public void cleanupIsIdempotent() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store a mix of expired and valid challenges
            for (int j = 0; j < 5; j++) {
                Challenge expired = generateExpiredChallenge();
                store.storeChallenge(expired.getChallengeId(), expired);
            }
            
            for (int j = 0; j < 5; j++) {
                Challenge valid = generateValidChallenge();
                store.storeChallenge(valid.getChallengeId(), valid);
            }
            
            // Perform cleanup multiple times
            store.cleanupExpiredChallenges();
            int sizeAfterFirstCleanup = store.size();
            
            store.cleanupExpiredChallenges();
            int sizeAfterSecondCleanup = store.size();
            
            store.cleanupExpiredChallenges();
            int sizeAfterThirdCleanup = store.size();
            
            // Assert: Size should be the same after each cleanup
            assertEquals(
                "Store size should be same after multiple cleanups (iteration " + i + ")",
                sizeAfterFirstCleanup,
                sizeAfterSecondCleanup
            );
            assertEquals(
                "Store size should be same after multiple cleanups (iteration " + i + ")",
                sizeAfterSecondCleanup,
                sizeAfterThirdCleanup
            );
            
            // Assert: Should have 5 valid challenges
            assertEquals("Store should have 5 valid challenges", 5, sizeAfterThirdCleanup);
            
            // Clear for next iteration
            store.clear();
        }
    }

    /**
     * Property 19 (extended): Challenge cleanup across types
     * 
     * For any challenge type (REGISTRATION or AUTHENTICATION), cleanup should
     * work consistently.
     */
    @org.junit.Test
    public void cleanupWorksAcrossTypes() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store expired challenges of both types
            for (int j = 0; j < 3; j++) {
                Challenge expiredReg = generateExpiredChallenge(Challenge.ChallengeType.REGISTRATION);
                store.storeChallenge(expiredReg.getChallengeId(), expiredReg);
                
                Challenge expiredAuth = generateExpiredChallenge(Challenge.ChallengeType.AUTHENTICATION);
                store.storeChallenge(expiredAuth.getChallengeId(), expiredAuth);
            }
            
            // Store valid challenges of both types
            for (int j = 0; j < 2; j++) {
                Challenge validReg = generateValidChallenge(Challenge.ChallengeType.REGISTRATION);
                store.storeChallenge(validReg.getChallengeId(), validReg);
                
                Challenge validAuth = generateValidChallenge(Challenge.ChallengeType.AUTHENTICATION);
                store.storeChallenge(validAuth.getChallengeId(), validAuth);
            }
            
            // Assert: Store should have 10 challenges (6 expired + 4 valid)
            assertEquals("Store should have 10 challenges", 10, store.size());
            
            // Perform cleanup
            store.cleanupExpiredChallenges();
            
            // Assert: Store should have 4 challenges (valid ones)
            assertEquals(
                "Store should have 4 valid challenges after cleanup (iteration " + i + ")",
                4,
                store.size()
            );
            
            // Clear for next iteration
            store.clear();
        }
    }

    // Helper methods

    /**
     * Generate an expired challenge.
     */
    private Challenge generateExpiredChallenge() {
        return generateExpiredChallenge(Challenge.ChallengeType.REGISTRATION);
    }

    /**
     * Generate an expired challenge of a specific type.
     */
    private Challenge generateExpiredChallenge(Challenge.ChallengeType type) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        
        Instant now = Instant.now();
        Instant expiresAt = now.minusSeconds(60); // Expired 60 seconds ago
        
        return new Challenge(
            challengeId,
            challengeBytes,
            "testuser",
            type,
            expiresAt.minusSeconds(300),
            expiresAt,
            UUID.randomUUID().toString()
        );
    }

    /**
     * Generate a valid challenge.
     */
    private Challenge generateValidChallenge() {
        return generateValidChallenge(Challenge.ChallengeType.REGISTRATION);
    }

    /**
     * Generate a valid challenge of a specific type.
     */
    private Challenge generateValidChallenge(Challenge.ChallengeType type) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300); // Expires in 5 minutes
        
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
     * Generate a challenge with a specific timeout (in seconds).
     */
    private Challenge generateChallengeWithTimeout(long timeoutSeconds) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(timeoutSeconds);
        
        return new Challenge(
            challengeId,
            challengeBytes,
            "testuser",
            Challenge.ChallengeType.REGISTRATION,
            now,
            expiresAt,
            UUID.randomUUID().toString()
        );
    }
}
