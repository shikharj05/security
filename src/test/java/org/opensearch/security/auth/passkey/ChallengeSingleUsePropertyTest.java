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
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for challenge single-use enforcement.
 * 
 * **Feature: passkey-authentication, Property 17: Challenge single-use**
 * **Validates: Requirements 4.3**
 * 
 * For any challenge, attempting to use it more than once should result in rejection.
 * This prevents replay attacks where an attacker captures and reuses authentication data.
 */
public class ChallengeSingleUsePropertyTest {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Property 17: Challenge single-use
     * 
     * For any challenge, attempting to use it more than once should result in rejection.
     * 
     * This test runs 100 iterations storing challenges and verifying that:
     * 1. The first consumption succeeds
     * 2. The second consumption fails (returns empty)
     * 3. Subsequent consumptions also fail
     */
    @org.junit.Test
    public void challengeCanOnlyBeUsedOnce() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Generate and store a challenge
            Challenge challenge = generateChallenge();
            String challengeId = challenge.getChallengeId();
            store.storeChallenge(challengeId, challenge);
            
            // Assert: First consumption should succeed
            Optional<Challenge> firstConsumption = store.consumeChallenge(challengeId);
            assertTrue(
                "First consumption of challenge should succeed (iteration " + i + ")",
                firstConsumption.isPresent()
            );
            
            // Assert: Second consumption should fail (challenge already consumed)
            Optional<Challenge> secondConsumption = store.consumeChallenge(challengeId);
            assertFalse(
                "Second consumption of challenge should fail (iteration " + i + ")",
                secondConsumption.isPresent()
            );
            
            // Assert: Third consumption should also fail
            Optional<Challenge> thirdConsumption = store.consumeChallenge(challengeId);
            assertFalse(
                "Third consumption of challenge should fail (iteration " + i + ")",
                thirdConsumption.isPresent()
            );
        }
    }

    /**
     * Property 17 (extended): Challenge single-use across different challenge types
     * 
     * For any challenge type (REGISTRATION or AUTHENTICATION), the single-use
     * property should hold.
     */
    @org.junit.Test
    public void challengeSingleUseAcrossTypes() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Test with registration challenge
            Challenge regChallenge = generateChallenge(Challenge.ChallengeType.REGISTRATION);
            String regChallengeId = regChallenge.getChallengeId();
            store.storeChallenge(regChallengeId, regChallenge);
            
            Optional<Challenge> regFirst = store.consumeChallenge(regChallengeId);
            assertTrue("Registration challenge first use should succeed", regFirst.isPresent());
            
            Optional<Challenge> regSecond = store.consumeChallenge(regChallengeId);
            assertFalse("Registration challenge second use should fail", regSecond.isPresent());
            
            // Test with authentication challenge
            Challenge authChallenge = generateChallenge(Challenge.ChallengeType.AUTHENTICATION);
            String authChallengeId = authChallenge.getChallengeId();
            store.storeChallenge(authChallengeId, authChallenge);
            
            Optional<Challenge> authFirst = store.consumeChallenge(authChallengeId);
            assertTrue("Authentication challenge first use should succeed", authFirst.isPresent());
            
            Optional<Challenge> authSecond = store.consumeChallenge(authChallengeId);
            assertFalse("Authentication challenge second use should fail", authSecond.isPresent());
        }
    }

    /**
     * Property 17 (extended): Challenge single-use with concurrent access
     * 
     * For any challenge, even with concurrent consumption attempts, only one
     * should succeed.
     */
    @org.junit.Test
    public void challengeSingleUseWithConcurrentAccess() throws InterruptedException {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            Challenge challenge = generateChallenge();
            String challengeId = challenge.getChallengeId();
            store.storeChallenge(challengeId, challenge);
            
            // Track successful consumptions
            final boolean[] consumptionResults = new boolean[3];
            
            // Create three threads that try to consume the same challenge
            Thread thread1 = new Thread(() -> {
                consumptionResults[0] = store.consumeChallenge(challengeId).isPresent();
            });
            
            Thread thread2 = new Thread(() -> {
                consumptionResults[1] = store.consumeChallenge(challengeId).isPresent();
            });
            
            Thread thread3 = new Thread(() -> {
                consumptionResults[2] = store.consumeChallenge(challengeId).isPresent();
            });
            
            // Start all threads simultaneously
            thread1.start();
            thread2.start();
            thread3.start();
            
            // Wait for all threads to complete
            thread1.join();
            thread2.join();
            thread3.join();
            
            // Assert: Exactly one thread should have succeeded
            int successCount = 0;
            for (boolean result : consumptionResults) {
                if (result) {
                    successCount++;
                }
            }
            
            assertTrue(
                "Exactly one concurrent consumption should succeed (iteration " + i + "), but " + successCount + " succeeded",
                successCount == 1
            );
        }
    }

    /**
     * Property 17 (extended): Challenge single-use with multiple challenges
     * 
     * For any set of challenges, each should be independently single-use.
     * Consuming one challenge should not affect others.
     */
    @org.junit.Test
    public void multipleChallengesIndependentSingleUse() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Store three different challenges
            Challenge challenge1 = generateChallenge();
            Challenge challenge2 = generateChallenge();
            Challenge challenge3 = generateChallenge();
            
            store.storeChallenge(challenge1.getChallengeId(), challenge1);
            store.storeChallenge(challenge2.getChallengeId(), challenge2);
            store.storeChallenge(challenge3.getChallengeId(), challenge3);
            
            // Consume challenge1
            Optional<Challenge> result1 = store.consumeChallenge(challenge1.getChallengeId());
            assertTrue("Challenge 1 first consumption should succeed", result1.isPresent());
            
            // Assert: challenge2 and challenge3 should still be available
            Optional<Challenge> result2 = store.consumeChallenge(challenge2.getChallengeId());
            assertTrue("Challenge 2 should still be available after challenge 1 consumed", result2.isPresent());
            
            Optional<Challenge> result3 = store.consumeChallenge(challenge3.getChallengeId());
            assertTrue("Challenge 3 should still be available after challenges 1 and 2 consumed", result3.isPresent());
            
            // Assert: All challenges should now be consumed
            assertFalse("Challenge 1 second consumption should fail", 
                store.consumeChallenge(challenge1.getChallengeId()).isPresent());
            assertFalse("Challenge 2 second consumption should fail", 
                store.consumeChallenge(challenge2.getChallengeId()).isPresent());
            assertFalse("Challenge 3 second consumption should fail", 
                store.consumeChallenge(challenge3.getChallengeId()).isPresent());
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
}
