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
 * Property-based tests for challenge expiration.
 * 
 * **Feature: passkey-authentication, Property 18: Challenge expiration**
 * **Validates: Requirements 4.4**
 * 
 * For any challenge, validation should fail if the challenge age exceeds 
 * the configured timeout. This prevents old challenges from being reused.
 */
public class ChallengeExpirationPropertyTest {

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Property 18: Challenge expiration
     * 
     * For any challenge, validation should fail if the challenge age exceeds
     * the configured timeout.
     * 
     * This test runs 100 iterations creating challenges with different expiration
     * times and verifying that:
     * 1. Non-expired challenges can be consumed
     * 2. Expired challenges cannot be consumed
     */
    @org.junit.Test
    public void expiredChallengesCannotBeConsumed() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Create a challenge that expires in the past
            Challenge expiredChallenge = generateExpiredChallenge();
            store.storeChallenge(expiredChallenge.getChallengeId(), expiredChallenge);
            
            // Assert: Expired challenge should not be consumable
            Optional<Challenge> expiredResult = store.consumeChallenge(expiredChallenge.getChallengeId());
            assertFalse(
                "Expired challenge should not be consumable (iteration " + i + ")",
                expiredResult.isPresent()
            );
            
            // Create a challenge that expires in the future
            Challenge validChallenge = generateValidChallenge();
            store.storeChallenge(validChallenge.getChallengeId(), validChallenge);
            
            // Assert: Valid challenge should be consumable
            Optional<Challenge> validResult = store.consumeChallenge(validChallenge.getChallengeId());
            assertTrue(
                "Valid challenge should be consumable (iteration " + i + ")",
                validResult.isPresent()
            );
        }
    }

    /**
     * Property 18 (extended): Challenge expiration with various timeout values
     * 
     * For any challenge with different timeout values, expiration should be
     * correctly enforced based on the configured timeout.
     */
    @org.junit.Test
    public void challengeExpirationWithVariousTimeouts() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        // Test with various timeout values (in seconds)
        long[] timeouts = {1, 5, 10, 30, 60, 300, 600, 3600};
        
        for (int i = 0; i < 100; i++) {
            long timeout = timeouts[i % timeouts.length];
            
            // Create a challenge that expired 1 second ago
            Challenge expiredChallenge = generateChallengeWithTimeout(-1);
            store.storeChallenge(expiredChallenge.getChallengeId(), expiredChallenge);
            
            // Assert: Should be expired
            assertFalse(
                "Challenge with timeout " + timeout + "s should be expired after expiration time",
                store.consumeChallenge(expiredChallenge.getChallengeId()).isPresent()
            );
            
            // Create a challenge that expires in the future
            Challenge validChallenge = generateChallengeWithTimeout(timeout);
            store.storeChallenge(validChallenge.getChallengeId(), validChallenge);
            
            // Assert: Should be valid
            assertTrue(
                "Challenge with timeout " + timeout + "s should be valid before expiration",
                store.consumeChallenge(validChallenge.getChallengeId()).isPresent()
            );
        }
    }

    /**
     * Property 18 (extended): Challenge expiration boundary conditions
     * 
     * For any challenge at the exact expiration boundary, it should be
     * correctly classified as expired or valid.
     */
    @org.junit.Test
    public void challengeExpirationBoundaryConditions() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Create a challenge that expires exactly now (boundary case)
            Instant now = Instant.now();
            Challenge boundaryChallenge = generateChallengeWithExactExpiration(now);
            store.storeChallenge(boundaryChallenge.getChallengeId(), boundaryChallenge);
            
            // Small delay to ensure we're past the expiration time
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            // Assert: Challenge should be expired (now is after expiresAt)
            Optional<Challenge> result = store.consumeChallenge(boundaryChallenge.getChallengeId());
            assertFalse(
                "Challenge expiring at boundary should be expired after boundary time (iteration " + i + ")",
                result.isPresent()
            );
        }
    }

    /**
     * Property 18 (extended): Challenge expiration across types
     * 
     * For any challenge type (REGISTRATION or AUTHENTICATION), expiration
     * should be enforced consistently.
     */
    @org.junit.Test
    public void challengeExpirationAcrossTypes() {
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        
        for (int i = 0; i < 100; i++) {
            // Test expired registration challenge
            Challenge expiredReg = generateExpiredChallenge(Challenge.ChallengeType.REGISTRATION);
            store.storeChallenge(expiredReg.getChallengeId(), expiredReg);
            assertFalse(
                "Expired registration challenge should not be consumable",
                store.consumeChallenge(expiredReg.getChallengeId()).isPresent()
            );
            
            // Test valid registration challenge
            Challenge validReg = generateValidChallenge(Challenge.ChallengeType.REGISTRATION);
            store.storeChallenge(validReg.getChallengeId(), validReg);
            assertTrue(
                "Valid registration challenge should be consumable",
                store.consumeChallenge(validReg.getChallengeId()).isPresent()
            );
            
            // Test expired authentication challenge
            Challenge expiredAuth = generateExpiredChallenge(Challenge.ChallengeType.AUTHENTICATION);
            store.storeChallenge(expiredAuth.getChallengeId(), expiredAuth);
            assertFalse(
                "Expired authentication challenge should not be consumable",
                store.consumeChallenge(expiredAuth.getChallengeId()).isPresent()
            );
            
            // Test valid authentication challenge
            Challenge validAuth = generateValidChallenge(Challenge.ChallengeType.AUTHENTICATION);
            store.storeChallenge(validAuth.getChallengeId(), validAuth);
            assertTrue(
                "Valid authentication challenge should be consumable",
                store.consumeChallenge(validAuth.getChallengeId()).isPresent()
            );
        }
    }

    /**
     * Property 18 (extended): Challenge expiration with isExpired method
     * 
     * For any challenge, the isExpired() method should correctly reflect
     * the expiration state.
     */
    @org.junit.Test
    public void challengeIsExpiredMethodCorrectness() {
        for (int i = 0; i < 100; i++) {
            // Create expired challenge
            Challenge expiredChallenge = generateExpiredChallenge();
            assertTrue(
                "isExpired() should return true for expired challenge (iteration " + i + ")",
                expiredChallenge.isExpired()
            );
            
            // Create valid challenge
            Challenge validChallenge = generateValidChallenge();
            assertFalse(
                "isExpired() should return false for valid challenge (iteration " + i + ")",
                validChallenge.isExpired()
            );
        }
    }

    // Helper methods

    /**
     * Generate an expired challenge (expires in the past).
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
            expiresAt.minusSeconds(300), // Created 5 minutes before expiration
            expiresAt,
            UUID.randomUUID().toString()
        );
    }

    /**
     * Generate a valid challenge (expires in the future).
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

    /**
     * Generate a challenge with an exact expiration time.
     */
    private Challenge generateChallengeWithExactExpiration(Instant expiresAt) {
        String challengeId = UUID.randomUUID().toString();
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        
        return new Challenge(
            challengeId,
            challengeBytes,
            "testuser",
            Challenge.ChallengeType.REGISTRATION,
            expiresAt.minusSeconds(300),
            expiresAt,
            UUID.randomUUID().toString()
        );
    }
}
