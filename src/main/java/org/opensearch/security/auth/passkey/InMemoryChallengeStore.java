/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * In-memory implementation of ChallengeStore.
 * 
 * This implementation uses a ConcurrentHashMap for thread-safe storage
 * and provides automatic cleanup of expired challenges.
 * 
 * Requirements addressed:
 * - 4.1: Cryptographically random challenges with timestamp tracking
 * - 4.2: Challenge storage with timestamp and session association
 * - 4.3: Single-use challenges (consumeChallenge removes after retrieval)
 * - 4.4: Challenge expiration based on configured time window
 * - 4.5: Cleanup of expired and used challenges
 */
public class InMemoryChallengeStore implements ChallengeStore {

    private static final Logger logger = LogManager.getLogger(InMemoryChallengeStore.class);
    
    private final Map<String, Challenge> challenges;
    private final int maxChallenges;

    /**
     * Create a new in-memory challenge store.
     */
    public InMemoryChallengeStore() {
        this(10000); // Default max 10,000 concurrent challenges
    }

    /**
     * Create a new in-memory challenge store with a specified maximum capacity.
     * 
     * @param maxChallenges maximum number of concurrent challenges to store
     */
    public InMemoryChallengeStore(int maxChallenges) {
        this.challenges = new ConcurrentHashMap<>();
        this.maxChallenges = maxChallenges;
    }

    @Override
    public void storeChallenge(String challengeId, Challenge challenge) {
        if (challengeId == null || challenge == null) {
            throw new IllegalArgumentException("Challenge ID and challenge must not be null");
        }

        // Check capacity before storing
        if (challenges.size() >= maxChallenges) {
            logger.warn("Challenge store at capacity ({}), cleaning up expired challenges", maxChallenges);
            cleanupExpiredChallenges();
            
            // If still at capacity after cleanup, reject the new challenge
            if (challenges.size() >= maxChallenges) {
                throw new IllegalStateException("Challenge store capacity exceeded");
            }
        }

        challenges.put(challengeId, challenge);
        logger.debug("Stored challenge {} of type {} for user {}", 
            challengeId, challenge.getType(), challenge.getUsername());
    }

    @Override
    public Optional<Challenge> consumeChallenge(String challengeId) {
        if (challengeId == null) {
            return Optional.empty();
        }

        // Remove the challenge from the store (single-use)
        Challenge challenge = challenges.remove(challengeId);
        
        if (challenge == null) {
            logger.debug("Challenge {} not found in store", challengeId);
            return Optional.empty();
        }

        // Check if the challenge has expired
        if (challenge.isExpired()) {
            logger.debug("Challenge {} has expired (expires at: {})", 
                challengeId, challenge.getExpiresAt());
            return Optional.empty();
        }

        logger.debug("Consumed challenge {} of type {} for user {}", 
            challengeId, challenge.getType(), challenge.getUsername());
        
        return Optional.of(challenge);
    }

    @Override
    public void cleanupExpiredChallenges() {
        Instant now = Instant.now();
        int removedCount = 0;

        // Iterate through all challenges and remove expired ones
        for (Map.Entry<String, Challenge> entry : challenges.entrySet()) {
            if (now.isAfter(entry.getValue().getExpiresAt())) {
                challenges.remove(entry.getKey());
                removedCount++;
            }
        }

        if (removedCount > 0) {
            logger.debug("Cleaned up {} expired challenges", removedCount);
        }
    }

    /**
     * Get the current number of stored challenges (for testing/monitoring).
     * 
     * @return the number of challenges currently in the store
     */
    public int size() {
        return challenges.size();
    }

    /**
     * Clear all challenges from the store (for testing).
     */
    public void clear() {
        challenges.clear();
        logger.debug("Cleared all challenges from store");
    }
}
