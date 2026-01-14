/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.util.Optional;

/**
 * Interface for managing temporary challenges used in WebAuthn authentication.
 * Challenges are single-use and have a time-to-live to prevent replay attacks.
 */
public interface ChallengeStore {

    /**
     * Store a challenge with timestamp and session tracking.
     * 
     * @param challengeId the unique identifier for the challenge
     * @param challenge the challenge object containing all challenge data
     */
    void storeChallenge(String challengeId, Challenge challenge);

    /**
     * Consume a challenge, removing it from the store (single-use).
     * This method ensures challenges can only be used once.
     * 
     * @param challengeId the unique identifier for the challenge
     * @return Optional containing the challenge if found and not expired, empty otherwise
     */
    Optional<Challenge> consumeChallenge(String challengeId);

    /**
     * Clean up expired challenges based on their TTL.
     * This method should be called periodically to prevent memory leaks.
     */
    void cleanupExpiredChallenges();
}
