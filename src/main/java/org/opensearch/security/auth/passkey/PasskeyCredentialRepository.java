/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing passkey credentials.
 * Provides CRUD operations for storing and retrieving WebAuthn credentials.
 */
public interface PasskeyCredentialRepository {

    /**
     * Store a new passkey credential.
     *
     * @param credential the credential to store
     */
    void storeCredential(PasskeyCredential credential);

    /**
     * Find a credential by its credential ID.
     *
     * @param credentialId the credential ID to search for
     * @return an Optional containing the credential if found, empty otherwise
     */
    Optional<PasskeyCredential> findByCredentialId(String credentialId);

    /**
     * Find all credentials associated with a username.
     *
     * @param username the username to search for
     * @return a list of credentials for the user (empty list if none found)
     */
    List<PasskeyCredential> findByUsername(String username);

    /**
     * Delete a credential by its credential ID.
     *
     * @param credentialId the credential ID to delete
     */
    void deleteCredential(String credentialId);

    /**
     * Update the metadata for a credential.
     *
     * @param credentialId the credential ID to update
     * @param metadata the new metadata
     */
    void updateCredentialMetadata(String credentialId, PasskeyMetadata metadata);

    /**
     * Update the signature counter for a credential.
     * Used for clone detection.
     *
     * @param credentialId the credential ID to update
     * @param counter the new signature counter value
     */
    void updateSignatureCounter(String credentialId, long counter);

    /**
     * Update the last used timestamp for a credential.
     *
     * @param credentialId the credential ID to update
     */
    void updateLastUsed(String credentialId);
}
