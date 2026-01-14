/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Base exception for all passkey-related errors.
 */
public class PasskeyException extends Exception {

    private final PasskeyErrorType errorType;

    public PasskeyException(String message, PasskeyErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }

    public PasskeyException(String message, Throwable cause, PasskeyErrorType errorType) {
        super(message, cause);
        this.errorType = errorType;
    }

    public PasskeyErrorType getErrorType() {
        return errorType;
    }

    /**
     * Enum defining the types of passkey errors for categorization and logging.
     */
    public enum PasskeyErrorType {
        CONFIGURATION_ERROR,
        REGISTRATION_ERROR,
        AUTHENTICATION_ERROR,
        STORAGE_ERROR,
        ATTESTATION_VERIFICATION_FAILED,
        SIGNATURE_VERIFICATION_FAILED,
        CHALLENGE_EXPIRED,
        UNKNOWN_CREDENTIAL,
        INVALID_REQUEST,
        UNAUTHORIZED
    }
}
