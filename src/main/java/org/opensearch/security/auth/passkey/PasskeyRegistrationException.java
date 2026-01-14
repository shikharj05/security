/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Exception thrown when passkey registration fails.
 * Examples: invalid attestation format, attestation verification failure, duplicate credential registration.
 */
public class PasskeyRegistrationException extends PasskeyException {

    public PasskeyRegistrationException(String message, PasskeyErrorType errorType) {
        super(message, errorType);
    }

    public PasskeyRegistrationException(String message, Throwable cause, PasskeyErrorType errorType) {
        super(message, cause, errorType);
    }

    /**
     * Creates a registration exception for attestation verification failures.
     */
    public static PasskeyRegistrationException attestationVerificationFailed(String message) {
        return new PasskeyRegistrationException(message, PasskeyErrorType.ATTESTATION_VERIFICATION_FAILED);
    }

    /**
     * Creates a registration exception for attestation verification failures with a cause.
     */
    public static PasskeyRegistrationException attestationVerificationFailed(String message, Throwable cause) {
        return new PasskeyRegistrationException(message, cause, PasskeyErrorType.ATTESTATION_VERIFICATION_FAILED);
    }

    /**
     * Creates a registration exception for invalid requests.
     */
    public static PasskeyRegistrationException invalidRequest(String message) {
        return new PasskeyRegistrationException(message, PasskeyErrorType.INVALID_REQUEST);
    }
}
