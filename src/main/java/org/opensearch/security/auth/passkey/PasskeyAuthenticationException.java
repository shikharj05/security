/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Exception thrown when passkey authentication fails.
 * Examples: unknown credential ID, signature verification failure, challenge mismatch, expired challenge.
 */
public class PasskeyAuthenticationException extends PasskeyException {

    public PasskeyAuthenticationException(String message, PasskeyErrorType errorType) {
        super(message, errorType);
    }

    public PasskeyAuthenticationException(String message, Throwable cause, PasskeyErrorType errorType) {
        super(message, cause, errorType);
    }

    /**
     * Creates an authentication exception for signature verification failures.
     */
    public static PasskeyAuthenticationException signatureVerificationFailed(String message) {
        return new PasskeyAuthenticationException(message, PasskeyErrorType.SIGNATURE_VERIFICATION_FAILED);
    }

    /**
     * Creates an authentication exception for signature verification failures with a cause.
     */
    public static PasskeyAuthenticationException signatureVerificationFailed(String message, Throwable cause) {
        return new PasskeyAuthenticationException(message, cause, PasskeyErrorType.SIGNATURE_VERIFICATION_FAILED);
    }

    /**
     * Creates an authentication exception for expired challenges.
     */
    public static PasskeyAuthenticationException challengeExpired(String message) {
        return new PasskeyAuthenticationException(message, PasskeyErrorType.CHALLENGE_EXPIRED);
    }

    /**
     * Creates an authentication exception for unknown credentials.
     */
    public static PasskeyAuthenticationException unknownCredential(String message) {
        return new PasskeyAuthenticationException(message, PasskeyErrorType.UNKNOWN_CREDENTIAL);
    }

    /**
     * Creates an authentication exception for invalid requests.
     */
    public static PasskeyAuthenticationException invalidRequest(String message) {
        return new PasskeyAuthenticationException(message, PasskeyErrorType.INVALID_REQUEST);
    }

    /**
     * Creates an authentication exception for unauthorized access.
     */
    public static PasskeyAuthenticationException unauthorized(String message) {
        return new PasskeyAuthenticationException(message, PasskeyErrorType.UNAUTHORIZED);
    }
}
