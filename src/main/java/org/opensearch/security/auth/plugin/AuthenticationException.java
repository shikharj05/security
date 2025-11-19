/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth.plugin;

/**
 * Exception thrown when authentication fails.
 * This exception is specific to the new authentication plugin architecture.
 */
public class AuthenticationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String authenticationType;
    private final String reason;

    /**
     * Creates a new AuthenticationException.
     *
     * @param authenticationType The type of authentication that failed (e.g., "ldap", "saml", "internal")
     * @param reason The reason for the authentication failure
     */
    public AuthenticationException(String authenticationType, String reason) {
        super(String.format("Authentication failed for type '%s': %s", authenticationType, reason));
        this.authenticationType = authenticationType;
        this.reason = reason;
    }

    /**
     * Creates a new AuthenticationException with a cause.
     *
     * @param authenticationType The type of authentication that failed
     * @param reason The reason for the authentication failure
     * @param cause The underlying cause of the failure
     */
    public AuthenticationException(String authenticationType, String reason, Throwable cause) {
        super(String.format("Authentication failed for type '%s': %s", authenticationType, reason), cause);
        this.authenticationType = authenticationType;
        this.reason = reason;
    }

    /**
     * Gets the type of authentication that failed.
     *
     * @return The authentication type
     */
    public String getAuthenticationType() {
        return authenticationType;
    }

    /**
     * Gets the reason for the authentication failure.
     *
     * @return The failure reason
     */
    public String getReason() {
        return reason;
    }
}
