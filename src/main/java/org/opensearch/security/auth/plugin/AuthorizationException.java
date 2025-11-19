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
 * Exception thrown when authorization fails.
 * This exception is specific to the new authorization plugin architecture.
 */
public class AuthorizationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String principal;
    private final String resource;
    private final String action;

    /**
     * Creates a new AuthorizationException.
     *
     * @param principal The principal (user) that was denied access
     * @param resource The resource that was being accessed
     * @param action The action that was being performed
     */
    public AuthorizationException(String principal, String resource, String action) {
        super(
            String.format("Authorization failed for principal '%s' attempting action '%s' on resource '%s'", principal, action, resource)
        );
        this.principal = principal;
        this.resource = resource;
        this.action = action;
    }

    /**
     * Creates a new AuthorizationException with a custom message.
     *
     * @param principal The principal (user) that was denied access
     * @param resource The resource that was being accessed
     * @param action The action that was being performed
     * @param message Custom error message
     */
    public AuthorizationException(String principal, String resource, String action, String message) {
        super(message);
        this.principal = principal;
        this.resource = resource;
        this.action = action;
    }

    /**
     * Creates a new AuthorizationException with a cause.
     *
     * @param principal The principal (user) that was denied access
     * @param resource The resource that was being accessed
     * @param action The action that was being performed
     * @param cause The underlying cause of the failure
     */
    public AuthorizationException(String principal, String resource, String action, Throwable cause) {
        super(
            String.format("Authorization failed for principal '%s' attempting action '%s' on resource '%s'", principal, action, resource),
            cause
        );
        this.principal = principal;
        this.resource = resource;
        this.action = action;
    }

    /**
     * Gets the principal that was denied access.
     *
     * @return The principal name
     */
    public String getPrincipal() {
        return principal;
    }

    /**
     * Gets the resource that was being accessed.
     *
     * @return The resource identifier
     */
    public String getResource() {
        return resource;
    }

    /**
     * Gets the action that was being performed.
     *
     * @return The action name
     */
    public String getAction() {
        return action;
    }
}
