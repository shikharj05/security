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

package org.opensearch.security.auth.plugin.adapter;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

/**
 * Adapter that wraps an {@link AuthenticationBackend} to implement the {@link AuthenticationPlugin} interface.
 * <p>
 * This adapter provides backward compatibility by allowing existing authentication backends
 * to work with the new plugin architecture. It converts between the old {@link User} object
 * and the new {@link UserPrincipal} representation.
 * <p>
 * <b>IMPORTANT - Adapter Usage:</b> As of the current release, all built-in authentication backends
 * have been converted to implement {@link AuthenticationPlugin} directly. This adapter is now
 * <b>ONLY</b> used for third-party custom backends that haven't migrated to the new interface yet.
 * <p>
 * Built-in backends that have been converted (no longer use this adapter):
 * <ul>
 *   <li>InternalAuthenticationBackend</li>
 *   <li>LDAPAuthenticationBackend2</li>
 *   <li>HTTPSamlAuthenticator</li>
 *   <li>HTTPJwtAuthenticator</li>
 *   <li>HTTPSpnegoAuthenticator</li>
 * </ul>
 * <p>
 * The adapter:
 * <ul>
 *   <li>Delegates authentication to the wrapped backend</li>
 *   <li>Converts the {@link User} returned by the backend to a {@link UserPrincipal}</li>
 *   <li>Extracts roles and attributes from the User as claims in the UserPrincipal</li>
 *   <li>Converts {@link OpenSearchSecurityException} to {@link AuthenticationException}</li>
 * </ul>
 * <p>
 * <b>Migration Recommendation:</b> Third-party plugin developers should migrate their backends
 * to implement {@link AuthenticationPlugin} directly to eliminate adapter overhead and prepare
 * for eventual removal of the old {@link AuthenticationBackend} interface.
 * <p>
 * This class is thread-safe if the wrapped backend is thread-safe.
 *
 * @see AuthenticationBackend
 * @see AuthenticationPlugin
 * @see UserPrincipal
 */
public class AuthenticationBackendAdapter implements AuthenticationPlugin {

    private final AuthenticationBackend backend;

    /**
     * Creates a new adapter wrapping the given authentication backend.
     *
     * @param backend The authentication backend to wrap, must not be null
     * @throws IllegalArgumentException if backend is null
     */
    public AuthenticationBackendAdapter(AuthenticationBackend backend) {
        if (backend == null) {
            throw new IllegalArgumentException("backend must not be null");
        }
        this.backend = backend;
    }

    @Override
    public String getType() {
        return backend.getType();
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // The old AuthenticationBackend interface doesn't have a supports() method,
        // so we assume it can attempt to authenticate any credentials.
        // The backend will throw an exception if it cannot handle the credentials.
        return true;
    }

    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        try {
            // Call the existing backend's authenticate method
            User user = backend.authenticate(context);

            if (user == null) {
                throw new AuthenticationException(
                    getType(),
                    "Backend returned null user"
                );
            }

            // Convert User to UserPrincipal using the conversion method
            return user.toPrincipal();

        } catch (AuthenticationException e) {
            // Re-throw AuthenticationException as-is
            throw e;
        } catch (OpenSearchSecurityException e) {
            // Convert OpenSearchSecurityException to AuthenticationException
            throw new AuthenticationException(
                getType(),
                e.getMessage() != null ? e.getMessage() : "Authentication failed",
                e
            );
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            throw new AuthenticationException(
                getType(),
                "Unexpected error during authentication: " + e.getMessage(),
                e
            );
        }
    }

    /**
     * Returns the wrapped authentication backend.
     * <p>
     * This method is provided for testing and debugging purposes.
     *
     * @return The wrapped backend
     */
    public AuthenticationBackend getBackend() {
        return backend;
    }

    @Override
    public String toString() {
        return "AuthenticationBackendAdapter{" +
            "backend=" + backend.getClass().getSimpleName() +
            ", type=" + getType() +
            '}';
    }
}
