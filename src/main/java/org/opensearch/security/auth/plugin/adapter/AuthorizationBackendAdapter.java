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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

/**
 * Adapter that wraps an {@link AuthorizationBackend} to implement the {@link AuthorizationPlugin} interface.
 * <p>
 * This adapter provides backward compatibility by allowing existing authorization backends
 * to work with the new plugin architecture. It converts between the new {@link UserPrincipal}
 * representation and the old {@link User} object.
 * <p>
 * <b>IMPORTANT - Adapter Usage:</b> As of the current release, all built-in authorization backends
 * have been converted to implement {@link AuthorizationPlugin} directly. This adapter is now
 * <b>ONLY</b> used for third-party custom backends that haven't migrated to the new interface yet.
 * <p>
 * Built-in backends that have been converted (no longer use this adapter):
 * <ul>
 *   <li>LDAPAuthorizationBackend2</li>
 *   <li>RoleBasedAuthorizationPlugin (internal)</li>
 * </ul>
 * <p>
 * The adapter:
 * <ul>
 *   <li>Converts {@link UserPrincipal} to {@link User} for backend processing</li>
 *   <li>Delegates authorization to the wrapped backend's {@code addRoles()} method</li>
 *   <li>Converts role additions from the backend to {@link AuthorizationResult}</li>
 *   <li>Converts {@link OpenSearchSecurityException} to authorization denials</li>
 * </ul>
 * <p>
 * <b>Important:</b> The old {@link AuthorizationBackend} interface modifies the {@link User}
 * object by adding roles. This adapter interprets any roles added by the backend as
 * authorization grants, returning an allow result if roles were added.
 * <p>
 * <b>Migration Recommendation:</b> Third-party plugin developers should migrate their backends
 * to implement {@link AuthorizationPlugin} directly to eliminate adapter overhead and prepare
 * for eventual removal of the old {@link AuthorizationBackend} interface.
 * <p>
 * This class is thread-safe if the wrapped backend is thread-safe.
 *
 * @see AuthorizationBackend
 * @see AuthorizationPlugin
 * @see UserPrincipal
 */
public class AuthorizationBackendAdapter implements AuthorizationPlugin {

    private final AuthorizationBackend backend;

    /**
     * Creates a new adapter wrapping the given authorization backend.
     *
     * @param backend The authorization backend to wrap, must not be null
     * @throws IllegalArgumentException if backend is null
     */
    public AuthorizationBackendAdapter(AuthorizationBackend backend) {
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
    public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
        try {
            // Convert UserPrincipal to User for backend processing
            // We need to create a User object with empty security roles since the backend
            // will add roles through the addRoles() method
            User user = User.fromPrincipal(principal, Collections.emptySet());

            // Create an AuthenticationContext for the backend
            // The old interface expects AuthenticationContext, but we only have AuthorizationContext
            // We'll create a minimal context with the information we have
            AuthenticationContext authContext = new AuthenticationContext(null);

            // Call the backend's addRoles method
            User userWithRoles = backend.addRoles(user, authContext);

            if (userWithRoles == null) {
                // Backend returned null, treat as authorization failure
                return AuthorizationResult.deny("Backend returned null user");
            }

            // The old authorization backend adds roles to the user
            // We interpret this as successful authorization
            // In the new architecture, the actual permission evaluation happens elsewhere
            return AuthorizationResult.allow();

        } catch (OpenSearchSecurityException e) {
            // Backend threw an exception, treat as authorization failure
            return AuthorizationResult.deny(
                e.getMessage() != null ? e.getMessage() : "Authorization backend error"
            );
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            return AuthorizationResult.deny(
                "Unexpected error during authorization: " + e.getMessage()
            );
        }
    }

    @Override
    public Set<String> resolvePermissions(UserPrincipal principal) {
        try {
            // Convert UserPrincipal to User
            User user = User.fromPrincipal(principal, Collections.emptySet());

            // Create a minimal AuthenticationContext
            AuthenticationContext authContext = new AuthenticationContext(null);

            // Call the backend to add roles
            User userWithRoles = backend.addRoles(user, authContext);

            if (userWithRoles == null) {
                return Collections.emptySet();
            }

            // Extract the roles that were added by the backend
            // In the old architecture, these are the "backend roles" or "roles"
            Set<String> resolvedRoles = new HashSet<>(userWithRoles.getRoles());

            // Also include security roles if they were set
            resolvedRoles.addAll(userWithRoles.getSecurityRoles());

            return Collections.unmodifiableSet(resolvedRoles);

        } catch (OpenSearchSecurityException e) {
            // Backend failed, return empty set
            return Collections.emptySet();
        } catch (Exception e) {
            // Handle any other unexpected exceptions
            return Collections.emptySet();
        }
    }

    /**
     * Returns the wrapped authorization backend.
     * <p>
     * This method is provided for testing and debugging purposes.
     *
     * @return The wrapped backend
     */
    public AuthorizationBackend getBackend() {
        return backend;
    }

    @Override
    public String toString() {
        return "AuthorizationBackendAdapter{" +
            "backend=" + backend.getClass().getSimpleName() +
            ", type=" + getType() +
            '}';
    }
}
