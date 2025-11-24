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

package org.opensearch.security.auth.plugin.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

/**
 * Authentication plugin for internal user database.
 * <p>
 * This plugin authenticates users against the internal user database configured
 * in the OpenSearch Security plugin. It verifies credentials using password hashing
 * and extracts backend roles and custom attributes as claims.
 * <p>
 * This implementation is based on {@code InternalAuthenticationBackend} but follows
 * the new plugin architecture that separates authentication from authorization.
 *
 * @see org.opensearch.security.auth.internal.InternalAuthenticationBackend
 */
public class InternalAuthenticationPlugin implements AuthenticationPlugin {

    private final PasswordHasher passwordHasher;
    private InternalUsersModel internalUsersModel;

    /**
     * Creates a new internal authentication plugin.
     *
     * @param passwordHasher The password hasher for verifying credentials
     */
    public InternalAuthenticationPlugin(PasswordHasher passwordHasher) {
        if (passwordHasher == null) {
            throw new IllegalArgumentException("passwordHasher must not be null");
        }
        this.passwordHasher = passwordHasher;
    }

    @Override
    public String getType() {
        return "internal";
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // Internal authentication supports username/password credentials
        return credentials != null && credentials.getUsername() != null && credentials.getPassword() != null;
    }

    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        AuthCredentials credentials = context.getCredentials();

        if (internalUsersModel == null) {
            throw new AuthenticationException(
                getType(),
                "Internal authentication backend not configured. May be OpenSearch is not initialized."
            );
        }

        if (credentials == null || credentials.getUsername() == null) {
            throw new AuthenticationException(getType(), "Credentials or username is null");
        }

        boolean userExists;
        final byte[] password;
        String hash;

        if (!internalUsersModel.exists(credentials.getUsername())) {
            userExists = false;
            password = credentials.getPassword();
            // Ensure the same cryptographic complexity for users not found and invalid password
            hash = "$2y$12$NmKhjNssNgSIj8iXT7SYxeXvMA1E95a9tCt4cySY9FrQ4fB18xEc2";
        } else {
            userExists = true;
            password = credentials.getPassword();
            hash = internalUsersModel.getHash(credentials.getUsername());
        }

        if (password == null || password.length == 0) {
            throw new AuthenticationException(getType(), "empty passwords not supported");
        }

        ByteBuffer wrap = ByteBuffer.wrap(password);
        CharBuffer buf = StandardCharsets.UTF_8.decode(wrap);
        char[] array = new char[buf.limit()];
        buf.get(array);

        Arrays.fill(password, (byte) 0);

        try {
            if (passwordHasher.check(array, hash) && userExists) {
                // Authentication successful - extract claims
                ImmutableSet<String> backendRoles = internalUsersModel.getBackendRoles(credentials.getUsername());
                ImmutableSet<String> securityRoles = internalUsersModel.getSecurityRoles(credentials.getUsername());
                ImmutableMap<String, String> userAttributes = internalUsersModel.getAttributes(credentials.getUsername());

                // Build claims map
                Map<String, Object> claims = new HashMap<>();

                // Add backend roles as a claim
                if (backendRoles != null && !backendRoles.isEmpty()) {
                    claims.put("backend_roles", new ArrayList<>(backendRoles));
                }

                // Add security roles as a claim (for backward compatibility)
                if (securityRoles != null && !securityRoles.isEmpty()) {
                    claims.put("security_roles", new ArrayList<>(securityRoles));
                }

                // Add user attributes with "attr.internal." prefix
                if (userAttributes != null && !userAttributes.isEmpty()) {
                    for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
                        claims.put("attr.internal." + entry.getKey(), entry.getValue());
                    }
                }

                // Add attributes from credentials
                if (credentials.getAttributes() != null && !credentials.getAttributes().isEmpty()) {
                    claims.putAll(credentials.getAttributes());
                }

                // Return UserPrincipal with identity and claims
                return UserPrincipal.builder(credentials.getUsername())
                    .claims(claims)
                    .authenticationType(getType())
                    .authenticationTime(System.currentTimeMillis())
                    .build();
            } else {
                if (!userExists) {
                    throw new AuthenticationException(getType(), credentials.getUsername() + " not found");
                }
                throw new AuthenticationException(getType(), "password does not match");
            }
        } finally {
            Arrays.fill(wrap.array(), (byte) 0);
            Arrays.fill(buf.array(), '\0');
            Arrays.fill(array, '\0');
        }
    }

    /**
     * Updates the internal users model when it changes.
     * This method is called by the event bus when the configuration is reloaded.
     *
     * @param ium The new internal users model
     */
    @Subscribe
    public void onInternalUsersModelChanged(InternalUsersModel ium) {
        this.internalUsersModel = ium;
    }
}
