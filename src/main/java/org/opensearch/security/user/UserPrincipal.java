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

package org.opensearch.security.user;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableMap;

/**
 * Represents an authenticated user with identity and claims extracted during authentication.
 * This is the contract between authentication and authorization plugins.
 * <p>
 * <b>INTERNAL USE ONLY:</b> This class is for internal use within the OpenSearch Security plugin.
 * It is NOT intended for serialization between nodes. The {@link User} class remains the
 * wire format for inter-node communication to maintain backward compatibility during rolling upgrades.
 * <p>
 * Objects of this class are immutable and thread-safe.
 * <p>
 * <b>Do not subclass from this class!</b>
 *
 * @see User
 */
public final class UserPrincipal implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final ImmutableMap<String, Object> claims;
    private final String authenticationType;
    private final long authenticationTime;

    /**
     * Private constructor. Use the Builder to create instances.
     */
    private UserPrincipal(String name, Map<String, Object> claims, String authenticationType, long authenticationTime) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name must not be null or empty");
        }

        this.name = name;
        this.claims = claims != null ? ImmutableMap.copyOf(claims) : ImmutableMap.of();
        this.authenticationType = authenticationType != null ? authenticationType : "unknown";
        this.authenticationTime = authenticationTime;
    }

    /**
     * Returns the verified user identifier.
     *
     * @return The username, never null or empty
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the claims extracted by the authentication plugin.
     * Claims are key-value pairs of attributes or assertions about the user
     * (e.g., groups, roles, email, custom attributes).
     *
     * @return An immutable map of claims, never null
     */
    public ImmutableMap<String, Object> getClaims() {
        return claims;
    }

    /**
     * Returns the type of authentication used.
     *
     * @return The authentication type (e.g., "ldap", "saml", "internal"), never null
     */
    public String getAuthenticationType() {
        return authenticationType;
    }

    /**
     * Returns the timestamp when authentication occurred.
     *
     * @return The authentication time in milliseconds since epoch
     */
    public long getAuthenticationTime() {
        return authenticationTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserPrincipal that = (UserPrincipal) o;
        return authenticationTime == that.authenticationTime
            && Objects.equals(name, that.name)
            && Objects.equals(claims, that.claims)
            && Objects.equals(authenticationType, that.authenticationType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, claims, authenticationType, authenticationTime);
    }

    @Override
    public String toString() {
        return "UserPrincipal{"
            + "name='"
            + name
            + '\''
            + ", authenticationType='"
            + authenticationType
            + '\''
            + ", authenticationTime="
            + authenticationTime
            + ", claimsCount="
            + claims.size()
            + '}';
    }

    /**
     * Creates a new Builder for constructing UserPrincipal instances.
     *
     * @param name The username, must not be null or empty
     * @return A new Builder instance
     */
    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * Builder for creating UserPrincipal instances.
     */
    public static final class Builder {
        private final String name;
        private Map<String, Object> claims;
        private String authenticationType;
        private long authenticationTime;

        /**
         * Creates a new Builder with the specified username.
         *
         * @param name The username, must not be null or empty
         */
        private Builder(String name) {
            if (name == null || name.isEmpty()) {
                throw new IllegalArgumentException("name must not be null or empty");
            }
            this.name = name;
            this.claims = new HashMap<>();
            this.authenticationType = "unknown";
            this.authenticationTime = System.currentTimeMillis();
        }

        /**
         * Sets the claims for this user principal.
         *
         * @param claims A map of claims, may be null
         * @return This builder instance
         */
        public Builder claims(Map<String, Object> claims) {
            if (claims != null) {
                this.claims = new HashMap<>(claims);
            }
            return this;
        }

        /**
         * Adds a single claim to this user principal.
         *
         * @param key The claim key, must not be null
         * @param value The claim value, may be null
         * @return This builder instance
         */
        public Builder claim(String key, Object value) {
            Objects.requireNonNull(key, "claim key must not be null");
            if (this.claims == null) {
                this.claims = new HashMap<>();
            }
            this.claims.put(key, value);
            return this;
        }

        /**
         * Sets the authentication type.
         *
         * @param authenticationType The authentication type (e.g., "ldap", "saml", "internal")
         * @return This builder instance
         */
        public Builder authenticationType(String authenticationType) {
            this.authenticationType = authenticationType;
            return this;
        }

        /**
         * Sets the authentication time.
         *
         * @param authenticationTime The authentication time in milliseconds since epoch
         * @return This builder instance
         */
        public Builder authenticationTime(long authenticationTime) {
            this.authenticationTime = authenticationTime;
            return this;
        }

        /**
         * Builds and returns a new UserPrincipal instance.
         *
         * @return A new UserPrincipal instance
         */
        public UserPrincipal build() {
            return new UserPrincipal(name, claims, authenticationType, authenticationTime);
        }
    }
}
