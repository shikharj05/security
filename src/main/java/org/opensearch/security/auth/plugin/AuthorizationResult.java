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

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import com.google.common.collect.ImmutableSet;

/**
 * Result of an authorization decision.
 * <p>
 * This immutable class represents the outcome of an authorization plugin's evaluation,
 * including whether access is allowed, the reason for the decision, and which policies
 * were applied during the evaluation.
 * <p>
 * Objects of this class are immutable and thread-safe.
 * <p>
 * <b>Do not subclass from this class!</b>
 */
public final class AuthorizationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final boolean allowed;
    private final String reason;
    private final ImmutableSet<String> appliedPolicies;

    /**
     * Private constructor. Use the static factory methods or Builder to create instances.
     */
    private AuthorizationResult(boolean allowed, String reason, Set<String> appliedPolicies) {
        this.allowed = allowed;
        this.reason = reason;
        this.appliedPolicies = appliedPolicies != null ? ImmutableSet.copyOf(appliedPolicies) : ImmutableSet.of();
    }

    /**
     * Creates an authorization result indicating that access is allowed.
     *
     * @return An AuthorizationResult with allowed=true
     */
    public static AuthorizationResult allow() {
        return new AuthorizationResult(true, null, null);
    }

    /**
     * Creates an authorization result indicating that access is denied.
     *
     * @param reason The reason for denying access, must not be null or empty
     * @return An AuthorizationResult with allowed=false and the specified reason
     * @throws IllegalArgumentException if reason is null or empty
     */
    public static AuthorizationResult deny(String reason) {
        if (reason == null || reason.isEmpty()) {
            throw new IllegalArgumentException("reason must not be null or empty for deny result");
        }
        return new AuthorizationResult(false, reason, null);
    }

    /**
     * Returns whether access is allowed.
     *
     * @return true if access is allowed, false otherwise
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * Returns the reason for the authorization decision.
     * <p>
     * This is typically populated for deny decisions to explain why access was denied.
     * For allow decisions, this may be null.
     *
     * @return The reason string, may be null
     */
    public String getReason() {
        return reason;
    }

    /**
     * Returns the set of policies that were applied during the authorization evaluation.
     * <p>
     * This can be used for audit logging and debugging to understand which policies
     * contributed to the authorization decision.
     *
     * @return An immutable set of policy identifiers, never null
     */
    public ImmutableSet<String> getAppliedPolicies() {
        return appliedPolicies;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationResult that = (AuthorizationResult) o;
        return allowed == that.allowed && Objects.equals(reason, that.reason) && Objects.equals(appliedPolicies, that.appliedPolicies);
    }

    @Override
    public int hashCode() {
        return Objects.hash(allowed, reason, appliedPolicies);
    }

    @Override
    public String toString() {
        return "AuthorizationResult{"
            + "allowed="
            + allowed
            + ", reason='"
            + reason
            + '\''
            + ", appliedPoliciesCount="
            + appliedPolicies.size()
            + '}';
    }

    /**
     * Creates a new Builder for constructing AuthorizationResult instances.
     *
     * @param allowed Whether access is allowed
     * @return A new Builder instance
     */
    public static Builder builder(boolean allowed) {
        return new Builder(allowed);
    }

    /**
     * Builder for creating AuthorizationResult instances with additional details.
     */
    public static final class Builder {
        private final boolean allowed;
        private String reason;
        private Set<String> appliedPolicies;

        /**
         * Creates a new Builder with the specified allowed status.
         *
         * @param allowed Whether access is allowed
         */
        private Builder(boolean allowed) {
            this.allowed = allowed;
            this.appliedPolicies = new HashSet<>();
        }

        /**
         * Sets the reason for the authorization decision.
         *
         * @param reason The reason string, may be null
         * @return This builder instance
         */
        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        /**
         * Sets the policies that were applied during authorization evaluation.
         *
         * @param appliedPolicies A set of policy identifiers, may be null
         * @return This builder instance
         */
        public Builder appliedPolicies(Set<String> appliedPolicies) {
            if (appliedPolicies != null) {
                this.appliedPolicies = new HashSet<>(appliedPolicies);
            }
            return this;
        }

        /**
         * Adds a single policy to the set of applied policies.
         *
         * @param policy The policy identifier, must not be null
         * @return This builder instance
         */
        public Builder appliedPolicy(String policy) {
            Objects.requireNonNull(policy, "policy must not be null");
            if (this.appliedPolicies == null) {
                this.appliedPolicies = new HashSet<>();
            }
            this.appliedPolicies.add(policy);
            return this;
        }

        /**
         * Builds and returns a new AuthorizationResult instance.
         *
         * @return A new AuthorizationResult instance
         */
        public AuthorizationResult build() {
            return new AuthorizationResult(allowed, reason, appliedPolicies);
        }
    }
}
