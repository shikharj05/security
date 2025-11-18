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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableMap;

/**
 * Context for authorization decisions.
 * <p>
 * This immutable class encapsulates all information needed by an authorization plugin
 * to make an access control decision, including the action being performed, the resource
 * being accessed, resource-specific attributes, and the remote address of the request.
 * <p>
 * Objects of this class are immutable and thread-safe.
 * <p>
 * <b>Do not subclass from this class!</b>
 */
public final class AuthorizationContext implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String action;
    private final String resource;
    private final ImmutableMap<String, Object> resourceAttributes;
    private final String remoteAddress;

    /**
     * Private constructor. Use the Builder to create instances.
     */
    private AuthorizationContext(String action, String resource, Map<String, Object> resourceAttributes, String remoteAddress) {
        if (action == null || action.isEmpty()) {
            throw new IllegalArgumentException("action must not be null or empty");
        }
        if (resource == null || resource.isEmpty()) {
            throw new IllegalArgumentException("resource must not be null or empty");
        }

        this.action = action;
        this.resource = resource;
        this.resourceAttributes = resourceAttributes != null ? ImmutableMap.copyOf(resourceAttributes) : ImmutableMap.of();
        this.remoteAddress = remoteAddress;
    }

    /**
     * Returns the action being performed.
     * <p>
     * Examples: "indices:data/read/search", "cluster:admin/settings/update"
     *
     * @return The action string, never null or empty
     */
    public String getAction() {
        return action;
    }

    /**
     * Returns the resource being accessed.
     * <p>
     * Examples: "myindex", "myindex/mydoc/123", "*"
     *
     * @return The resource string, never null or empty
     */
    public String getResource() {
        return resource;
    }

    /**
     * Returns resource-specific attributes that may be relevant for authorization decisions.
     * <p>
     * Examples: index settings, document fields, cluster state information
     *
     * @return An immutable map of resource attributes, never null
     */
    public ImmutableMap<String, Object> getResourceAttributes() {
        return resourceAttributes;
    }

    /**
     * Returns the remote address of the request.
     * <p>
     * This may be an IP address or hostname, and can be used for IP-based
     * access control policies.
     *
     * @return The remote address, may be null if not available
     */
    public String getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationContext that = (AuthorizationContext) o;
        return Objects.equals(action, that.action)
            && Objects.equals(resource, that.resource)
            && Objects.equals(resourceAttributes, that.resourceAttributes)
            && Objects.equals(remoteAddress, that.remoteAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(action, resource, resourceAttributes, remoteAddress);
    }

    @Override
    public String toString() {
        return "AuthorizationContext{"
            + "action='"
            + action
            + '\''
            + ", resource='"
            + resource
            + '\''
            + ", remoteAddress='"
            + remoteAddress
            + '\''
            + ", resourceAttributesCount="
            + resourceAttributes.size()
            + '}';
    }

    /**
     * Creates a new Builder for constructing AuthorizationContext instances.
     *
     * @param action The action being performed, must not be null or empty
     * @param resource The resource being accessed, must not be null or empty
     * @return A new Builder instance
     */
    public static Builder builder(String action, String resource) {
        return new Builder(action, resource);
    }

    /**
     * Builder for creating AuthorizationContext instances.
     */
    public static final class Builder {
        private final String action;
        private final String resource;
        private Map<String, Object> resourceAttributes;
        private String remoteAddress;

        /**
         * Creates a new Builder with the specified action and resource.
         *
         * @param action The action being performed, must not be null or empty
         * @param resource The resource being accessed, must not be null or empty
         */
        private Builder(String action, String resource) {
            if (action == null || action.isEmpty()) {
                throw new IllegalArgumentException("action must not be null or empty");
            }
            if (resource == null || resource.isEmpty()) {
                throw new IllegalArgumentException("resource must not be null or empty");
            }
            this.action = action;
            this.resource = resource;
            this.resourceAttributes = new HashMap<>();
        }

        /**
         * Sets the resource attributes for this authorization context.
         *
         * @param resourceAttributes A map of resource attributes, may be null
         * @return This builder instance
         */
        public Builder resourceAttributes(Map<String, Object> resourceAttributes) {
            if (resourceAttributes != null) {
                this.resourceAttributes = new HashMap<>(resourceAttributes);
            }
            return this;
        }

        /**
         * Adds a single resource attribute to this authorization context.
         *
         * @param key The attribute key, must not be null
         * @param value The attribute value, may be null
         * @return This builder instance
         */
        public Builder resourceAttribute(String key, Object value) {
            Objects.requireNonNull(key, "resource attribute key must not be null");
            if (this.resourceAttributes == null) {
                this.resourceAttributes = new HashMap<>();
            }
            this.resourceAttributes.put(key, value);
            return this;
        }

        /**
         * Sets the remote address for this authorization context.
         *
         * @param remoteAddress The remote address (IP or hostname), may be null
         * @return This builder instance
         */
        public Builder remoteAddress(String remoteAddress) {
            this.remoteAddress = remoteAddress;
            return this;
        }

        /**
         * Builds and returns a new AuthorizationContext instance.
         *
         * @return A new AuthorizationContext instance
         */
        public AuthorizationContext build() {
            return new AuthorizationContext(action, resource, resourceAttributes, remoteAddress);
        }
    }
}
