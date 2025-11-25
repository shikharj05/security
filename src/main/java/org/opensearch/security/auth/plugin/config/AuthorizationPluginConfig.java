/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Configuration for an authorization plugin.
 * Represents the YAML configuration structure for authorization plugins.
 */
public class AuthorizationPluginConfig {

    private final String type;
    private final boolean enabled;
    private final Map<String, Object> settings;

    /**
     * Creates a new authorization plugin configuration.
     *
     * @param type The plugin type identifier (e.g., "role_based", "custom")
     * @param enabled Whether the plugin is enabled
     * @param settings Plugin-specific configuration settings
     */
    public AuthorizationPluginConfig(String type, boolean enabled, Map<String, Object> settings) {
        this.type = Objects.requireNonNull(type, "Plugin type cannot be null");
        this.enabled = enabled;
        this.settings = settings != null ? Collections.unmodifiableMap(new java.util.HashMap<>(settings)) : Collections.emptyMap();
    }

    /**
     * Gets the plugin type identifier.
     *
     * @return The plugin type
     */
    public String getType() {
        return type;
    }

    /**
     * Checks if the plugin is enabled.
     *
     * @return true if enabled, false otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Gets the plugin-specific settings.
     *
     * @return Immutable map of settings
     */
    public Map<String, Object> getSettings() {
        return settings;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationPluginConfig that = (AuthorizationPluginConfig) o;
        return enabled == that.enabled && Objects.equals(type, that.type) && Objects.equals(settings, that.settings);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, enabled, settings);
    }

    @Override
    public String toString() {
        return "AuthorizationPluginConfig{" + "type='" + type + '\'' + ", enabled=" + enabled + ", settings=" + settings + '}';
    }
}
