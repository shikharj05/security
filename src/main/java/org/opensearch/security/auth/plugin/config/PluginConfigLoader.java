/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;

/**
 * Loads authentication and authorization plugin configurations from OpenSearch settings.
 * Supports loading from both YAML configuration files and dynamic settings.
 */
public class PluginConfigLoader {

    private static final Logger log = LogManager.getLogger(PluginConfigLoader.class);

    // Configuration keys
    private static final String AUTHENTICATION_PLUGINS_KEY = "plugins.security.authentication";
    private static final String AUTHORIZATION_PLUGINS_KEY = "plugins.security.authorization";
    private static final String TYPE_KEY = "type";
    private static final String ENABLED_KEY = "enabled";
    private static final String ORDER_KEY = "order";
    private static final String CONFIG_KEY = "config";

    private final PluginConfigValidator validator;

    /**
     * Creates a new plugin configuration loader.
     */
    public PluginConfigLoader() {
        this.validator = new PluginConfigValidator();
    }

    /**
     * Loads authentication plugin configurations from settings.
     *
     * @param settings The OpenSearch settings containing plugin configurations
     * @return List of authentication plugin configurations, sorted by order
     */
    public List<AuthenticationPluginConfig> loadAuthenticationPlugins(Settings settings) {
        log.debug("Loading authentication plugin configurations");

        List<AuthenticationPluginConfig> configs = new ArrayList<>();

        // Check if authentication plugins are configured
        Settings authPluginsSettings = settings.getByPrefix(AUTHENTICATION_PLUGINS_KEY + ".");
        if (authPluginsSettings.isEmpty()) {
            log.debug("No authentication plugins configured");
            return Collections.emptyList();
        }

        // Parse each plugin configuration
        Map<String, Settings> pluginGroups = authPluginsSettings.getAsGroups();
        for (Map.Entry<String, Settings> entry : pluginGroups.entrySet()) {
            String pluginIndex = entry.getKey();
            Settings pluginSettings = entry.getValue();

            try {
                AuthenticationPluginConfig config = parseAuthenticationPlugin(pluginIndex, pluginSettings);
                configs.add(config);
                log.debug("Loaded authentication plugin: type={}, enabled={}, order={}", 
                    config.getType(), config.isEnabled(), config.getOrder());
            } catch (Exception e) {
                log.error("Failed to load authentication plugin at index {}: {}", pluginIndex, e.getMessage(), e);
            }
        }

        // Validate all configurations
        try {
            validator.validateAuthenticationConfigs(configs);
        } catch (Exception e) {
            log.error("Authentication plugin configuration validation failed: {}", e.getMessage(), e);
            return Collections.emptyList();
        }

        // Sort by order and filter enabled plugins
        List<AuthenticationPluginConfig> sortedConfigs = configs.stream()
            .filter(AuthenticationPluginConfig::isEnabled)
            .sorted(Comparator.comparingInt(AuthenticationPluginConfig::getOrder))
            .collect(Collectors.toList());

        log.info("Loaded {} enabled authentication plugins", sortedConfigs.size());
        return sortedConfigs;
    }

    /**
     * Loads authorization plugin configurations from settings.
     *
     * @param settings The OpenSearch settings containing plugin configurations
     * @return List of authorization plugin configurations
     */
    public List<AuthorizationPluginConfig> loadAuthorizationPlugins(Settings settings) {
        log.debug("Loading authorization plugin configurations");

        List<AuthorizationPluginConfig> configs = new ArrayList<>();

        // Check if authorization plugins are configured
        Settings authzPluginsSettings = settings.getByPrefix(AUTHORIZATION_PLUGINS_KEY + ".");
        if (authzPluginsSettings.isEmpty()) {
            log.debug("No authorization plugins configured");
            return Collections.emptyList();
        }

        // Parse each plugin configuration
        Map<String, Settings> pluginGroups = authzPluginsSettings.getAsGroups();
        for (Map.Entry<String, Settings> entry : pluginGroups.entrySet()) {
            String pluginIndex = entry.getKey();
            Settings pluginSettings = entry.getValue();

            try {
                AuthorizationPluginConfig config = parseAuthorizationPlugin(pluginIndex, pluginSettings);
                configs.add(config);
                log.debug("Loaded authorization plugin: type={}, enabled={}", 
                    config.getType(), config.isEnabled());
            } catch (Exception e) {
                log.error("Failed to load authorization plugin at index {}: {}", pluginIndex, e.getMessage(), e);
            }
        }

        // Validate all configurations
        try {
            validator.validateAuthorizationConfigs(configs);
        } catch (Exception e) {
            log.error("Authorization plugin configuration validation failed: {}", e.getMessage(), e);
            return Collections.emptyList();
        }

        // Filter enabled plugins
        List<AuthorizationPluginConfig> enabledConfigs = configs.stream()
            .filter(AuthorizationPluginConfig::isEnabled)
            .collect(Collectors.toList());

        log.info("Loaded {} enabled authorization plugins", enabledConfigs.size());
        return enabledConfigs;
    }

    /**
     * Parses an authentication plugin configuration from settings.
     */
    private AuthenticationPluginConfig parseAuthenticationPlugin(String index, Settings pluginSettings) {
        String type = pluginSettings.get(TYPE_KEY);
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("Authentication plugin at index " + index + " missing required 'type' field");
        }

        boolean enabled = pluginSettings.getAsBoolean(ENABLED_KEY, true);
        int order = pluginSettings.getAsInt(ORDER_KEY, Integer.MAX_VALUE);

        // Parse plugin-specific settings
        Settings configSettings = pluginSettings.getByPrefix(CONFIG_KEY + ".");
        Map<String, Object> settings = settingsToMap(configSettings);

        return new AuthenticationPluginConfig(type, enabled, order, settings);
    }

    /**
     * Parses an authorization plugin configuration from settings.
     */
    private AuthorizationPluginConfig parseAuthorizationPlugin(String index, Settings pluginSettings) {
        String type = pluginSettings.get(TYPE_KEY);
        if (type == null || type.isEmpty()) {
            throw new IllegalArgumentException("Authorization plugin at index " + index + " missing required 'type' field");
        }

        boolean enabled = pluginSettings.getAsBoolean(ENABLED_KEY, true);

        // Parse plugin-specific settings
        Settings configSettings = pluginSettings.getByPrefix(CONFIG_KEY + ".");
        Map<String, Object> settings = settingsToMap(configSettings);

        return new AuthorizationPluginConfig(type, enabled, settings);
    }

    /**
     * Converts OpenSearch Settings to a Map for plugin-specific configuration.
     */
    private Map<String, Object> settingsToMap(Settings settings) {
        if (settings.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, Object> map = new java.util.HashMap<>();
        for (String key : settings.keySet()) {
            String value = settings.get(key);
            map.put(key, value);
        }
        return map;
    }
}
