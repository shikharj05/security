/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates plugin configurations for correctness and consistency.
 */
public class PluginConfigValidator {

    /**
     * Validates a list of authentication plugin configurations.
     *
     * @param configs The configurations to validate
     * @throws PluginConfigValidationException if validation fails
     */
    public void validateAuthenticationConfigs(List<AuthenticationPluginConfig> configs) throws PluginConfigValidationException {
        if (configs == null || configs.isEmpty()) {
            return; // Empty configuration is valid
        }

        List<String> errors = new ArrayList<>();
        Set<String> seenTypes = new HashSet<>();
        Set<Integer> seenOrders = new HashSet<>();

        for (int i = 0; i < configs.size(); i++) {
            AuthenticationPluginConfig config = configs.get(i);

            // Validate type
            if (config.getType() == null || config.getType().trim().isEmpty()) {
                errors.add("Configuration at index " + i + ": type cannot be null or empty");
            } else {
                // Check for duplicate types
                if (seenTypes.contains(config.getType())) {
                    errors.add("Configuration at index " + i + ": duplicate plugin type '" + config.getType() + "'");
                }
                seenTypes.add(config.getType());
            }

            // Validate order
            if (config.getOrder() < 0) {
                errors.add("Configuration at index " + i + ": order must be non-negative, got " + config.getOrder());
            } else {
                // Check for duplicate orders among enabled plugins
                if (config.isEnabled() && seenOrders.contains(config.getOrder())) {
                    errors.add(
                        "Configuration at index " + i + ": duplicate order " + config.getOrder() + " among enabled plugins"
                    );
                }
                if (config.isEnabled()) {
                    seenOrders.add(config.getOrder());
                }
            }

            // Validate settings
            if (config.getSettings() != null) {
                validateSettings(config.getSettings(), "Configuration at index " + i, errors);
            }
        }

        if (!errors.isEmpty()) {
            throw new PluginConfigValidationException("Authentication plugin configuration validation failed", errors);
        }
    }

    /**
     * Validates a list of authorization plugin configurations.
     *
     * @param configs The configurations to validate
     * @throws PluginConfigValidationException if validation fails
     */
    public void validateAuthorizationConfigs(List<AuthorizationPluginConfig> configs) throws PluginConfigValidationException {
        if (configs == null || configs.isEmpty()) {
            return; // Empty configuration is valid
        }

        List<String> errors = new ArrayList<>();
        Set<String> seenTypes = new HashSet<>();

        for (int i = 0; i < configs.size(); i++) {
            AuthorizationPluginConfig config = configs.get(i);

            // Validate type
            if (config.getType() == null || config.getType().trim().isEmpty()) {
                errors.add("Configuration at index " + i + ": type cannot be null or empty");
            } else {
                // Check for duplicate types
                if (seenTypes.contains(config.getType())) {
                    errors.add("Configuration at index " + i + ": duplicate plugin type '" + config.getType() + "'");
                }
                seenTypes.add(config.getType());
            }

            // Validate settings
            if (config.getSettings() != null) {
                validateSettings(config.getSettings(), "Configuration at index " + i, errors);
            }
        }

        if (!errors.isEmpty()) {
            throw new PluginConfigValidationException("Authorization plugin configuration validation failed", errors);
        }
    }

    /**
     * Validates plugin settings for basic correctness.
     *
     * @param settings The settings map to validate
     * @param context Context string for error messages
     * @param errors List to accumulate error messages
     */
    private void validateSettings(Map<String, Object> settings, String context, List<String> errors) {
        for (Map.Entry<String, Object> entry : settings.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Validate key
            if (key == null || key.trim().isEmpty()) {
                errors.add(context + ": settings key cannot be null or empty");
                continue;
            }

            // Validate value types (basic validation)
            if (value != null && !isValidSettingValue(value)) {
                errors.add(
                    context
                        + ": settings value for key '"
                        + key
                        + "' has unsupported type: "
                        + value.getClass().getSimpleName()
                );
            }
        }
    }

    /**
     * Checks if a value is a valid setting type.
     *
     * @param value The value to check
     * @return true if valid, false otherwise
     */
    private boolean isValidSettingValue(Object value) {
        return value instanceof String
            || value instanceof Number
            || value instanceof Boolean
            || value instanceof Map
            || value instanceof List;
    }
}
