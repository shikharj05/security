/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.tools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

/**
 * Tool to migrate old authentication/authorization backend configurations
 * to the new plugin-based configuration format.
 */
public class ConfigMigrationTool {

    private static final String OLD_AUTHC_KEY = "config.dynamic.authc";
    private static final String OLD_AUTHZ_KEY = "config.dynamic.authz";
    private static final String NEW_AUTHN_KEY = "plugins.security.authentication";
    private static final String NEW_AUTHZ_KEY = "plugins.security.authorization";

    /**
     * Migrates an old configuration file to the new plugin format.
     *
     * @param oldConfigPath Path to the old config.yml file
     * @param newConfigPath Path where the new configuration should be written
     * @throws IOException if file operations fail
     */
    public void migrateConfiguration(String oldConfigPath, String newConfigPath) throws IOException {
        Path oldPath = Paths.get(oldConfigPath);
        Path newPath = Paths.get(newConfigPath);

        if (!Files.exists(oldPath)) {
            throw new IOException("Old configuration file not found: " + oldConfigPath);
        }

        // Read old configuration
        Yaml yaml = new Yaml();
        Map<String, Object> oldConfig = yaml.load(Files.newBufferedReader(oldPath));

        // Migrate to new format
        Map<String, Object> newConfig = migrateConfig(oldConfig);

        // Validate new configuration
        validateConfiguration(newConfig);

        // Write new configuration
        String output = yaml.dump(newConfig);
        Files.writeString(newPath, output);
    }

    /**
     * Migrates configuration from old format to new format.
     *
     * @param oldConfig Old configuration map
     * @return New configuration map
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> migrateConfig(Map<String, Object> oldConfig) {
        Map<String, Object> newConfig = new LinkedHashMap<>();

        // Extract authentication domains
        Map<String, Object> authcDomains = extractNestedMap(oldConfig, "config", "dynamic", "authc");
        if (authcDomains != null && !authcDomains.isEmpty()) {
            List<Map<String, Object>> authPlugins = migrateAuthenticationDomains(authcDomains);
            newConfig.put(NEW_AUTHN_KEY, authPlugins);
        }

        // Extract authorization backends
        Map<String, Object> authzBackends = extractNestedMap(oldConfig, "config", "dynamic", "authz");
        if (authzBackends != null && !authzBackends.isEmpty()) {
            List<Map<String, Object>> authzPlugins = migrateAuthorizationBackends(authzBackends);
            newConfig.put(NEW_AUTHZ_KEY, authzPlugins);
        }

        return newConfig;
    }

    /**
     * Migrates authentication domains to authentication plugins.
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> migrateAuthenticationDomains(Map<String, Object> authcDomains) {
        List<Map<String, Object>> plugins = new ArrayList<>();

        for (Map.Entry<String, Object> entry : authcDomains.entrySet()) {
            String domainName = entry.getKey();
            Map<String, Object> domain = (Map<String, Object>) entry.getValue();

            Map<String, Object> plugin = new LinkedHashMap<>();

            // Extract authentication backend type
            Map<String, Object> authBackend = (Map<String, Object>) domain.get("authentication_backend");
            if (authBackend == null) {
                continue;
            }

            String backendType = (String) authBackend.get("type");
            if (backendType == null) {
                continue;
            }

            // Map old backend types to new plugin types
            String pluginType = mapAuthenticationBackendType(backendType);
            plugin.put("type", pluginType);

            // Extract enabled status (default to true if http_enabled or transport_enabled is true)
            Boolean httpEnabled = (Boolean) domain.get("http_enabled");
            Boolean transportEnabled = (Boolean) domain.get("transport_enabled");
            boolean enabled = (httpEnabled != null && httpEnabled) || (transportEnabled != null && transportEnabled);
            plugin.put("enabled", enabled);

            // Extract order
            Integer order = (Integer) domain.get("order");
            if (order != null) {
                plugin.put("order", order);
            }

            // Extract configuration
            Map<String, Object> backendConfig = (Map<String, Object>) authBackend.get("config");
            if (backendConfig != null && !backendConfig.isEmpty()) {
                Map<String, Object> pluginConfig = migrateAuthenticationConfig(backendType, backendConfig);
                if (!pluginConfig.isEmpty()) {
                    plugin.put("config", pluginConfig);
                }
            }

            // Add description as comment (stored in config for reference)
            String description = (String) domain.get("description");
            if (description != null) {
                plugin.put("_comment", description);
            }

            plugins.add(plugin);
        }

        return plugins;
    }

    /**
     * Migrates authorization backends to authorization plugins.
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> migrateAuthorizationBackends(Map<String, Object> authzBackends) {
        List<Map<String, Object>> plugins = new ArrayList<>();

        for (Map.Entry<String, Object> entry : authzBackends.entrySet()) {
            String backendName = entry.getKey();
            Map<String, Object> backend = (Map<String, Object>) entry.getValue();

            Map<String, Object> plugin = new LinkedHashMap<>();

            // Extract authorization backend
            Map<String, Object> authzBackend = (Map<String, Object>) backend.get("authorization_backend");
            if (authzBackend == null) {
                continue;
            }

            String backendType = (String) authzBackend.get("type");
            if (backendType == null) {
                continue;
            }

            // Map old backend types to new plugin types
            String pluginType = mapAuthorizationBackendType(backendType);
            plugin.put("type", pluginType);

            // Extract enabled status
            Boolean httpEnabled = (Boolean) backend.get("http_enabled");
            Boolean transportEnabled = (Boolean) backend.get("transport_enabled");
            boolean enabled = (httpEnabled != null && httpEnabled) || (transportEnabled != null && transportEnabled);
            plugin.put("enabled", enabled);

            // Extract configuration
            Map<String, Object> backendConfig = (Map<String, Object>) authzBackend.get("config");
            if (backendConfig != null && !backendConfig.isEmpty()) {
                Map<String, Object> pluginConfig = migrateAuthorizationConfig(backendType, backendConfig);
                if (!pluginConfig.isEmpty()) {
                    plugin.put("config", pluginConfig);
                }
            }

            // Add description as comment
            String description = (String) backend.get("description");
            if (description != null) {
                plugin.put("_comment", description);
            }

            plugins.add(plugin);
        }

        return plugins;
    }

    /**
     * Maps old authentication backend types to new plugin types.
     */
    private String mapAuthenticationBackendType(String oldType) {
        switch (oldType.toLowerCase()) {
            case "intern":
            case "internal":
                return "internal";
            case "ldap":
                return "ldap";
            case "noop":
                return "noop";
            default:
                return oldType;
        }
    }

    /**
     * Maps old authorization backend types to new plugin types.
     */
    private String mapAuthorizationBackendType(String oldType) {
        switch (oldType.toLowerCase()) {
            case "ldap":
                return "ldap";
            case "noop":
                return "noop";
            default:
                return "role_based";
        }
    }

    /**
     * Migrates authentication backend configuration.
     */
    private Map<String, Object> migrateAuthenticationConfig(String backendType, Map<String, Object> oldConfig) {
        Map<String, Object> newConfig = new LinkedHashMap<>();

        if ("ldap".equalsIgnoreCase(backendType)) {
            // Migrate LDAP configuration
            copyIfPresent(oldConfig, newConfig, "hosts");
            copyIfPresent(oldConfig, newConfig, "bind_dn");
            copyIfPresent(oldConfig, newConfig, "password");
            copyIfPresent(oldConfig, newConfig, "userbase");
            copyIfPresent(oldConfig, newConfig, "usersearch");
            copyIfPresent(oldConfig, newConfig, "username_attribute");
            copyIfPresent(oldConfig, newConfig, "enable_ssl");
            copyIfPresent(oldConfig, newConfig, "enable_start_tls");
            copyIfPresent(oldConfig, newConfig, "enable_ssl_client_auth");
            copyIfPresent(oldConfig, newConfig, "verify_hostnames");

            // Add claims mapping for LDAP
            Map<String, String> claimsMapping = new LinkedHashMap<>();
            claimsMapping.put("groups", "memberOf");
            claimsMapping.put("email", "mail");
            newConfig.put("claims_mapping", claimsMapping);
        }

        return newConfig;
    }

    /**
     * Migrates authorization backend configuration.
     */
    private Map<String, Object> migrateAuthorizationConfig(String backendType, Map<String, Object> oldConfig) {
        Map<String, Object> newConfig = new LinkedHashMap<>();

        if ("ldap".equalsIgnoreCase(backendType)) {
            // Migrate LDAP authorization configuration
            copyIfPresent(oldConfig, newConfig, "hosts");
            copyIfPresent(oldConfig, newConfig, "bind_dn");
            copyIfPresent(oldConfig, newConfig, "password");
            copyIfPresent(oldConfig, newConfig, "rolebase");
            copyIfPresent(oldConfig, newConfig, "rolesearch");
            copyIfPresent(oldConfig, newConfig, "userroleattribute");
            copyIfPresent(oldConfig, newConfig, "userrolename");
            copyIfPresent(oldConfig, newConfig, "rolename");
            copyIfPresent(oldConfig, newConfig, "resolve_nested_roles");
            copyIfPresent(oldConfig, newConfig, "userbase");
            copyIfPresent(oldConfig, newConfig, "usersearch");
            copyIfPresent(oldConfig, newConfig, "enable_ssl");
            copyIfPresent(oldConfig, newConfig, "enable_start_tls");
            copyIfPresent(oldConfig, newConfig, "enable_ssl_client_auth");
            copyIfPresent(oldConfig, newConfig, "verify_hostnames");
        }

        return newConfig;
    }

    /**
     * Validates the migrated configuration.
     */
    @SuppressWarnings("unchecked")
    public void validateConfiguration(Map<String, Object> config) throws IllegalArgumentException {
        // Validate authentication plugins
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) config.get(NEW_AUTHN_KEY);
        if (authPlugins != null) {
            for (Map<String, Object> plugin : authPlugins) {
                validateAuthenticationPlugin(plugin);
            }
        }

        // Validate authorization plugins
        List<Map<String, Object>> authzPlugins = (List<Map<String, Object>>) config.get(NEW_AUTHZ_KEY);
        if (authzPlugins != null) {
            for (Map<String, Object> plugin : authzPlugins) {
                validateAuthorizationPlugin(plugin);
            }
        }
    }

    /**
     * Validates an authentication plugin configuration.
     */
    private void validateAuthenticationPlugin(Map<String, Object> plugin) {
        if (!plugin.containsKey("type")) {
            throw new IllegalArgumentException("Authentication plugin missing required 'type' field");
        }

        String type = (String) plugin.get("type");
        if (type == null || type.trim().isEmpty()) {
            throw new IllegalArgumentException("Authentication plugin 'type' cannot be empty");
        }

        if (!plugin.containsKey("enabled")) {
            throw new IllegalArgumentException("Authentication plugin missing required 'enabled' field");
        }
    }

    /**
     * Validates an authorization plugin configuration.
     */
    private void validateAuthorizationPlugin(Map<String, Object> plugin) {
        if (!plugin.containsKey("type")) {
            throw new IllegalArgumentException("Authorization plugin missing required 'type' field");
        }

        String type = (String) plugin.get("type");
        if (type == null || type.trim().isEmpty()) {
            throw new IllegalArgumentException("Authorization plugin 'type' cannot be empty");
        }

        if (!plugin.containsKey("enabled")) {
            throw new IllegalArgumentException("Authorization plugin missing required 'enabled' field");
        }
    }

    /**
     * Extracts a nested map from a configuration.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractNestedMap(Map<String, Object> config, String... keys) {
        Map<String, Object> current = config;
        for (String key : keys) {
            if (current == null) {
                return null;
            }
            Object value = current.get(key);
            if (value instanceof Map) {
                current = (Map<String, Object>) value;
            } else {
                return null;
            }
        }
        return current;
    }

    /**
     * Copies a value from old config to new config if present.
     */
    private void copyIfPresent(Map<String, Object> oldConfig, Map<String, Object> newConfig, String key) {
        copyIfPresent(oldConfig, newConfig, key, key);
    }

    /**
     * Copies a value from old config to new config with a different key if present.
     */
    private void copyIfPresent(Map<String, Object> oldConfig, Map<String, Object> newConfig, String oldKey, String newKey) {
        if (oldConfig.containsKey(oldKey)) {
            newConfig.put(newKey, oldConfig.get(oldKey));
        }
    }

    /**
     * Main method for CLI usage.
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: ConfigMigrationTool <old-config-path> <new-config-path>");
            System.err.println();
            System.err.println("Migrates old authentication/authorization backend configurations");
            System.err.println("to the new plugin-based configuration format.");
            System.err.println();
            System.err.println("Arguments:");
            System.err.println("  old-config-path  Path to the old config.yml file");
            System.err.println("  new-config-path  Path where the new configuration should be written");
            System.exit(1);
        }

        String oldConfigPath = args[0];
        String newConfigPath = args[1];

        ConfigMigrationTool tool = new ConfigMigrationTool();
        try {
            tool.migrateConfiguration(oldConfigPath, newConfigPath);
            System.out.println("Configuration migrated successfully!");
            System.out.println("Old configuration: " + oldConfigPath);
            System.out.println("New configuration: " + newConfigPath);
            System.out.println();
            System.out.println("Please review the new configuration before using it in production.");
        } catch (Exception e) {
            System.err.println("Error migrating configuration: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
