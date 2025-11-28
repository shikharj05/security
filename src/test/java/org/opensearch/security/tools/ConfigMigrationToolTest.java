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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import static org.junit.Assert.*;

/**
 * Tests for ConfigMigrationTool.
 */
public class ConfigMigrationToolTest {

    private ConfigMigrationTool tool;
    private Path tempDir;

    @Before
    public void setUp() throws IOException {
        tool = new ConfigMigrationTool();
        tempDir = Files.createTempDirectory("config-migration-test");
    }

    @After
    public void tearDown() throws IOException {
        // Clean up temp directory
        if (tempDir != null && Files.exists(tempDir)) {
            Files.walk(tempDir)
                .sorted((a, b) -> b.compareTo(a))
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        // Ignore
                    }
                });
        }
    }

    @Test
    public void testMigrateInternalAuthenticationDomain() {
        Map<String, Object> oldConfig = createOldConfigWithInternalAuth();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authentication"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authentication");
        assertNotNull(authPlugins);
        assertEquals(1, authPlugins.size());

        Map<String, Object> plugin = authPlugins.get(0);
        assertEquals("internal", plugin.get("type"));
        assertEquals(true, plugin.get("enabled"));
        assertEquals(4, plugin.get("order"));
    }

    @Test
    public void testMigrateLDAPAuthenticationDomain() {
        Map<String, Object> oldConfig = createOldConfigWithLDAPAuth();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authentication"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authentication");
        assertNotNull(authPlugins);
        assertEquals(1, authPlugins.size());

        Map<String, Object> plugin = authPlugins.get(0);
        assertEquals("ldap", plugin.get("type"));
        assertEquals(true, plugin.get("enabled"));
        assertEquals(5, plugin.get("order"));

        @SuppressWarnings("unchecked")
        Map<String, Object> config = (Map<String, Object>) plugin.get("config");
        assertNotNull(config);
        assertEquals("localhost:8389", config.get("hosts"));
        assertEquals("ou=people,dc=example,dc=com", config.get("userbase"));
        assertEquals("(sAMAccountName={0})", config.get("usersearch"));

        // Check claims mapping was added
        @SuppressWarnings("unchecked")
        Map<String, String> claimsMapping = (Map<String, String>) config.get("claims_mapping");
        assertNotNull(claimsMapping);
        assertEquals("memberOf", claimsMapping.get("groups"));
        assertEquals("mail", claimsMapping.get("email"));
    }

    @Test
    public void testMigrateLDAPAuthorizationBackend() {
        Map<String, Object> oldConfig = createOldConfigWithLDAPAuthz();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authorization"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authzPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authorization");
        assertNotNull(authzPlugins);
        assertEquals(1, authzPlugins.size());

        Map<String, Object> plugin = authzPlugins.get(0);
        assertEquals("ldap", plugin.get("type"));
        assertEquals(true, plugin.get("enabled"));

        @SuppressWarnings("unchecked")
        Map<String, Object> config = (Map<String, Object>) plugin.get("config");
        assertNotNull(config);
        assertEquals("localhost:8389", config.get("hosts"));
        assertEquals("ou=groups,dc=example,dc=com", config.get("rolebase"));
        assertEquals("(member={0})", config.get("rolesearch"));
        assertEquals("cn", config.get("rolename"));
        assertEquals(true, config.get("resolve_nested_roles"));
    }

    @Test
    public void testMigrateMultipleAuthenticationDomains() {
        Map<String, Object> oldConfig = createOldConfigWithMultipleAuthDomains();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authentication"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authentication");
        assertNotNull(authPlugins);
        assertEquals(2, authPlugins.size());

        // Check internal auth plugin
        Map<String, Object> internalPlugin = authPlugins.get(0);
        assertEquals("internal", internalPlugin.get("type"));
        assertEquals(true, internalPlugin.get("enabled"));

        // Check LDAP auth plugin
        Map<String, Object> ldapPlugin = authPlugins.get(1);
        assertEquals("ldap", ldapPlugin.get("type"));
        assertEquals(true, ldapPlugin.get("enabled"));
    }

    @Test
    public void testMigrateDisabledDomain() {
        Map<String, Object> oldConfig = createOldConfigWithDisabledDomain();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authentication"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authentication");
        assertNotNull(authPlugins);
        assertEquals(1, authPlugins.size());

        Map<String, Object> plugin = authPlugins.get(0);
        assertEquals("internal", plugin.get("type"));
        assertEquals(false, plugin.get("enabled"));
    }

    @Test
    public void testValidateValidConfiguration() {
        Map<String, Object> config = createValidNewConfig();
        
        // Should not throw exception
        tool.validateConfiguration(config);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateMissingType() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> plugin = new HashMap<>();
        plugin.put("enabled", true);
        config.put("plugins.security.authentication", List.of(plugin));

        tool.validateConfiguration(config);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateEmptyType() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> plugin = new HashMap<>();
        plugin.put("type", "");
        plugin.put("enabled", true);
        config.put("plugins.security.authentication", List.of(plugin));

        tool.validateConfiguration(config);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateMissingEnabled() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> plugin = new HashMap<>();
        plugin.put("type", "internal");
        config.put("plugins.security.authentication", List.of(plugin));

        tool.validateConfiguration(config);
    }

    @Test
    public void testMigrateConfigurationFile() throws IOException {
        // Create old config file
        Path oldConfigPath = tempDir.resolve("old-config.yml");
        Map<String, Object> oldConfig = createOldConfigWithInternalAuth();
        Yaml yaml = new Yaml();
        Files.writeString(oldConfigPath, yaml.dump(oldConfig));

        // Migrate
        Path newConfigPath = tempDir.resolve("new-config.yml");
        tool.migrateConfiguration(oldConfigPath.toString(), newConfigPath.toString());

        // Verify new config file exists
        assertTrue(Files.exists(newConfigPath));

        // Read and verify new config
        Map<String, Object> newConfig = yaml.load(Files.newBufferedReader(newConfigPath));
        assertNotNull(newConfig);
        assertTrue(newConfig.containsKey("plugins.security.authentication"));
    }

    @Test(expected = IOException.class)
    public void testMigrateNonExistentFile() throws IOException {
        Path oldConfigPath = tempDir.resolve("non-existent.yml");
        Path newConfigPath = tempDir.resolve("new-config.yml");
        tool.migrateConfiguration(oldConfigPath.toString(), newConfigPath.toString());
    }

    @Test
    public void testPreserveDescription() {
        Map<String, Object> oldConfig = createOldConfigWithDescription();
        Map<String, Object> newConfig = tool.migrateConfig(oldConfig);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> authPlugins = (List<Map<String, Object>>) newConfig.get("plugins.security.authentication");
        assertNotNull(authPlugins);
        assertEquals(1, authPlugins.size());

        Map<String, Object> plugin = authPlugins.get(0);
        assertEquals("Authenticate via HTTP Basic against internal users database", plugin.get("_comment"));
    }

    // Helper methods to create test configurations

    private Map<String, Object> createOldConfigWithInternalAuth() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authc = new LinkedHashMap<>();
        Map<String, Object> domain = new LinkedHashMap<>();

        domain.put("http_enabled", true);
        domain.put("transport_enabled", true);
        domain.put("order", 4);

        Map<String, Object> authBackend = new LinkedHashMap<>();
        authBackend.put("type", "intern");
        domain.put("authentication_backend", authBackend);

        authc.put("basic_internal_auth_domain", domain);
        dynamic.put("authc", authc);

        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createOldConfigWithLDAPAuth() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authc = new LinkedHashMap<>();
        Map<String, Object> domain = new LinkedHashMap<>();

        domain.put("http_enabled", true);
        domain.put("transport_enabled", true);
        domain.put("order", 5);

        Map<String, Object> authBackend = new LinkedHashMap<>();
        authBackend.put("type", "ldap");

        Map<String, Object> backendConfig = new LinkedHashMap<>();
        backendConfig.put("hosts", "localhost:8389");
        backendConfig.put("userbase", "ou=people,dc=example,dc=com");
        backendConfig.put("usersearch", "(sAMAccountName={0})");
        backendConfig.put("enable_ssl", false);
        authBackend.put("config", backendConfig);

        domain.put("authentication_backend", authBackend);
        authc.put("ldap", domain);
        dynamic.put("authc", authc);

        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createOldConfigWithLDAPAuthz() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authz = new LinkedHashMap<>();
        Map<String, Object> backend = new LinkedHashMap<>();

        backend.put("http_enabled", true);
        backend.put("transport_enabled", true);

        Map<String, Object> authzBackend = new LinkedHashMap<>();
        authzBackend.put("type", "ldap");

        Map<String, Object> backendConfig = new LinkedHashMap<>();
        backendConfig.put("hosts", "localhost:8389");
        backendConfig.put("rolebase", "ou=groups,dc=example,dc=com");
        backendConfig.put("rolesearch", "(member={0})");
        backendConfig.put("rolename", "cn");
        backendConfig.put("resolve_nested_roles", true);
        authzBackend.put("config", backendConfig);

        backend.put("authorization_backend", authzBackend);
        authz.put("roles_from_myldap", backend);
        dynamic.put("authz", authz);

        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createOldConfigWithMultipleAuthDomains() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authc = new LinkedHashMap<>();

        // Internal auth domain
        Map<String, Object> internalDomain = new LinkedHashMap<>();
        internalDomain.put("http_enabled", true);
        internalDomain.put("transport_enabled", true);
        internalDomain.put("order", 1);
        Map<String, Object> internalBackend = new LinkedHashMap<>();
        internalBackend.put("type", "intern");
        internalDomain.put("authentication_backend", internalBackend);
        authc.put("internal", internalDomain);

        // LDAP auth domain
        Map<String, Object> ldapDomain = new LinkedHashMap<>();
        ldapDomain.put("http_enabled", true);
        ldapDomain.put("transport_enabled", true);
        ldapDomain.put("order", 2);
        Map<String, Object> ldapBackend = new LinkedHashMap<>();
        ldapBackend.put("type", "ldap");
        ldapDomain.put("authentication_backend", ldapBackend);
        authc.put("ldap", ldapDomain);

        dynamic.put("authc", authc);
        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createOldConfigWithDisabledDomain() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authc = new LinkedHashMap<>();
        Map<String, Object> domain = new LinkedHashMap<>();

        domain.put("http_enabled", false);
        domain.put("transport_enabled", false);
        domain.put("order", 1);

        Map<String, Object> authBackend = new LinkedHashMap<>();
        authBackend.put("type", "intern");
        domain.put("authentication_backend", authBackend);

        authc.put("internal", domain);
        dynamic.put("authc", authc);

        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createOldConfigWithDescription() {
        Map<String, Object> config = new LinkedHashMap<>();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        Map<String, Object> authc = new LinkedHashMap<>();
        Map<String, Object> domain = new LinkedHashMap<>();

        domain.put("description", "Authenticate via HTTP Basic against internal users database");
        domain.put("http_enabled", true);
        domain.put("transport_enabled", true);
        domain.put("order", 1);

        Map<String, Object> authBackend = new LinkedHashMap<>();
        authBackend.put("type", "intern");
        domain.put("authentication_backend", authBackend);

        authc.put("internal", domain);
        dynamic.put("authc", authc);

        Map<String, Object> configSection = new LinkedHashMap<>();
        configSection.put("dynamic", dynamic);
        config.put("config", configSection);

        return config;
    }

    private Map<String, Object> createValidNewConfig() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> plugin = new HashMap<>();
        plugin.put("type", "internal");
        plugin.put("enabled", true);
        config.put("plugins.security.authentication", List.of(plugin));
        return config;
    }
}
