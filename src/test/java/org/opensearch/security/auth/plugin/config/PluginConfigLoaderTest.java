/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for PluginConfigLoader.
 */
public class PluginConfigLoaderTest {

    private PluginConfigLoader loader;

    @Before
    public void setUp() {
        loader = new PluginConfigLoader();
    }

    @Test
    public void testLoadAuthenticationPlugins_Empty() {
        Settings settings = Settings.builder().build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertNotNull(configs);
        assertTrue(configs.isEmpty());
    }

    @Test
    public void testLoadAuthenticationPlugins_SinglePlugin() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(1, configs.size());
        AuthenticationPluginConfig config = configs.get(0);
        assertEquals("internal", config.getType());
        assertTrue(config.isEnabled());
        assertEquals(1, config.getOrder());
    }

    @Test
    public void testLoadAuthenticationPlugins_MultiplePlugins() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 2)
            .put("plugins.security.authentication.1.config.host", "ldap.example.com")
            .put("plugins.security.authentication.2.type", "saml")
            .put("plugins.security.authentication.2.enabled", true)
            .put("plugins.security.authentication.2.order", 3)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(3, configs.size());
        
        // Verify ordering
        assertEquals("internal", configs.get(0).getType());
        assertEquals(1, configs.get(0).getOrder());
        
        assertEquals("ldap", configs.get(1).getType());
        assertEquals(2, configs.get(1).getOrder());
        assertEquals("ldap.example.com", configs.get(1).getSettings().get("host"));
        
        assertEquals("saml", configs.get(2).getType());
        assertEquals(3, configs.get(2).getOrder());
    }

    @Test
    public void testLoadAuthenticationPlugins_DisabledPluginFiltered() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", false)
            .put("plugins.security.authentication.1.order", 2)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        // Only enabled plugin should be returned
        assertEquals(1, configs.size());
        assertEquals("internal", configs.get(0).getType());
    }

    @Test
    public void testLoadAuthenticationPlugins_OrderSorting() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "saml")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 3)
            .put("plugins.security.authentication.1.type", "internal")
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 1)
            .put("plugins.security.authentication.2.type", "ldap")
            .put("plugins.security.authentication.2.enabled", true)
            .put("plugins.security.authentication.2.order", 2)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        // Should be sorted by order
        assertEquals(3, configs.size());
        assertEquals("internal", configs.get(0).getType());
        assertEquals("ldap", configs.get(1).getType());
        assertEquals("saml", configs.get(2).getType());
    }

    @Test
    public void testLoadAuthenticationPlugins_WithSettings() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "ldap")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.0.config.host", "ldap.example.com")
            .put("plugins.security.authentication.0.config.port", "389")
            .put("plugins.security.authentication.0.config.bind_dn", "cn=admin,dc=example,dc=com")
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(1, configs.size());
        AuthenticationPluginConfig config = configs.get(0);
        assertEquals("ldap", config.getType());
        assertEquals("ldap.example.com", config.getSettings().get("host"));
        assertEquals("389", config.getSettings().get("port"));
        assertEquals("cn=admin,dc=example,dc=com", config.getSettings().get("bind_dn"));
    }

    @Test
    public void testLoadAuthorizationPlugins_Empty() {
        Settings settings = Settings.builder().build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        assertNotNull(configs);
        assertTrue(configs.isEmpty());
    }

    @Test
    public void testLoadAuthorizationPlugins_SinglePlugin() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        assertEquals(1, configs.size());
        AuthorizationPluginConfig config = configs.get(0);
        assertEquals("role_based", config.getType());
        assertTrue(config.isEnabled());
    }

    @Test
    public void testLoadAuthorizationPlugins_MultiplePlugins() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .put("plugins.security.authorization.1.type", "custom")
            .put("plugins.security.authorization.1.enabled", true)
            .put("plugins.security.authorization.1.config.policy_file", "/etc/policies.json")
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        assertEquals(2, configs.size());
        assertEquals("role_based", configs.get(0).getType());
        assertEquals("custom", configs.get(1).getType());
        assertEquals("/etc/policies.json", configs.get(1).getSettings().get("policy_file"));
    }

    @Test
    public void testLoadAuthorizationPlugins_DisabledPluginFiltered() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .put("plugins.security.authorization.1.type", "custom")
            .put("plugins.security.authorization.1.enabled", false)
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        // Only enabled plugin should be returned
        assertEquals(1, configs.size());
        assertEquals("role_based", configs.get(0).getType());
    }

    @Test
    public void testLoadAuthorizationPlugins_WithSettings() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .put("plugins.security.authorization.0.config.roles_mapping.admin", "Admins")
            .put("plugins.security.authorization.0.config.roles_mapping.developer", "Developers")
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        assertEquals(1, configs.size());
        AuthorizationPluginConfig config = configs.get(0);
        assertEquals("role_based", config.getType());
        assertFalse(config.getSettings().isEmpty());
    }

    @Test
    public void testLoadAuthenticationPlugins_DefaultEnabledTrue() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.order", 1)
            // enabled not specified, should default to true
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(1, configs.size());
        assertTrue(configs.get(0).isEnabled());
    }

    @Test
    public void testLoadAuthorizationPlugins_DefaultEnabledTrue() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            // enabled not specified, should default to true
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        assertEquals(1, configs.size());
        assertTrue(configs.get(0).isEnabled());
    }

    @Test
    public void testLoadAuthenticationPlugins_InvalidConfigSkipped() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            // Missing type for plugin 1 - should be skipped
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 2)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        // Only valid plugin should be loaded
        assertEquals(1, configs.size());
        assertEquals("internal", configs.get(0).getType());
    }

    @Test
    public void testLoadAuthorizationPlugins_InvalidConfigSkipped() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            // Missing type for plugin 1 - should be skipped
            .put("plugins.security.authorization.1.enabled", true)
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        // Only valid plugin should be loaded
        assertEquals(1, configs.size());
        assertEquals("role_based", configs.get(0).getType());
    }
}
