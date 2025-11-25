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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests for PluginConfigLoader with realistic configuration scenarios.
 */
public class PluginConfigLoaderIntegrationTest {

    private PluginConfigLoader loader;

    @Before
    public void setUp() {
        loader = new PluginConfigLoader();
    }

    @Test
    public void testLoadCompleteAuthenticationConfiguration() {
        // Simulates a complete authentication configuration with multiple plugins
        Settings settings = Settings.builder()
            // Internal authentication plugin
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            
            // LDAP authentication plugin
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 2)
            .put("plugins.security.authentication.1.config.host", "ldap.example.com")
            .put("plugins.security.authentication.1.config.bind_dn", "cn=admin,dc=example,dc=com")
            .put("plugins.security.authentication.1.config.claims_mapping.groups", "memberOf")
            .put("plugins.security.authentication.1.config.claims_mapping.email", "mail")
            
            // SAML authentication plugin
            .put("plugins.security.authentication.2.type", "saml")
            .put("plugins.security.authentication.2.enabled", true)
            .put("plugins.security.authentication.2.order", 3)
            .put("plugins.security.authentication.2.config.idp_metadata_url", "https://idp.example.com/metadata")
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(3, configs.size());
        
        // Verify internal plugin
        AuthenticationPluginConfig internalConfig = configs.get(0);
        assertEquals("internal", internalConfig.getType());
        assertEquals(1, internalConfig.getOrder());
        assertTrue(internalConfig.isEnabled());
        
        // Verify LDAP plugin
        AuthenticationPluginConfig ldapConfig = configs.get(1);
        assertEquals("ldap", ldapConfig.getType());
        assertEquals(2, ldapConfig.getOrder());
        assertEquals("ldap.example.com", ldapConfig.getSettings().get("host"));
        assertEquals("cn=admin,dc=example,dc=com", ldapConfig.getSettings().get("bind_dn"));
        
        // Verify SAML plugin
        AuthenticationPluginConfig samlConfig = configs.get(2);
        assertEquals("saml", samlConfig.getType());
        assertEquals(3, samlConfig.getOrder());
        assertEquals("https://idp.example.com/metadata", samlConfig.getSettings().get("idp_metadata_url"));
    }

    @Test
    public void testLoadCompleteAuthorizationConfiguration() {
        // Simulates a complete authorization configuration
        Settings settings = Settings.builder()
            // Role-based authorization plugin
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .put("plugins.security.authorization.0.config.roles_mapping.admin", "Admins")
            .put("plugins.security.authorization.0.config.roles_mapping.developer", "Developers")
            
            // Custom authorization plugin (disabled)
            .put("plugins.security.authorization.1.type", "custom")
            .put("plugins.security.authorization.1.enabled", false)
            .put("plugins.security.authorization.1.config.policy_file", "/etc/policies.json")
            .build();

        List<AuthorizationPluginConfig> configs = loader.loadAuthorizationPlugins(settings);

        // Only enabled plugin should be returned
        assertEquals(1, configs.size());
        
        AuthorizationPluginConfig roleBasedConfig = configs.get(0);
        assertEquals("role_based", roleBasedConfig.getType());
        assertTrue(roleBasedConfig.isEnabled());
        assertNotNull(roleBasedConfig.getSettings());
    }

    @Test
    public void testLoadMixedAuthenticationAndAuthorizationConfiguration() {
        // Simulates a configuration with both authentication and authorization plugins
        Settings settings = Settings.builder()
            // Authentication plugins
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 2)
            
            // Authorization plugins
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .build();

        List<AuthenticationPluginConfig> authConfigs = loader.loadAuthenticationPlugins(settings);
        List<AuthorizationPluginConfig> authzConfigs = loader.loadAuthorizationPlugins(settings);

        assertEquals(2, authConfigs.size());
        assertEquals(1, authzConfigs.size());
        
        assertEquals("internal", authConfigs.get(0).getType());
        assertEquals("ldap", authConfigs.get(1).getType());
        assertEquals("role_based", authzConfigs.get(0).getType());
    }

    @Test
    public void testLoadConfigurationWithPartiallyDisabledPlugins() {
        // Simulates a configuration where some plugins are disabled
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", false)
            .put("plugins.security.authentication.1.order", 2)
            
            .put("plugins.security.authentication.2.type", "saml")
            .put("plugins.security.authentication.2.enabled", true)
            .put("plugins.security.authentication.2.order", 3)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        // Only enabled plugins should be returned
        assertEquals(2, configs.size());
        assertEquals("internal", configs.get(0).getType());
        assertEquals("saml", configs.get(1).getType());
    }

    @Test
    public void testLoadConfigurationWithComplexSettings() {
        // Simulates a configuration with complex nested settings
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "ldap")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.0.config.host", "ldap.example.com")
            .put("plugins.security.authentication.0.config.port", "636")
            .put("plugins.security.authentication.0.config.ssl.enabled", "true")
            .put("plugins.security.authentication.0.config.ssl.verify_certificates", "true")
            .put("plugins.security.authentication.0.config.bind_dn", "cn=admin,dc=example,dc=com")
            .put("plugins.security.authentication.0.config.password", "secret")
            .put("plugins.security.authentication.0.config.userbase", "ou=people,dc=example,dc=com")
            .put("plugins.security.authentication.0.config.usersearch", "(uid={0})")
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(1, configs.size());
        AuthenticationPluginConfig config = configs.get(0);
        assertEquals("ldap", config.getType());
        
        // Verify all settings are loaded
        assertEquals("ldap.example.com", config.getSettings().get("host"));
        assertEquals("636", config.getSettings().get("port"));
        assertEquals("cn=admin,dc=example,dc=com", config.getSettings().get("bind_dn"));
        assertEquals("ou=people,dc=example,dc=com", config.getSettings().get("userbase"));
        assertEquals("(uid={0})", config.getSettings().get("usersearch"));
    }

    @Test
    public void testLoadEmptyConfiguration() {
        // Simulates an empty configuration
        Settings settings = Settings.builder().build();

        List<AuthenticationPluginConfig> authConfigs = loader.loadAuthenticationPlugins(settings);
        List<AuthorizationPluginConfig> authzConfigs = loader.loadAuthorizationPlugins(settings);

        assertTrue(authConfigs.isEmpty());
        assertTrue(authzConfigs.isEmpty());
    }

    @Test
    public void testLoadConfigurationWithDefaultOrder() {
        // Simulates a configuration where order is not specified
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            // order not specified, should use default (Integer.MAX_VALUE)
            .build();

        List<AuthenticationPluginConfig> configs = loader.loadAuthenticationPlugins(settings);

        assertEquals(1, configs.size());
        assertEquals("internal", configs.get(0).getType());
        // Default order should be Integer.MAX_VALUE
        assertEquals(Integer.MAX_VALUE, configs.get(0).getOrder());
    }
}
