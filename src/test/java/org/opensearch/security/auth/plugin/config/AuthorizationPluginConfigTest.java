/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationPluginConfigTest {

    @Test
    public void testConstructorWithAllParameters() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("roles_file", "roles.yml");
        settings.put("cache_ttl", 3600);

        AuthorizationPluginConfig config = new AuthorizationPluginConfig("role_based", true, settings);

        assertEquals("role_based", config.getType());
        assertTrue(config.isEnabled());
        assertNotNull(config.getSettings());
        assertEquals(2, config.getSettings().size());
        assertEquals("roles.yml", config.getSettings().get("roles_file"));
        assertEquals(3600, config.getSettings().get("cache_ttl"));
    }

    @Test
    public void testConstructorWithNullSettings() {
        AuthorizationPluginConfig config = new AuthorizationPluginConfig("custom", true, null);

        assertEquals("custom", config.getType());
        assertTrue(config.isEnabled());
        assertNotNull(config.getSettings());
        assertTrue(config.getSettings().isEmpty());
    }

    @Test
    public void testConstructorWithEmptySettings() {
        AuthorizationPluginConfig config = new AuthorizationPluginConfig("role_based", false, new HashMap<>());

        assertEquals("role_based", config.getType());
        assertFalse(config.isEnabled());
        assertNotNull(config.getSettings());
        assertTrue(config.getSettings().isEmpty());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorWithNullType() {
        new AuthorizationPluginConfig(null, true, new HashMap<>());
    }

    @Test
    public void testSettingsAreImmutable() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("key", "value");

        AuthorizationPluginConfig config = new AuthorizationPluginConfig("test", true, settings);

        // Modify original map
        settings.put("newKey", "newValue");

        // Config settings should not be affected
        assertEquals(1, config.getSettings().size());
        assertFalse(config.getSettings().containsKey("newKey"));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testSettingsCannotBeModified() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("key", "value");

        AuthorizationPluginConfig config = new AuthorizationPluginConfig("test", true, settings);

        // Attempt to modify returned settings should throw exception
        config.getSettings().put("newKey", "newValue");
    }

    @Test
    public void testEquals() {
        Map<String, Object> settings1 = new HashMap<>();
        settings1.put("key", "value");

        Map<String, Object> settings2 = new HashMap<>();
        settings2.put("key", "value");

        AuthorizationPluginConfig config1 = new AuthorizationPluginConfig("role_based", true, settings1);
        AuthorizationPluginConfig config2 = new AuthorizationPluginConfig("role_based", true, settings2);

        assertEquals(config1, config2);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    public void testNotEquals() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("key", "value");

        AuthorizationPluginConfig config1 = new AuthorizationPluginConfig("role_based", true, settings);
        AuthorizationPluginConfig config2 = new AuthorizationPluginConfig("custom", true, settings);
        AuthorizationPluginConfig config3 = new AuthorizationPluginConfig("role_based", false, settings);

        assertFalse(config1.equals(config2));
        assertFalse(config1.equals(config3));
    }

    @Test
    public void testToString() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("roles_file", "roles.yml");

        AuthorizationPluginConfig config = new AuthorizationPluginConfig("role_based", true, settings);

        String str = config.toString();
        assertTrue(str.contains("role_based"));
        assertTrue(str.contains("enabled=true"));
    }
}
