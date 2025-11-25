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

public class AuthenticationPluginConfigTest {

    @Test
    public void testConstructorWithAllParameters() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("host", "ldap.example.com");
        settings.put("port", 389);

        AuthenticationPluginConfig config = new AuthenticationPluginConfig("ldap", true, 1, settings);

        assertEquals("ldap", config.getType());
        assertTrue(config.isEnabled());
        assertEquals(1, config.getOrder());
        assertNotNull(config.getSettings());
        assertEquals(2, config.getSettings().size());
        assertEquals("ldap.example.com", config.getSettings().get("host"));
        assertEquals(389, config.getSettings().get("port"));
    }

    @Test
    public void testConstructorWithNullSettings() {
        AuthenticationPluginConfig config = new AuthenticationPluginConfig("internal", true, 0, null);

        assertEquals("internal", config.getType());
        assertTrue(config.isEnabled());
        assertEquals(0, config.getOrder());
        assertNotNull(config.getSettings());
        assertTrue(config.getSettings().isEmpty());
    }

    @Test
    public void testConstructorWithEmptySettings() {
        AuthenticationPluginConfig config = new AuthenticationPluginConfig("saml", false, 2, new HashMap<>());

        assertEquals("saml", config.getType());
        assertFalse(config.isEnabled());
        assertEquals(2, config.getOrder());
        assertNotNull(config.getSettings());
        assertTrue(config.getSettings().isEmpty());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorWithNullType() {
        new AuthenticationPluginConfig(null, true, 0, new HashMap<>());
    }

    @Test
    public void testSettingsAreImmutable() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("key", "value");

        AuthenticationPluginConfig config = new AuthenticationPluginConfig("test", true, 0, settings);

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

        AuthenticationPluginConfig config = new AuthenticationPluginConfig("test", true, 0, settings);

        // Attempt to modify returned settings should throw exception
        config.getSettings().put("newKey", "newValue");
    }

    @Test
    public void testEquals() {
        Map<String, Object> settings1 = new HashMap<>();
        settings1.put("key", "value");

        Map<String, Object> settings2 = new HashMap<>();
        settings2.put("key", "value");

        AuthenticationPluginConfig config1 = new AuthenticationPluginConfig("ldap", true, 1, settings1);
        AuthenticationPluginConfig config2 = new AuthenticationPluginConfig("ldap", true, 1, settings2);

        assertEquals(config1, config2);
        assertEquals(config1.hashCode(), config2.hashCode());
    }

    @Test
    public void testNotEquals() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("key", "value");

        AuthenticationPluginConfig config1 = new AuthenticationPluginConfig("ldap", true, 1, settings);
        AuthenticationPluginConfig config2 = new AuthenticationPluginConfig("saml", true, 1, settings);
        AuthenticationPluginConfig config3 = new AuthenticationPluginConfig("ldap", false, 1, settings);
        AuthenticationPluginConfig config4 = new AuthenticationPluginConfig("ldap", true, 2, settings);

        assertFalse(config1.equals(config2));
        assertFalse(config1.equals(config3));
        assertFalse(config1.equals(config4));
    }

    @Test
    public void testToString() {
        Map<String, Object> settings = new HashMap<>();
        settings.put("host", "ldap.example.com");

        AuthenticationPluginConfig config = new AuthenticationPluginConfig("ldap", true, 1, settings);

        String str = config.toString();
        assertTrue(str.contains("ldap"));
        assertTrue(str.contains("enabled=true"));
        assertTrue(str.contains("order=1"));
    }
}
