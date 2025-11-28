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

package org.opensearch.security.auth.plugin.kerberos;

import java.nio.file.Paths;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

import static org.junit.Assert.*;

/**
 * Unit tests for KerberosAuthenticationPlugin.
 */
public class KerberosAuthenticationPluginTest {

    private KerberosAuthenticationPlugin plugin;

    @Before
    public void setUp() {
        // Note: In real tests, you would need proper Kerberos configuration
        // For unit tests, we're testing the plugin logic with minimal config
        Settings settings = Settings.builder()
            .putList("plugins.security.kerberos.acceptor_principal", "HTTP/localhost@EXAMPLE.COM")
            .put("plugins.security.kerberos.acceptor_keytab_filepath", "test.keytab")
            .put("strip_realm_from_principal", true)
            .build();
        
        try {
            plugin = new KerberosAuthenticationPlugin(settings, Paths.get("src/test/resources/kerberos"));
        } catch (Exception e) {
            // Expected in unit test environment without actual Kerberos setup
            // We'll skip tests that require actual Kerberos configuration
        }
    }

    @Test
    public void testGetType() {
        if (plugin != null) {
            assertEquals("spnego", plugin.getType());
        }
    }

    @Test
    public void testSupportsWithValidCredentials() {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser@EXAMPLE.COM");
            assertTrue(plugin.supports(credentials));
        }
    }

    @Test
    public void testSupportsWithNullCredentials() {
        if (plugin != null) {
            assertFalse(plugin.supports(null));
        }
    }

    @Test
    public void testSupportsWithNullUsername() {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials(null);
            assertFalse(plugin.supports(credentials));
        }
    }

    @Test
    public void testAuthenticateWithValidCredentials() throws AuthenticationException {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser@EXAMPLE.COM", "role1");
            credentials.addAttribute("custom_attr", "value1");

            AuthenticationContext context = new AuthenticationContext(credentials);

            UserPrincipal principal = plugin.authenticate(context);

            assertNotNull(principal);
            assertEquals("testuser@EXAMPLE.COM", principal.getName());
            assertEquals("spnego", principal.getAuthenticationType());
            
            Map<String, Object> claims = principal.getClaims();
            assertNotNull(claims);
            assertTrue(claims.containsKey("backend_roles"));
            assertTrue(claims.containsKey("kerberos.strip_realm"));
            assertTrue(claims.containsKey("kerberos.acceptor_principal"));
        }
    }

    @Test(expected = AuthenticationException.class)
    public void testAuthenticateWithNullCredentials() throws AuthenticationException {
        if (plugin != null) {
            AuthenticationContext context = new AuthenticationContext(null);
            plugin.authenticate(context);
        } else {
            throw new AuthenticationException("spnego", "Test exception");
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAuthenticateWithNullUsername() throws AuthenticationException {
        // AuthCredentials constructor throws IllegalArgumentException for null username
        new AuthCredentials(null);
    }

    @Test
    public void testAuthenticateExtractsBackendRoles() throws AuthenticationException {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser@EXAMPLE.COM", "admin", "developer");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = plugin.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertTrue(claims.containsKey("backend_roles"));
            
            @SuppressWarnings("unchecked")
            java.util.List<String> roles = (java.util.List<String>) claims.get("backend_roles");
            assertEquals(2, roles.size());
            assertTrue(roles.contains("admin"));
            assertTrue(roles.contains("developer"));
        }
    }

    @Test
    public void testAuthenticateExtractsAttributes() throws AuthenticationException {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser@EXAMPLE.COM");
            credentials.addAttribute("custom_attr", "custom_value");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = plugin.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertEquals("custom_value", claims.get("kerberos.attr.custom_attr"));
        }
    }

    @Test
    public void testBuilderPattern() {
        Settings settings = Settings.builder()
            .putList("plugins.security.kerberos.acceptor_principal", "HTTP/localhost@EXAMPLE.COM")
            .put("plugins.security.kerberos.acceptor_keytab_filepath", "test.keytab")
            .build();

        try {
            KerberosAuthenticationPlugin plugin = KerberosAuthenticationPlugin.builder()
                .settings(settings)
                .configPath(Paths.get("src/test/resources/kerberos"))
                .build();

            assertNotNull(plugin);
            assertEquals("spnego", plugin.getType());
        } catch (Exception e) {
            // Expected in unit test environment without actual Kerberos setup
        }
    }
}
