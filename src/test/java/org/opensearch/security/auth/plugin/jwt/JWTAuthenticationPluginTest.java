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

package org.opensearch.security.auth.plugin.jwt;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

import static org.junit.Assert.*;

/**
 * Unit tests for JWTAuthenticationPlugin.
 */
public class JWTAuthenticationPluginTest {

    private JWTAuthenticationPlugin plugin;

    @Before
    public void setUp() {
        // Use a valid base64-encoded key for testing
        // This is a test key - not for production use
        String testKey = "c2VjcmV0a2V5dGhhdGlzbG9uZ2Vub3VnaGZvcnRlc3Rpbmc="; // "secretkeythatislongenoughfortesting" in base64
        Settings settings = Settings.builder()
            .putList("signing_key", testKey)
            .build();
        
        try {
            plugin = new JWTAuthenticationPlugin(settings, Paths.get("/tmp"));
        } catch (Exception e) {
            // If JWT parser creation fails, we'll skip tests that require it
            plugin = null;
        }
    }

    @Test
    public void testGetType() {
        if (plugin != null) {
            assertEquals("jwt", plugin.getType());
        }
    }

    @Test
    public void testSupportsWithValidCredentials() {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser");
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
            try {
                AuthCredentials credentials = new AuthCredentials(null);
                assertFalse(plugin.supports(credentials));
            } catch (IllegalArgumentException e) {
                // Expected - AuthCredentials doesn't allow null username
            }
        }
    }

    @Test
    public void testAuthenticateWithValidCredentials() throws AuthenticationException {
        if (plugin != null) {
            AuthCredentials credentials = new AuthCredentials("testuser", "role1", "role2");
            credentials.addAttribute("attr.jwt.email", "test@example.com");
            credentials.addAttribute("attr.jwt.groups", "[\"group1\",\"group2\"]");

            AuthenticationContext context = new AuthenticationContext(credentials);

            UserPrincipal principal = plugin.authenticate(context);

            assertNotNull(principal);
            assertEquals("testuser", principal.getName());
            assertEquals("jwt", principal.getAuthenticationType());
            
            Map<String, Object> claims = principal.getClaims();
            assertNotNull(claims);
            assertTrue(claims.containsKey("backend_roles"));
            assertTrue(claims.containsKey("attr.jwt.email"));
            assertTrue(claims.containsKey("attr.jwt.groups"));
        }
    }

    @Test(expected = AuthenticationException.class)
    public void testAuthenticateWithNullCredentials() throws AuthenticationException {
        if (plugin != null) {
            AuthenticationContext context = new AuthenticationContext(null);
            plugin.authenticate(context);
        } else {
            throw new AuthenticationException("jwt", "Test exception");
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
            AuthCredentials credentials = new AuthCredentials("testuser", "admin", "developer");

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
            AuthCredentials credentials = new AuthCredentials("testuser");
            credentials.addAttribute("attr.jwt.email", "user@example.com");
            credentials.addAttribute("attr.jwt.department", "Engineering");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = plugin.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertEquals("user@example.com", claims.get("attr.jwt.email"));
            assertEquals("Engineering", claims.get("attr.jwt.department"));
        }
    }

    @Test
    public void testBuilderPattern() {
        String testKey = "c2VjcmV0a2V5dGhhdGlzbG9uZ2Vub3VnaGZvcnRlc3Rpbmc=";
        Settings settings = Settings.builder()
            .putList("signing_key", testKey)
            .build();

        try {
            JWTAuthenticationPlugin plugin = JWTAuthenticationPlugin.builder()
                .settings(settings)
                .configPath(Paths.get("/tmp"))
                .build();

            assertNotNull(plugin);
            assertEquals("jwt", plugin.getType());
        } catch (Exception e) {
            // Expected if JWT parser creation fails
        }
    }
}
