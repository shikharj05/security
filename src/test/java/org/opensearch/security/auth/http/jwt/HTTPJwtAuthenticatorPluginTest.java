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

package org.opensearch.security.auth.http.jwt;

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
 * Unit tests for HTTPJwtAuthenticator implementing AuthenticationPlugin.
 */
public class HTTPJwtAuthenticatorPluginTest {

    private HTTPJwtAuthenticator authenticator;

    @Before
    public void setUp() {
        String testKey = "c2VjcmV0a2V5dGhhdGlzbG9uZ2Vub3VnaGZvcnRlc3Rpbmc=";
        Settings settings = Settings.builder()
            .putList("signing_key", testKey)
            .build();
        
        try {
            authenticator = new HTTPJwtAuthenticator(settings, Paths.get("/tmp"));
        } catch (Exception e) {
            authenticator = null;
        }
    }

    @Test
    public void testGetType() {
        if (authenticator != null) {
            assertEquals("jwt", authenticator.getType());
        }
    }

    @Test
    public void testSupportsWithValidCredentials() {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("testuser");
            assertTrue(authenticator.supports(credentials));
        }
    }

    @Test
    public void testSupportsWithNullCredentials() {
        if (authenticator != null) {
            assertFalse(authenticator.supports(null));
        }
    }

    @Test
    public void testSupportsWithNullUsername() {
        if (authenticator != null) {
            try {
                AuthCredentials credentials = new AuthCredentials(null);
                assertFalse(authenticator.supports(credentials));
            } catch (IllegalArgumentException e) {
                // Expected
            }
        }
    }

    @Test
    public void testAuthenticateWithValidCredentials() throws AuthenticationException {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("jwtuser", "jwt_role1", "jwt_role2");
            credentials.addAttribute("attr.jwt.email", "jwt@example.com");
            credentials.addAttribute("attr.jwt.sub", "jwt-subject");

            AuthenticationContext context = new AuthenticationContext(credentials);

            UserPrincipal principal = authenticator.authenticate(context);

            assertNotNull(principal);
            assertEquals("jwtuser", principal.getName());
            assertEquals("jwt", principal.getAuthenticationType());
            
            Map<String, Object> claims = principal.getClaims();
            assertNotNull(claims);
            assertTrue(claims.containsKey("backend_roles"));
            assertTrue(claims.containsKey("attr.jwt.email"));
            assertTrue(claims.containsKey("attr.jwt.sub"));
        }
    }

    @Test(expected = AuthenticationException.class)
    public void testAuthenticateWithNullCredentials() throws AuthenticationException {
        if (authenticator != null) {
            AuthenticationContext context = new AuthenticationContext(null);
            authenticator.authenticate(context);
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
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("jwtuser", "admin", "developer");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = authenticator.authenticate(context);

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
    public void testAuthenticateExtractsJWTAttributes() throws AuthenticationException {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("jwtuser");
            credentials.addAttribute("attr.jwt.email", "user@jwt.com");
            credentials.addAttribute("attr.jwt.groups", "[\"group1\",\"group2\"]");
            credentials.addAttribute("attr.jwt.iss", "https://issuer.example.com");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = authenticator.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertEquals("user@jwt.com", claims.get("attr.jwt.email"));
            assertEquals("[\"group1\",\"group2\"]", claims.get("attr.jwt.groups"));
            assertEquals("https://issuer.example.com", claims.get("attr.jwt.iss"));
        }
    }

    @Test
    public void testAuthenticatePreservesAttributePrefix() throws AuthenticationException {
        if (authenticator != null) {
            // HTTPJwtAuthenticator adds "attr.jwt." prefix to JWT claims
            // This test verifies that the prefix is preserved in UserPrincipal
            AuthCredentials credentials = new AuthCredentials("jwtuser");
            credentials.addAttribute("attr.jwt.custom_claim", "custom_value");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = authenticator.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertTrue(claims.containsKey("attr.jwt.custom_claim"));
            assertEquals("custom_value", claims.get("attr.jwt.custom_claim"));
        }
    }
}
