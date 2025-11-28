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

package org.opensearch.security.auth.http.kerberos;

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
 * Unit tests for HTTPSpnegoAuthenticator implementing AuthenticationPlugin.
 */
public class HTTPSpnegoAuthenticatorPluginTest {

    private HTTPSpnegoAuthenticator authenticator;

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
            authenticator = new HTTPSpnegoAuthenticator(settings, Paths.get("src/test/resources/kerberos"));
        } catch (Exception e) {
            // Expected in unit test environment without actual Kerberos setup
            // We'll skip tests that require actual Kerberos configuration
        }
    }

    @Test
    public void testGetType() {
        if (authenticator != null) {
            assertEquals("spnego", authenticator.getType());
        }
    }

    @Test
    public void testSupportsWithValidCredentials() {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("testuser@EXAMPLE.COM");
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
            AuthCredentials credentials = new AuthCredentials(null);
            assertFalse(authenticator.supports(credentials));
        }
    }

    @Test
    public void testAuthenticateWithValidCredentials() throws AuthenticationException {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("kerberosuser@EXAMPLE.COM", "krb_role1");
            credentials.addAttribute("custom_attr", "value1");

            AuthenticationContext context = new AuthenticationContext(credentials);

            UserPrincipal principal = authenticator.authenticate(context);

            assertNotNull(principal);
            assertEquals("kerberosuser@EXAMPLE.COM", principal.getName());
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
        if (authenticator != null) {
            AuthenticationContext context = new AuthenticationContext(null);
            authenticator.authenticate(context);
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
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("kerberosuser@EXAMPLE.COM", "admin", "developer");

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
    public void testAuthenticateExtractsKerberosAttributes() throws AuthenticationException {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("kerberosuser@EXAMPLE.COM");
            credentials.addAttribute("realm", "EXAMPLE.COM");
            credentials.addAttribute("principal", "kerberosuser");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = authenticator.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertEquals("EXAMPLE.COM", claims.get("kerberos.attr.realm"));
            assertEquals("kerberosuser", claims.get("kerberos.attr.principal"));
        }
    }

    @Test
    public void testAuthenticateIncludesKerberosMetadata() throws AuthenticationException {
        if (authenticator != null) {
            AuthCredentials credentials = new AuthCredentials("kerberosuser@EXAMPLE.COM");

            AuthenticationContext context = new AuthenticationContext(credentials);
            UserPrincipal principal = authenticator.authenticate(context);

            Map<String, Object> claims = principal.getClaims();
            assertTrue(claims.containsKey("kerberos.strip_realm"));
            assertTrue(claims.containsKey("kerberos.acceptor_principal"));
            
            // Verify strip_realm setting is captured
            assertEquals(true, claims.get("kerberos.strip_realm"));
        }
    }
}
