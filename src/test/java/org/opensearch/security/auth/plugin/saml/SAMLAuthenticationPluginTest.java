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

package org.opensearch.security.auth.plugin.saml;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

/**
 * Unit tests for SAMLAuthenticationPlugin.
 * <p>
 * These tests verify that the SAML authentication plugin correctly:
 * - Extracts backend roles and security roles from credentials
 * - Extracts attributes as claims with saml.attr prefix
 * - Supports configurable attribute name mapping
 * - Maintains behavior compatibility with existing SAML authenticator
 */
public class SAMLAuthenticationPluginTest {

    @Mock
    private AuthenticationContext mockContext;

    private SAMLAuthenticationPlugin plugin;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetType() {
        plugin = SAMLAuthenticationPlugin.builder().build();
        assertEquals("saml", plugin.getType());
    }

    @Test
    public void testSupportsWithValidCredentials() {
        plugin = SAMLAuthenticationPlugin.builder().build();

        AuthCredentials credentials = new AuthCredentials("testuser");
        assertTrue(plugin.supports(credentials));
    }

    @Test
    public void testSupportsWithNullCredentials() {
        plugin = SAMLAuthenticationPlugin.builder().build();
        assertFalse(plugin.supports(null));
    }

    @Test
    public void testAuthenticateWithBackendRoles() throws Exception {
        plugin = SAMLAuthenticationPlugin.builder().build();

        // Create credentials with backend roles
        AuthCredentials credentials = new AuthCredentials("user@example.com", "admin", "developers");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify principal
        assertNotNull(principal);
        assertEquals("user@example.com", principal.getName());
        assertEquals("saml", principal.getAuthenticationType());

        // Verify claims
        Map<String, Object> claims = principal.getClaims();
        assertNotNull(claims);

        // Check roles
        assertTrue(claims.containsKey("backend_roles"));
        @SuppressWarnings("unchecked")
        List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertEquals(2, backendRoles.size());
        assertTrue(backendRoles.contains("admin"));
        assertTrue(backendRoles.contains("developers"));
    }

    @Test
    public void testAuthenticateWithAttributes() throws Exception {
        plugin = SAMLAuthenticationPlugin.builder().build();

        // Create credentials with attributes
        AuthCredentials credentials = new AuthCredentials("testuser");
        credentials.addAttribute("email", "user@example.com");
        credentials.addAttribute("department", "Engineering");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify attributes are extracted with saml.attr prefix
        Map<String, Object> claims = principal.getClaims();
        assertEquals("user@example.com", claims.get("saml.attr.email"));
        assertEquals("Engineering", claims.get("saml.attr.department"));
    }

    @Test
    public void testAuthenticateWithAttributeMapping() throws Exception {
        // Plugin configured with attribute mapping
        Map<String, String> mapping = new HashMap<>();
        mapping.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email");
        mapping.put("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups", "groups");

        plugin = SAMLAuthenticationPlugin.builder().attributeMapping(mapping).build();

        // Create credentials with long attribute names
        AuthCredentials credentials = new AuthCredentials("testuser");
        credentials.addAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "user@example.com");
        credentials.addAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups", "admin");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify mapped attribute names are used
        Map<String, Object> claims = principal.getClaims();
        assertTrue(claims.containsKey("saml.attr.email"));
        assertEquals("user@example.com", claims.get("saml.attr.email"));

        // Verify raw attribute names are also preserved
        assertTrue(claims.containsKey("saml.attr.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
    }

    @Test
    public void testAuthenticateWithBothRoleTypes() throws Exception {
        plugin = SAMLAuthenticationPlugin.builder().build();

        // Create credentials with both backend and security roles
        java.util.List<String> securityRoles = new java.util.ArrayList<>();
        securityRoles.add("kibana_user");
        securityRoles.add("all_access");
        AuthCredentials credentials = new AuthCredentials("testuser", securityRoles, "admin", "developers");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify both role types are extracted
        Map<String, Object> claims = principal.getClaims();
        
        // Backend roles should be present
        assertTrue(claims.containsKey("backend_roles"));
        @SuppressWarnings("unchecked")
        List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertEquals(2, backendRoles.size());
        assertTrue(backendRoles.contains("admin"));
        assertTrue(backendRoles.contains("developers"));
        
        // Security roles should be present
        assertTrue(claims.containsKey("security_roles"));
        @SuppressWarnings("unchecked")
        List<String> extractedSecurityRoles = (List<String>) claims.get("security_roles");
        assertEquals(2, extractedSecurityRoles.size());
        assertTrue(extractedSecurityRoles.contains("kibana_user"));
        assertTrue(extractedSecurityRoles.contains("all_access"));
    }

    @Test
    public void testAuthenticateWithNullCredentials() {
        plugin = SAMLAuthenticationPlugin.builder().build();

        when(mockContext.getCredentials()).thenReturn(null);

        try {
            plugin.authenticate(mockContext);
            fail("Expected AuthenticationException");
        } catch (AuthenticationException e) {
            assertEquals("saml", e.getAuthenticationType());
            assertTrue(e.getMessage().contains("Credentials or username is null"));
        }
    }

    @Test
    public void testBuilderPattern() {
        // Test builder with all options
        Map<String, String> mapping = new HashMap<>();
        mapping.put("saml_attr", "claim_name");

        SAMLAuthenticationPlugin plugin = SAMLAuthenticationPlugin.builder()
            .attributeMapping(mapping)
            .addAttributeMapping("another_attr", "another_claim")
            .build();

        assertNotNull(plugin);
        assertEquals("saml", plugin.getType());
    }

    @Test
    public void testAuthenticateWithEmptyRoles() throws Exception {
        plugin = SAMLAuthenticationPlugin.builder().build();

        // Create credentials without roles
        AuthCredentials credentials = new AuthCredentials("testuser");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify no backend_roles claim when roles are empty
        assertFalse(principal.getClaims().containsKey("backend_roles"));
    }

    @Test
    public void testAuthenticateWithMultipleAttributes() throws Exception {
        plugin = SAMLAuthenticationPlugin.builder().build();

        // Create credentials with multiple attributes
        AuthCredentials credentials = new AuthCredentials("testuser", "admin", "developers");
        credentials.addAttribute("email", "user@example.com");
        credentials.addAttribute("department", "Engineering");
        credentials.addAttribute("location", "Seattle");

        when(mockContext.getCredentials()).thenReturn(credentials);

        // Authenticate
        UserPrincipal principal = plugin.authenticate(mockContext);

        // Verify all attributes are extracted
        Map<String, Object> claims = principal.getClaims();

        // Check backend roles
        assertTrue(claims.containsKey("backend_roles"));

        // Check all attributes
        assertEquals("user@example.com", claims.get("saml.attr.email"));
        assertEquals("Engineering", claims.get("saml.attr.department"));
        assertEquals("Seattle", claims.get("saml.attr.location"));
    }
}
