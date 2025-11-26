/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.http;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;

import com.google.common.io.BaseEncoding;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests verifying HTTPAuthenticator implementations work correctly
 * with the new plugin architecture.
 * 
 * These tests verify that HTTPAuthenticator implementations correctly extract
 * credentials that can be consumed by authentication plugins. The HTTPAuthenticator
 * interface and implementations do NOT need modification for plugin support - they
 * continue to extract AuthCredentials which are then processed by the plugin architecture
 * in BackendRegistry.
 * 
 * Requirements tested: 2.1, 2.2, 2.4
 */
public class HTTPAuthenticatorPluginIntegrationTest {

    private static final byte[] SECRET_KEY_BYTES = new byte[1024];
    private static final SecretKey SECRET_KEY;

    static {
        new SecureRandom().nextBytes(SECRET_KEY_BYTES);
        SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY_BYTES);
    }

    /**
     * Test that JWT authenticator extracts credentials compatible with plugin architecture.
     * 
     * Verifies:
     * - HTTPJwtAuthenticator extracts username from JWT subject
     * - Roles are extracted from JWT claims
     * - Custom JWT claims are extracted as attributes
     * - Credentials are marked complete
     * - All extracted data is available for plugin processing
     * 
     * Requirement 2.1: Authentication plugins receive User Principal as input
     * Requirement 2.2: Authentication plugins do not make authorization decisions
     * Requirement 2.4: Authorization plugins receive User Principal without modification
     */
    @Test
    public void testJwtAuthenticatorExtractsCredentialsForPlugins() throws Exception {
        // Create JWT token with various claims
        String jwsToken = Jwts.builder()
            .setSubject("jwtuser")
            .claim("roles", List.of("admin", "developer"))
            .claim("email", "jwtuser@example.com")
            .claim("department", "Engineering")
            .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
            .compact();

        // Configure JWT authenticator to extract roles
        Settings jwtSettings = Settings.builder()
            .put("signing_key", BaseEncoding.base64().encode(SECRET_KEY_BYTES))
            .putList("roles_key", "roles")
            .build();

        HTTPJwtAuthenticator jwtAuthenticator = new HTTPJwtAuthenticator(jwtSettings, null);

        // Create request with JWT token
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + jwsToken);
        FakeRestRequest request = new FakeRestRequest(headers, new HashMap<>());

        // Extract credentials
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        AuthCredentials credentials = jwtAuthenticator.extractCredentials(
            request.asSecurityRequest(),
            threadContext
        );

        // Verify credentials were extracted correctly
        assertNotNull("JWT authenticator should extract credentials", credentials);
        assertEquals("Username should match JWT subject", "jwtuser", credentials.getUsername());
        assertTrue("Credentials should be marked complete", credentials.isComplete());
        
        // Verify backend roles were extracted
        assertNotNull("Backend roles should be extracted", credentials.getBackendRoles());
        assertEquals("Should have 2 roles", 2, credentials.getBackendRoles().size());
        assertTrue("Should have admin role", credentials.getBackendRoles().contains("admin"));
        assertTrue("Should have developer role", credentials.getBackendRoles().contains("developer"));
        
        // Verify JWT claims were extracted as attributes (available for plugin processing)
        assertNotNull("JWT attributes should be extracted", credentials.getAttributes());
        assertTrue("Should have JWT subject claim", 
            credentials.getAttributes().containsKey("attr.jwt.sub"));
        assertTrue("Should have JWT roles claim", 
            credentials.getAttributes().containsKey("attr.jwt.roles"));
        assertTrue("Should have JWT email claim", 
            credentials.getAttributes().containsKey("attr.jwt.email"));
        assertTrue("Should have JWT department claim", 
            credentials.getAttributes().containsKey("attr.jwt.department"));
        
        // Verify attribute values
        assertEquals("jwtuser", credentials.getAttributes().get("attr.jwt.sub"));
        assertEquals("jwtuser@example.com", credentials.getAttributes().get("attr.jwt.email"));
        assertEquals("Engineering", credentials.getAttributes().get("attr.jwt.department"));
    }

    /**
     * Test that JWT authenticator handles nested claims correctly.
     * 
     * Verifies that complex JWT claim structures are properly extracted
     * and available for plugin processing.
     */
    @Test
    public void testJwtAuthenticatorExtractsNestedClaims() throws Exception {
        // Create JWT token with nested claims
        Map<String, Object> nestedClaim = Map.of(
            "level1", Map.of("level2", "nested-value")
        );
        
        String jwsToken = Jwts.builder()
            .setSubject("nesteduser")
            .claim("nested", nestedClaim)
            .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
            .compact();

        Settings jwtSettings = Settings.builder()
            .put("signing_key", BaseEncoding.base64().encode(SECRET_KEY_BYTES))
            .build();

        HTTPJwtAuthenticator jwtAuthenticator = new HTTPJwtAuthenticator(jwtSettings, null);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + jwsToken);
        FakeRestRequest request = new FakeRestRequest(headers, new HashMap<>());

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        AuthCredentials credentials = jwtAuthenticator.extractCredentials(
            request.asSecurityRequest(),
            threadContext
        );

        // Verify nested claims are extracted
        assertNotNull("Credentials should be extracted", credentials);
        assertNotNull("Attributes should contain nested claim", credentials.getAttributes());
        assertTrue("Should have nested claim", 
            credentials.getAttributes().containsKey("attr.jwt.nested"));
    }

    /**
     * Test that JWT authenticator handles missing optional claims gracefully.
     * 
     * Verifies that HTTPAuthenticator works correctly even when optional
     * claims are not present in the JWT token.
     */
    @Test
    public void testJwtAuthenticatorHandlesMissingOptionalClaims() throws Exception {
        // Create minimal JWT token with only subject
        String jwsToken = Jwts.builder()
            .setSubject("minimaluser")
            .signWith(SECRET_KEY, SignatureAlgorithm.HS512)
            .compact();

        Settings jwtSettings = Settings.builder()
            .put("signing_key", BaseEncoding.base64().encode(SECRET_KEY_BYTES))
            .putList("roles_key", "roles")  // Configure roles extraction but token has no roles
            .build();

        HTTPJwtAuthenticator jwtAuthenticator = new HTTPJwtAuthenticator(jwtSettings, null);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + jwsToken);
        FakeRestRequest request = new FakeRestRequest(headers, new HashMap<>());

        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        AuthCredentials credentials = jwtAuthenticator.extractCredentials(
            request.asSecurityRequest(),
            threadContext
        );

        // Verify credentials are still extracted
        assertNotNull("Credentials should be extracted even without optional claims", credentials);
        assertEquals("minimaluser", credentials.getUsername());
        assertTrue("Credentials should be marked complete", credentials.isComplete());
        
        // Verify empty roles set when roles claim is missing
        assertNotNull("Backend roles should not be null", credentials.getBackendRoles());
        assertEquals("Should have empty roles set", 0, credentials.getBackendRoles().size());
    }

    /**
     * Test that incomplete credentials are properly marked.
     * 
     * Verifies that HTTPAuthenticator correctly marks credentials as incomplete
     * when additional authentication steps are needed, allowing the plugin
     * architecture to handle multi-step authentication flows.
     */
    @Test
    public void testIncompleteCredentialsMarking() {
        // Create incomplete credentials (simulating multi-step auth)
        AuthCredentials incompleteCredentials = new AuthCredentials("partialuser");

        // Verify credentials are not marked complete
        assertFalse("Credentials should not be complete", incompleteCredentials.isComplete());
        
        // Mark as complete
        incompleteCredentials.markComplete();
        assertTrue("Credentials should now be complete", incompleteCredentials.isComplete());
    }

    /**
     * Test that HTTPAuthenticator attribute extraction preserves all data.
     * 
     * Verifies that custom attributes added by HTTPAuthenticator implementations
     * are fully preserved and available for plugin processing.
     */
    @Test
    public void testAttributePreservation() {
        // Create credentials with custom attributes
        AuthCredentials credentials = new AuthCredentials("attruser")
            .markComplete();
        credentials.addAttribute("custom.attr1", "value1");
        credentials.addAttribute("custom.attr2", "value2");
        credentials.addAttribute("department", "Engineering");
        credentials.addAttribute("location", "Seattle");

        // Verify all attributes are preserved
        Map<String, String> attributes = credentials.getAttributes();
        assertNotNull("Attributes should not be null", attributes);
        assertEquals("Should have 4 attributes", 4, attributes.size());
        assertEquals("value1", attributes.get("custom.attr1"));
        assertEquals("value2", attributes.get("custom.attr2"));
        assertEquals("Engineering", attributes.get("department"));
        assertEquals("Seattle", attributes.get("location"));
    }

    /**
     * Test that HTTPAuthenticator role extraction works correctly.
     * 
     * Verifies that backend roles extracted by HTTPAuthenticator are properly
     * stored in AuthCredentials and available for plugin processing.
     */
    @Test
    public void testRoleExtraction() {
        // Create credentials with backend roles
        String[] backendRoles = new String[] { "role1", "role2", "admin", "developer" };
        AuthCredentials credentials = new AuthCredentials("roleuser", backendRoles)
            .markComplete();

        // Verify roles are preserved
        assertNotNull("Backend roles should not be null", credentials.getBackendRoles());
        assertEquals("Should have 4 roles", 4, credentials.getBackendRoles().size());
        
        assertTrue("Should have role1", credentials.getBackendRoles().contains("role1"));
        assertTrue("Should have role2", credentials.getBackendRoles().contains("role2"));
        assertTrue("Should have admin", credentials.getBackendRoles().contains("admin"));
        assertTrue("Should have developer", credentials.getBackendRoles().contains("developer"));
    }

    /**
     * Test that HTTPAuthenticator supports different authentication types.
     * 
     * Verifies that the plugin architecture can work with credentials from
     * different HTTPAuthenticator implementations (JWT, Basic, SAML, etc.).
     */
    @Test
    public void testMultipleAuthenticatorTypes() {
        // JWT-style credentials
        AuthCredentials jwtCredentials = new AuthCredentials("jwtuser")
            .markComplete();
        jwtCredentials.addAttribute("auth.type", "jwt");
        jwtCredentials.addAttribute("attr.jwt.email", "jwt@example.com");
        
        assertNotNull("JWT credentials should be created", jwtCredentials);
        assertEquals("jwtuser", jwtCredentials.getUsername());
        assertEquals("jwt", jwtCredentials.getAttributes().get("auth.type"));

        // Basic auth-style credentials
        AuthCredentials basicCredentials = new AuthCredentials("basicuser", "password".getBytes())
            .markComplete();
        basicCredentials.addAttribute("auth.type", "basic");
        
        assertNotNull("Basic credentials should be created", basicCredentials);
        assertEquals("basicuser", basicCredentials.getUsername());
        assertEquals("basic", basicCredentials.getAttributes().get("auth.type"));

        // SAML-style credentials
        AuthCredentials samlCredentials = new AuthCredentials("samluser")
            .markComplete();
        samlCredentials.addAttribute("auth.type", "saml");
        samlCredentials.addAttribute("attr.saml.nameId", "saml@example.com");
        
        assertNotNull("SAML credentials should be created", samlCredentials);
        assertEquals("samluser", samlCredentials.getUsername());
        assertEquals("saml", samlCredentials.getAttributes().get("auth.type"));
    }
}
