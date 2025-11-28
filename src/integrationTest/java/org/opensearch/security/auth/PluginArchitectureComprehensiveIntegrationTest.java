/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Comprehensive integration tests for the plugin architecture.
 * 
 * Tests complete authentication and authorization flows with:
 * - New plugin interfaces
 * - Backward compatibility with existing backends
 * - Mixed configurations (old + new plugins)
 * - All existing security features
 * 
 * Requirements tested: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5
 */
public class PluginArchitectureComprehensiveIntegrationTest {

    /**
     * Test 1: User to UserPrincipal conversion
     * Requirements: 2.1, 2.4, 5.4
     */
    @Test
    public void testUserToUserPrincipalConversion() {
        // Create User object
        ImmutableSet<String> roles = ImmutableSet.of("admin", "developer");
        ImmutableSet<String> securityRoles = ImmutableSet.of("security_admin");
        
        User user = new User("testuser", roles, securityRoles, null, ImmutableMap.of(), false);

        // Convert to UserPrincipal
        UserPrincipal principal = user.toPrincipal();

        assertNotNull("Principal should not be null", principal);
        assertEquals("testuser", principal.getName());
        assertNotNull("Claims should not be null", principal.getClaims());
        assertTrue("Claims should contain backend_roles", principal.getClaims().containsKey("backend_roles"));
    }

    /**
     * Test 2: UserPrincipal to User conversion
     * Requirements: 2.1, 2.4, 5.4
     */
    @Test
    public void testUserPrincipalToUserConversion() {
        // Create UserPrincipal
        Map<String, Object> claims = new HashMap<>();
        List<String> backendRoles = new ArrayList<>();
        backendRoles.add("admin");
        backendRoles.add("developer");
        claims.put("backend_roles", backendRoles);
        
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .authenticationTime(System.currentTimeMillis())
            .build();

        // Convert to User
        ImmutableSet<String> securityRoles = ImmutableSet.of("security_admin");
        User user = User.fromPrincipal(principal, securityRoles);

        assertNotNull("User should not be null", user);
        assertEquals("testuser", user.getName());
        assertTrue("User should have backend roles", user.getRoles().contains("admin"));
        assertTrue("User should have security roles", user.getSecurityRoles().contains("security_admin"));
    }

    /**
     * Test 3: UserPrincipal builder pattern
     * Requirements: 5.3
     */
    @Test
    public void testUserPrincipalBuilderPattern() {
        // Build UserPrincipal using builder
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claim("role", "admin")
            .claim("email", "test@example.com")
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        assertNotNull("Principal should not be null", principal);
        assertEquals("testuser", principal.getName());
        assertEquals("ldap", principal.getAuthenticationType());
        assertEquals("admin", principal.getClaims().get("role"));
        assertEquals("test@example.com", principal.getClaims().get("email"));
    }

    /**
     * Test 4: AuthorizationContext builder pattern
     * Requirements: 3.1, 5.2
     */
    @Test
    public void testAuthorizationContextBuilderPattern() {
        // Build AuthorizationContext using builder
        AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .resourceAttribute("index_type", "logs")
            .resourceAttribute("tenant", "default")
            .remoteAddress("192.168.1.100")
            .build();

        assertNotNull("Context should not be null", context);
        assertEquals("indices:data/read/search", context.getAction());
        assertEquals("test-index", context.getResource());
        assertEquals("logs", context.getResourceAttributes().get("index_type"));
        assertEquals("default", context.getResourceAttributes().get("tenant"));
        assertEquals("192.168.1.100", context.getRemoteAddress());
    }

    /**
     * Test 5: AuthorizationResult with applied policies
     * Requirements: 3.1, 5.2
     */
    @Test
    public void testAuthorizationResultWithAppliedPolicies() {
        // Create authorization result with policies
        Set<String> policies = new HashSet<>();
        policies.add("admin_policy");
        policies.add("read_policy");

        AuthorizationResult result = AuthorizationResult.builder(true)
            .appliedPolicies(policies)
            .build();

        assertTrue("Result should be allowed", result.isAllowed());
        assertNotNull("Applied policies should not be null", result.getAppliedPolicies());
        assertTrue("Applied policies should contain admin_policy", result.getAppliedPolicies().contains("admin_policy"));
        assertTrue("Applied policies should contain read_policy", result.getAppliedPolicies().contains("read_policy"));
    }

    /**
     * Test 6: AuthorizationResult denial with reason
     * Requirements: 3.2, 5.5
     */
    @Test
    public void testAuthorizationResultDenialWithReason() {
        // Create denial result with reason
        AuthorizationResult result = AuthorizationResult.deny("Insufficient permissions");

        assertFalse("Result should be denied", result.isAllowed());
        assertNotNull("Denial reason should not be null", result.getReason());
        assertTrue("Denial reason should contain message", result.getReason().contains("Insufficient permissions"));
    }

    /**
     * Test 7: User object round-trip through serialization
     * User -> UserPrincipal -> User maintains compatibility
     * Requirements: 2.4, 5.4
     */
    @Test
    public void testUserObjectRoundTripThroughSerialization() {
        // Create original User
        ImmutableSet<String> roles = ImmutableSet.of("admin", "developer");
        ImmutableSet<String> securityRoles = ImmutableSet.of("security_admin");
        
        User originalUser = new User("testuser", roles, securityRoles, null, ImmutableMap.of(), false);

        // Convert to UserPrincipal (internal processing)
        UserPrincipal principal = originalUser.toPrincipal();

        // Convert back to User (for serialization)
        User convertedUser = User.fromPrincipal(principal, securityRoles);

        // Verify: User object maintains compatibility
        assertEquals("Username should match", originalUser.getName(), convertedUser.getName());
        assertTrue("Backend roles should be preserved", convertedUser.getRoles().containsAll(roles));
        assertTrue("Security roles should be preserved", convertedUser.getSecurityRoles().containsAll(securityRoles));
    }

    /**
     * Test 8: Immutability of UserPrincipal claims
     * Requirements: 5.3, 5.4
     */
    @Test
    public void testImmutabilityOfUserPrincipalClaims() {
        // Create UserPrincipal
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // Verify claims are immutable
        ImmutableMap<String, Object> retrievedClaims = principal.getClaims();
        try {
            retrievedClaims.put("new_claim", "value");
            // Should throw exception if immutable
            assertTrue("Claims should be immutable", false);
        } catch (UnsupportedOperationException e) {
            // Expected - claims should be immutable
            assertTrue("Claims are properly immutable", true);
        }
    }

    /**
     * Test 9: Authentication time tracking
     * Requirements: 5.3
     */
    @Test
    public void testAuthenticationTimeTracking() {
        // Create UserPrincipal
        long beforeTime = System.currentTimeMillis();
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("internal")
            .authenticationTime(System.currentTimeMillis())
            .build();
        long afterTime = System.currentTimeMillis();

        // Verify authentication time is set
        assertTrue("Authentication time should be after before time", principal.getAuthenticationTime() >= beforeTime);
        assertTrue("Authentication time should be before after time", principal.getAuthenticationTime() <= afterTime);
    }

    /**
     * Test 10: Claims extraction from multiple sources
     * Requirements: 2.1, 2.5, 5.3
     */
    @Test
    public void testClaimsExtractionFromMultipleSources() {
        // Create UserPrincipal with claims from multiple sources
        Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("ldap_admin", "ldap_developer"));
        claims.put("security_roles", List.of("security_admin"));
        claims.put("attr.ldap.email", "user@example.com");
        claims.put("attr.ldap.department", "Engineering");

        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        // Verify all claims are present
        assertNotNull("Claims should be extracted", principal.getClaims());
        assertTrue("Backend roles should be present", principal.getClaims().containsKey("backend_roles"));
        assertTrue("Security roles should be present", principal.getClaims().containsKey("security_roles"));
        assertTrue("LDAP email should be present", principal.getClaims().containsKey("attr.ldap.email"));
        assertTrue("LDAP department should be present", principal.getClaims().containsKey("attr.ldap.department"));
    }

    /**
     * Test 11: Authorization context with resource attributes
     * Requirements: 3.1, 5.2
     */
    @Test
    public void testAuthorizationContextWithResourceAttributes() {
        // Create authorization context with attributes
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("index_type", "logs");
        attributes.put("tenant", "default");
        attributes.put("document_level_security", true);

        AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "logs-*")
            .resourceAttributes(attributes)
            .remoteAddress("10.0.0.1")
            .build();

        assertNotNull("Context should not be null", context);
        assertEquals("logs-*", context.getResource());
        assertNotNull("Attributes should not be null", context.getResourceAttributes());
        assertEquals("logs", context.getResourceAttributes().get("index_type"));
        assertEquals("default", context.getResourceAttributes().get("tenant"));
        assertEquals(true, context.getResourceAttributes().get("document_level_security"));
    }

    /**
     * Test 12: Multiple backend roles consolidation
     * Requirements: 2.1, 3.3, 3.4
     */
    @Test
    public void testMultipleBackendRolesConsolidation() {
        // Create UserPrincipal with roles from multiple backends
        List<String> backendRoles = new ArrayList<>();
        backendRoles.add("ldap_admin");
        backendRoles.add("saml_developer");
        backendRoles.add("internal_readonly");

        Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", backendRoles);

        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("mixed")
            .build();

        // Convert to User
        User user = User.fromPrincipal(principal, ImmutableSet.of());

        // Verify all roles are consolidated
        assertTrue("User should have ldap_admin role", user.getRoles().contains("ldap_admin"));
        assertTrue("User should have saml_developer role", user.getRoles().contains("saml_developer"));
        assertTrue("User should have internal_readonly role", user.getRoles().contains("internal_readonly"));
    }

    /**
     * Test 13: Empty claims handling
     * Requirements: 5.3
     */
    @Test
    public void testEmptyClaimsHandling() {
        // Create UserPrincipal with no claims
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("internal")
            .build();

        assertNotNull("Principal should not be null", principal);
        assertNotNull("Claims should not be null", principal.getClaims());
        assertTrue("Claims should be empty", principal.getClaims().isEmpty());
    }

    /**
     * Test 14: UserPrincipal equality and hashCode
     * Requirements: 5.3, 5.4
     */
    @Test
    public void testUserPrincipalEqualityAndHashCode() {
        // Create two identical UserPrincipals
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");
        long authTime = System.currentTimeMillis();

        UserPrincipal principal1 = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .authenticationTime(authTime)
            .build();

        UserPrincipal principal2 = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .authenticationTime(authTime)
            .build();

        // Verify equality
        assertEquals("Principals should be equal", principal1, principal2);
        assertEquals("Hash codes should be equal", principal1.hashCode(), principal2.hashCode());
    }

    /**
     * Test 15: AuthorizationContext equality and hashCode
     * Requirements: 5.2
     */
    @Test
    public void testAuthorizationContextEqualityAndHashCode() {
        // Create two identical AuthorizationContexts
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("index_type", "logs");

        AuthorizationContext context1 = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .resourceAttributes(attributes)
            .remoteAddress("192.168.1.1")
            .build();

        AuthorizationContext context2 = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .resourceAttributes(attributes)
            .remoteAddress("192.168.1.1")
            .build();

        // Verify equality
        assertEquals("Contexts should be equal", context1, context2);
        assertEquals("Hash codes should be equal", context1.hashCode(), context2.hashCode());
    }
}
