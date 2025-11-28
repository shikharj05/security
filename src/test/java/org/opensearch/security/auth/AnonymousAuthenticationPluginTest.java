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

package org.opensearch.security.auth;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Tests for anonymous authentication with plugin architecture support.
 * Verifies that anonymous users can be properly represented as UserPrincipal
 * and work correctly with authorization plugins.
 */
public class AnonymousAuthenticationPluginTest {

    private BackendRegistry backendRegistry;
    private Settings settings;
    private AdminDNs adminDns;
    private XFFResolver xffResolver;
    private AuditLog auditLog;
    private ThreadPool threadPool;
    private ClusterInfoHolder clusterInfoHolder;

    @Before
    public void setUp() {
        settings = Settings.EMPTY;
        adminDns = mock(AdminDNs.class);
        xffResolver = mock(XFFResolver.class);
        auditLog = mock(AuditLog.class);
        threadPool = mock(ThreadPool.class);
        clusterInfoHolder = mock(ClusterInfoHolder.class);

        backendRegistry = new BackendRegistry(
            settings,
            adminDns,
            xffResolver,
            auditLog,
            threadPool,
            clusterInfoHolder
        );
    }

    @Test
    public void testAnonymousUserToPrincipalConversion() {
        // Get the anonymous user
        User anonymousUser = User.ANONYMOUS;

        // Convert to UserPrincipal
        UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

        // Verify the principal was created correctly
        assertNotNull("Anonymous principal should not be null", anonymousPrincipal);
        assertEquals(
            "Anonymous principal name should match user name",
            anonymousUser.getName(),
            anonymousPrincipal.getName()
        );
        assertEquals(
            "Anonymous principal should have legacy authentication type",
            "legacy",
            anonymousPrincipal.getAuthenticationType()
        );

        // Verify claims contain backend roles
        Map<String, Object> claims = anonymousPrincipal.getClaims();
        assertNotNull("Claims should not be null", claims);
        assertTrue("Claims should contain backend_roles", claims.containsKey("backend_roles"));
    }

    @Test
    public void testAnonymousUserWithAuthorizationPlugin() {
        // Register a test authorization plugin
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin();
        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Get the anonymous user and convert to principal
        User anonymousUser = User.ANONYMOUS;
        UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

        // Create authorization context
        AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .build();

        // Test authorization
        AuthorizationResult result = authzPlugin.authorize(anonymousPrincipal, context);

        // Verify the plugin was called and returned a result
        assertNotNull("Authorization result should not be null", result);
        assertTrue("Test plugin should allow access", result.isAllowed());
        assertTrue("Plugin should have been called", authzPlugin.wasAuthorizeCalled());
    }

    @Test
    public void testAnonymousUserWithDenyingAuthorizationPlugin() {
        // Register a denying authorization plugin
        DenyingAuthorizationPlugin authzPlugin = new DenyingAuthorizationPlugin();
        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Get the anonymous user and convert to principal
        User anonymousUser = User.ANONYMOUS;
        UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

        // Create authorization context
        AuthorizationContext context = AuthorizationContext.builder("indices:data/write/index", "protected-index")
            .build();

        // Test authorization
        AuthorizationResult result = authzPlugin.authorize(anonymousPrincipal, context);

        // Verify the plugin denied access
        assertNotNull("Authorization result should not be null", result);
        assertFalse("Denying plugin should deny access", result.isAllowed());
        assertEquals("Reason should be set", "Anonymous users not allowed", result.getReason());
    }

    @Test
    public void testAnonymousUserPrincipalHasCorrectClaims() {
        // Get the anonymous user
        User anonymousUser = User.ANONYMOUS;

        // Convert to UserPrincipal
        UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

        // Verify claims structure
        Map<String, Object> claims = anonymousPrincipal.getClaims();
        assertNotNull("Claims should not be null", claims);

        // Verify backend_roles claim
        assertTrue("Claims should contain backend_roles", claims.containsKey("backend_roles"));
        Object backendRoles = claims.get("backend_roles");
        assertNotNull("Backend roles should not be null", backendRoles);

        // Verify the anonymous user's backend role is present
        assertTrue("Backend roles should be a collection", backendRoles instanceof java.util.Collection);
        @SuppressWarnings("unchecked")
        java.util.Collection<String> roles = (java.util.Collection<String>) backendRoles;
        assertTrue(
            "Backend roles should contain anonymous backend role",
            roles.contains("opendistro_security_anonymous_backendrole")
        );
    }

    @Test
    public void testAnonymousUserRoundTripConversion() {
        // Get the anonymous user
        User originalUser = User.ANONYMOUS;

        // Convert to UserPrincipal
        UserPrincipal principal = originalUser.toPrincipal();

        // Convert back to User (simulating what would happen in authorization)
        User convertedUser = User.fromPrincipal(principal, Collections.emptySet());

        // Verify the conversion preserved the username
        assertEquals("Username should be preserved", originalUser.getName(), convertedUser.getName());

        // Verify backend roles are preserved
        assertTrue(
            "Backend roles should be preserved",
            convertedUser.getRoles().containsAll(originalUser.getRoles())
        );
    }

    @Test
    public void testMultipleAuthorizationPluginsWithAnonymousUser() {
        // Register multiple authorization plugins
        TestAuthorizationPlugin plugin1 = new TestAuthorizationPlugin();
        TestAuthorizationPlugin plugin2 = new TestAuthorizationPlugin();

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);

        // Get the anonymous user and convert to principal
        User anonymousUser = User.ANONYMOUS;
        UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

        // Create authorization context
        AuthorizationContext context = AuthorizationContext.builder("indices:data/read/get", "test-index")
            .build();

        // Test authorization with both plugins
        AuthorizationResult result1 = plugin1.authorize(anonymousPrincipal, context);
        AuthorizationResult result2 = plugin2.authorize(anonymousPrincipal, context);

        // Verify both plugins were called
        assertTrue("First plugin should have been called", plugin1.wasAuthorizeCalled());
        assertTrue("Second plugin should have been called", plugin2.wasAuthorizeCalled());
        assertTrue("Both plugins should allow access", result1.isAllowed() && result2.isAllowed());
    }

    // ========== Test Helper Classes ==========

    /**
     * Test authorization plugin that allows all access and tracks if it was called.
     */
    private static class TestAuthorizationPlugin implements AuthorizationPlugin {
        private boolean authorizeCalled = false;

        @Override
        public String getType() {
            return "test-authz-plugin";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            authorizeCalled = true;
            return AuthorizationResult.allow();
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }

        public boolean wasAuthorizeCalled() {
            return authorizeCalled;
        }
    }

    /**
     * Test authorization plugin that denies access to anonymous users.
     */
    private static class DenyingAuthorizationPlugin implements AuthorizationPlugin {

        @Override
        public String getType() {
            return "denying-authz-plugin";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            // Deny access for anonymous users
            if ("opendistro_security_anonymous".equals(principal.getName())) {
                return AuthorizationResult.deny("Anonymous users not allowed");
            }
            return AuthorizationResult.allow();
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }
}
