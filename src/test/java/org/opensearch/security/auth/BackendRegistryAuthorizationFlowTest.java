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

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationException;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Integration tests for BackendRegistry authorization plugin flow.
 * Tests the authorizeWithPlugins method and its interaction with authorization plugins.
 */
public class BackendRegistryAuthorizationFlowTest {

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
    public void testAuthorizeWithPlugins_NoPluginsRegistered() throws Exception {
        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins via reflection (it's private)
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should return null when no plugins are registered (fallback to existing flow)
        assertNull("Should return null when no plugins registered", result);
    }

    @Test
    public void testAuthorizeWithPlugins_SinglePluginAllows() throws Exception {
        // Register a plugin that allows access
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should allow access
        assertNotNull("Result should not be null", result);
        assertTrue("Should allow access", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_SinglePluginDenies() throws Exception {
        // Register a plugin that denies access
        backendRegistry.registerAuthorizationPlugin(new DenyAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access", result.isAllowed());
        assertNotNull("Should have deny reason", result.getReason());
    }

    @Test
    public void testAuthorizeWithPlugins_MultiplePluginsAllAllow() throws Exception {
        // Register multiple plugins that all allow access
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should allow access (all plugins allowed)
        assertNotNull("Result should not be null", result);
        assertTrue("Should allow access when all plugins allow", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_MultiplePluginsFirstDenies() throws Exception {
        // Register plugins where first one denies
        backendRegistry.registerAuthorizationPlugin(new DenyAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access (first plugin denied)
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when first plugin denies", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_MultiplePluginsMiddleDenies() throws Exception {
        // Register plugins where middle one denies
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new DenyAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access (middle plugin denied)
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when any plugin denies", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_MultiplePluginsLastDenies() throws Exception {
        // Register plugins where last one denies
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());
        backendRegistry.registerAuthorizationPlugin(new DenyAllAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access (last plugin denied)
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when last plugin denies", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_NullPrincipal() throws Exception {
        // Register a plugin
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create context but use null principal
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins with null principal
        AuthorizationResult result = invokeAuthorizeWithPlugins(null, context);

        // Should deny access with appropriate reason
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access with null principal", result.isAllowed());
        assertTrue("Reason should mention principal", result.getReason().contains("principal"));
    }

    @Test
    public void testAuthorizeWithPlugins_NullContext() throws Exception {
        // Register a plugin
        backendRegistry.registerAuthorizationPlugin(new AllowAllAuthorizationPlugin());

        // Create principal but use null context
        UserPrincipal principal = createTestPrincipal("testuser");

        // Call authorizeWithPlugins with null context
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, null);

        // Should deny access with appropriate reason
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access with null context", result.isAllowed());
        assertTrue("Reason should mention context", result.getReason().contains("context"));
    }

    @Test
    public void testAuthorizeWithPlugins_PluginReturnsNull() throws Exception {
        // Register a plugin that returns null
        backendRegistry.registerAuthorizationPlugin(new NullReturningAuthorizationPlugin());

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access when plugin returns null
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when plugin returns null", result.isAllowed());
        assertTrue("Reason should mention null result", result.getReason().contains("null"));
    }

    @Test
    public void testAuthorizeWithPlugins_PluginThrowsAuthorizationException() throws Exception {
        // Register a plugin that throws AuthorizationException
        backendRegistry.registerAuthorizationPlugin(new ExceptionThrowingAuthorizationPlugin(true));

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access when plugin throws exception
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when plugin throws exception", result.isAllowed());
        assertNotNull("Should have deny reason", result.getReason());
    }

    @Test
    public void testAuthorizeWithPlugins_PluginThrowsUnexpectedException() throws Exception {
        // Register a plugin that throws unexpected exception
        backendRegistry.registerAuthorizationPlugin(new ExceptionThrowingAuthorizationPlugin(false));

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Should deny access when plugin throws unexpected exception
        assertNotNull("Result should not be null", result);
        assertFalse("Should deny access when plugin throws unexpected exception", result.isAllowed());
        assertNotNull("Should have deny reason", result.getReason());
    }

    @Test
    public void testAuthorizeWithPlugins_RoleBasedPlugin() throws Exception {
        // Register a role-based authorization plugin
        backendRegistry.registerAuthorizationPlugin(new RoleBasedAuthorizationPlugin());

        // Create principal with admin role
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", Collections.singletonList("admin"));
        UserPrincipal adminPrincipal = UserPrincipal.builder("admin")
            .claims(claims)
            .authenticationType("test")
            .build();

        // Create context for admin action
        AuthorizationContext adminContext = createTestContext("cluster:admin/settings/update", "*");

        // Should allow admin action for admin user
        AuthorizationResult result = invokeAuthorizeWithPlugins(adminPrincipal, adminContext);
        assertNotNull("Result should not be null", result);
        assertTrue("Admin should be allowed admin action", result.isAllowed());

        // Create principal without admin role
        Map<String, Object> userClaims = new HashMap<>();
        userClaims.put("roles", Collections.singletonList("user"));
        UserPrincipal userPrincipal = UserPrincipal.builder("user")
            .claims(userClaims)
            .authenticationType("test")
            .build();

        // Should deny admin action for non-admin user
        result = invokeAuthorizeWithPlugins(userPrincipal, adminContext);
        assertNotNull("Result should not be null", result);
        assertFalse("Non-admin should be denied admin action", result.isAllowed());
    }

    @Test
    public void testAuthorizeWithPlugins_VerifyPluginOrder() throws Exception {
        // Register plugins in specific order
        OrderTrackingAuthorizationPlugin plugin1 = new OrderTrackingAuthorizationPlugin(1);
        OrderTrackingAuthorizationPlugin plugin2 = new OrderTrackingAuthorizationPlugin(2);
        OrderTrackingAuthorizationPlugin plugin3 = new OrderTrackingAuthorizationPlugin(3);

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);
        backendRegistry.registerAuthorizationPlugin(plugin3);

        // Create test principal and context
        UserPrincipal principal = createTestPrincipal("testuser");
        AuthorizationContext context = createTestContext("indices:data/read/search", "myindex");

        // Reset call order
        OrderTrackingAuthorizationPlugin.resetCallOrder();

        // Call authorizeWithPlugins
        AuthorizationResult result = invokeAuthorizeWithPlugins(principal, context);

        // Verify plugins were called in order
        assertEquals("First plugin should be called first", 1, plugin1.getCallOrder());
        assertEquals("Second plugin should be called second", 2, plugin2.getCallOrder());
        assertEquals("Third plugin should be called third", 3, plugin3.getCallOrder());
    }

    // ========== Helper Methods ==========

    /**
     * Invokes the private authorizeWithPlugins method via reflection.
     */
    private AuthorizationResult invokeAuthorizeWithPlugins(UserPrincipal principal, AuthorizationContext context) throws Exception {
        Method method = BackendRegistry.class.getDeclaredMethod(
            "authorizeWithPlugins",
            UserPrincipal.class,
            AuthorizationContext.class
        );
        method.setAccessible(true);
        return (AuthorizationResult) method.invoke(backendRegistry, principal, context);
    }

    /**
     * Creates a test UserPrincipal.
     */
    private UserPrincipal createTestPrincipal(String username) {
        return UserPrincipal.builder(username)
            .authenticationType("test")
            .build();
    }

    /**
     * Creates a test AuthorizationContext.
     */
    private AuthorizationContext createTestContext(String action, String resource) {
        return AuthorizationContext.builder(action, resource)
            .remoteAddress("127.0.0.1")
            .build();
    }

    // ========== Test Plugin Implementations ==========

    /**
     * Plugin that always allows access.
     */
    private static class AllowAllAuthorizationPlugin implements AuthorizationPlugin {
        @Override
        public String getType() {
            return "allow-all";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            return AuthorizationResult.allow();
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }

    /**
     * Plugin that always denies access.
     */
    private static class DenyAllAuthorizationPlugin implements AuthorizationPlugin {
        @Override
        public String getType() {
            return "deny-all";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            return AuthorizationResult.deny("Access denied by test plugin");
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }

    /**
     * Plugin that returns null.
     */
    private static class NullReturningAuthorizationPlugin implements AuthorizationPlugin {
        @Override
        public String getType() {
            return "null-returning";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            return null;
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }

    /**
     * Plugin that throws exceptions.
     */
    private static class ExceptionThrowingAuthorizationPlugin implements AuthorizationPlugin {
        private final boolean throwAuthorizationException;

        public ExceptionThrowingAuthorizationPlugin(boolean throwAuthorizationException) {
            this.throwAuthorizationException = throwAuthorizationException;
        }

        @Override
        public String getType() {
            return "exception-throwing";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            if (throwAuthorizationException) {
                // Since AuthorizationException is a checked exception and the interface doesn't declare it,
                // we wrap it in a RuntimeException
                throw new RuntimeException(
                    new AuthorizationException(
                        principal.getName(),
                        context.getResource(),
                        context.getAction(),
                        "Test authorization exception"
                    )
                );
            } else {
                throw new RuntimeException("Test unexpected exception");
            }
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }

    /**
     * Plugin that implements role-based authorization.
     */
    private static class RoleBasedAuthorizationPlugin implements AuthorizationPlugin {
        @Override
        public String getType() {
            return "role-based";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            // Extract roles from claims
            @SuppressWarnings("unchecked")
            java.util.List<String> roles = (java.util.List<String>) principal.getClaims().get("roles");

            if (roles == null || roles.isEmpty()) {
                return AuthorizationResult.deny("No roles found in principal");
            }

            // Check if action requires admin role
            if (context.getAction().startsWith("cluster:admin")) {
                if (roles.contains("admin")) {
                    return AuthorizationResult.allow();
                } else {
                    return AuthorizationResult.deny("Admin role required for action: " + context.getAction());
                }
            }

            // Allow all other actions
            return AuthorizationResult.allow();
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            @SuppressWarnings("unchecked")
            java.util.List<String> roles = (java.util.List<String>) principal.getClaims().get("roles");
            return roles != null ? new java.util.HashSet<>(roles) : Collections.emptySet();
        }
    }

    /**
     * Plugin that tracks the order in which it was called.
     */
    private static class OrderTrackingAuthorizationPlugin implements AuthorizationPlugin {
        private static int globalCallCounter = 0;
        private final int pluginId;
        private int callOrder = -1;

        public OrderTrackingAuthorizationPlugin(int pluginId) {
            this.pluginId = pluginId;
        }

        public static void resetCallOrder() {
            globalCallCounter = 0;
        }

        public int getCallOrder() {
            return callOrder;
        }

        @Override
        public String getType() {
            return "order-tracking-" + pluginId;
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            callOrder = ++globalCallCounter;
            return AuthorizationResult.allow();
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }
}
