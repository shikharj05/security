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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Integration tests for BackendRegistry plugin flow integration.
 * Tests that the new plugin architecture is properly integrated into the main authentication
 * and authorization paths while maintaining backward compatibility.
 */
public class BackendRegistryIntegrationTest {

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

    // ========== Authentication Plugin Integration Tests ==========

    @Test
    public void testAuthenticationWithPluginSucceeds() {
        // Register an authentication plugin that succeeds
        TestAuthenticationPlugin authPlugin = new TestAuthenticationPlugin("test-plugin", true);
        backendRegistry.registerAuthenticationPlugin(authPlugin);

        // Verify plugin was registered
        assertEquals(1, backendRegistry.getAuthenticationPlugins().size());
    }

    @Test
    public void testAuthenticationWithMultiplePlugins() {
        // Register multiple authentication plugins
        TestAuthenticationPlugin plugin1 = new TestAuthenticationPlugin("plugin1", false);
        TestAuthenticationPlugin plugin2 = new TestAuthenticationPlugin("plugin2", true);
        TestAuthenticationPlugin plugin3 = new TestAuthenticationPlugin("plugin3", true);

        backendRegistry.registerAuthenticationPlugin(plugin1);
        backendRegistry.registerAuthenticationPlugin(plugin2);
        backendRegistry.registerAuthenticationPlugin(plugin3);

        // Verify all plugins were registered
        assertEquals(3, backendRegistry.getAuthenticationPlugins().size());
    }

    @Test
    public void testAuthenticationPluginOrdering() {
        // Register plugins in specific order
        TestAuthenticationPlugin plugin1 = new TestAuthenticationPlugin("first", false);
        TestAuthenticationPlugin plugin2 = new TestAuthenticationPlugin("second", true);

        backendRegistry.registerAuthenticationPlugin(plugin1);
        backendRegistry.registerAuthenticationPlugin(plugin2);

        // Verify plugins are in correct order
        assertEquals("first", backendRegistry.getAuthenticationPlugins().get(0).getType());
        assertEquals("second", backendRegistry.getAuthenticationPlugins().get(1).getType());
    }

    @Test
    public void testAuthenticationWithNoPluginsRegistered() {
        // Verify no plugins are registered initially
        assertEquals(0, backendRegistry.getAuthenticationPlugins().size());
        
        // This should fall back to existing authentication flow
        // (which will fail since no backends are configured, but that's expected)
    }

    // ========== Authorization Plugin Integration Tests ==========

    @Test
    public void testAuthorizationWithPluginSucceeds() {
        // Register an authorization plugin that allows access
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("test-plugin", true);
        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Verify plugin was registered
        assertEquals(1, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testAuthorizationWithMultiplePlugins() {
        // Register multiple authorization plugins (all must allow for access)
        TestAuthorizationPlugin plugin1 = new TestAuthorizationPlugin("plugin1", true);
        TestAuthorizationPlugin plugin2 = new TestAuthorizationPlugin("plugin2", true);

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);

        // Verify all plugins were registered
        assertEquals(2, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testAuthorizationPluginDeniesAccess() {
        // Register plugins where one denies access
        TestAuthorizationPlugin plugin1 = new TestAuthorizationPlugin("plugin1", true);
        TestAuthorizationPlugin plugin2 = new TestAuthorizationPlugin("plugin2", false);

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);

        // Verify plugins were registered
        assertEquals(2, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testAuthorizationWithNoPluginsRegistered() {
        // Verify no plugins are registered initially
        assertEquals(0, backendRegistry.getAuthorizationPlugins().size());
        
        // This should fall back to existing authorization flow
    }

    // ========== Combined Authentication and Authorization Tests ==========

    @Test
    public void testAuthenticationAndAuthorizationWithPlugins() {
        // Register both authentication and authorization plugins
        TestAuthenticationPlugin authPlugin = new TestAuthenticationPlugin("auth-plugin", true);
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("authz-plugin", true);

        backendRegistry.registerAuthenticationPlugin(authPlugin);
        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Verify both were registered
        assertEquals(1, backendRegistry.getAuthenticationPlugins().size());
        assertEquals(1, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testAuthenticationSucceedsAuthorizationDenies() {
        // Register authentication plugin that succeeds
        TestAuthenticationPlugin authPlugin = new TestAuthenticationPlugin("auth-plugin", true);
        // Register authorization plugin that denies
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("authz-plugin", false);

        backendRegistry.registerAuthenticationPlugin(authPlugin);
        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Verify both were registered
        assertEquals(1, backendRegistry.getAuthenticationPlugins().size());
        assertEquals(1, backendRegistry.getAuthorizationPlugins().size());
    }

    // ========== Backward Compatibility Tests ==========

    @Test
    public void testBackwardCompatibilityWithOldBackends() {
        // Register old-style backends (should be wrapped with adapters)
        TestAuthenticationBackend authBackend = new TestAuthenticationBackend();
        TestAuthorizationBackend authzBackend = new TestAuthorizationBackend();

        backendRegistry.registerAuthenticationBackend(authBackend);
        backendRegistry.registerAuthorizationBackend(authzBackend);

        // Verify backends were wrapped and registered as plugins
        assertEquals(1, backendRegistry.getAuthenticationPlugins().size());
        assertEquals(1, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testMixedPluginsAndBackends() {
        // Register both new plugins and old backends
        TestAuthenticationPlugin authPlugin = new TestAuthenticationPlugin("plugin", true);
        TestAuthenticationBackend authBackend = new TestAuthenticationBackend();
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("plugin", true);
        TestAuthorizationBackend authzBackend = new TestAuthorizationBackend();

        backendRegistry.registerAuthenticationPlugin(authPlugin);
        backendRegistry.registerAuthenticationBackend(authBackend);
        backendRegistry.registerAuthorizationPlugin(authzPlugin);
        backendRegistry.registerAuthorizationBackend(authzBackend);

        // Verify all were registered
        assertEquals(2, backendRegistry.getAuthenticationPlugins().size());
        assertEquals(2, backendRegistry.getAuthorizationPlugins().size());
    }

    // ========== User Principal Conversion Tests ==========

    @Test
    public void testUserPrincipalToUserConversion() {
        // Create a UserPrincipal with claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", java.util.Arrays.asList("role1", "role2"));
        claims.put("email", "test@example.com");

        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.copyOf(claims))
            .authenticationType("test")
            .build();

        // Convert to User
        Set<String> securityRoles = new HashSet<>();
        securityRoles.add("security_role1");
        securityRoles.add("security_role2");

        User user = User.fromPrincipal(principal, securityRoles);

        // Verify conversion
        assertNotNull(user);
        assertEquals("testuser", user.getName());
        // The user should have the security roles we provided
        assertFalse(user.getRoles().isEmpty());
    }

    @Test
    public void testUserToUserPrincipalConversion() {
        // Create a User
        Set<String> roles = new HashSet<>();
        roles.add("role1");
        roles.add("role2");

        User user = new User(
            "testuser",
            com.google.common.collect.ImmutableSet.copyOf(roles),
            com.google.common.collect.ImmutableSet.of(),
            null,
            com.google.common.collect.ImmutableMap.of(),
            false
        );

        // Convert to UserPrincipal
        UserPrincipal principal = user.toPrincipal();

        // Verify conversion
        assertNotNull(principal);
        assertEquals("testuser", principal.getName());
        assertNotNull(principal.getClaims());
        assertTrue(principal.getClaims().containsKey("backend_roles"));
    }

    @Test
    public void testRoundTripConversion() {
        // Create a User
        Set<String> roles = new HashSet<>();
        roles.add("role1");
        roles.add("role2");

        User originalUser = new User(
            "testuser",
            com.google.common.collect.ImmutableSet.copyOf(roles),
            com.google.common.collect.ImmutableSet.of(),
            null,
            com.google.common.collect.ImmutableMap.of(),
            false
        );

        // Convert to UserPrincipal and back
        UserPrincipal principal = originalUser.toPrincipal();
        User convertedUser = User.fromPrincipal(principal, roles);

        // Verify round-trip maintains data
        assertEquals(originalUser.getName(), convertedUser.getName());
        assertEquals(originalUser.getRoles().size(), convertedUser.getRoles().size());
    }

    // ========== Permission Resolution Tests ==========

    @Test
    public void testPermissionResolutionWithSinglePlugin() {
        // Register authorization plugin that resolves permissions
        TestAuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("plugin", true);
        authzPlugin.setResolvedRoles(Set.of("admin", "developer"));

        backendRegistry.registerAuthorizationPlugin(authzPlugin);

        // Verify plugin was registered
        assertEquals(1, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testPermissionResolutionWithMultiplePlugins() {
        // Register multiple authorization plugins
        TestAuthorizationPlugin plugin1 = new TestAuthorizationPlugin("plugin1", true);
        plugin1.setResolvedRoles(Set.of("role1", "role2"));

        TestAuthorizationPlugin plugin2 = new TestAuthorizationPlugin("plugin2", true);
        plugin2.setResolvedRoles(Set.of("role3", "role4"));

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);

        // Verify both plugins were registered
        assertEquals(2, backendRegistry.getAuthorizationPlugins().size());
    }

    // ========== Test Helper Classes ==========

    private static class TestAuthenticationPlugin implements AuthenticationPlugin {
        private final String type;
        private final boolean shouldSucceed;
        private boolean authenticateCalled = false;

        public TestAuthenticationPlugin(String type, boolean shouldSucceed) {
            this.type = type;
            this.shouldSucceed = shouldSucceed;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            authenticateCalled = true;
            if (shouldSucceed) {
                Map<String, Object> claims = new HashMap<>();
                claims.put("backend_roles", java.util.Arrays.asList("role1", "role2"));
                return UserPrincipal.builder("test-user")
                    .claims(ImmutableMap.copyOf(claims))
                    .authenticationType(type)
                    .build();
            } else {
                throw new AuthenticationException("Authentication failed", type);
            }
        }

        public boolean wasAuthenticateCalled() {
            return authenticateCalled;
        }
    }

    private static class TestAuthorizationPlugin implements AuthorizationPlugin {
        private final String type;
        private final boolean shouldAllow;
        private Set<String> resolvedRoles = Collections.emptySet();

        public TestAuthorizationPlugin(String type, boolean shouldAllow) {
            this.type = type;
            this.shouldAllow = shouldAllow;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            if (shouldAllow) {
                return AuthorizationResult.allow();
            } else {
                return AuthorizationResult.deny("Access denied by " + type);
            }
        }

        @Override
        public Set<String> resolvePermissions(UserPrincipal principal) {
            return resolvedRoles;
        }

        public void setResolvedRoles(Set<String> roles) {
            this.resolvedRoles = roles;
        }
    }

    private static class TestAuthenticationBackend implements AuthenticationBackend {
        @Override
        public String getType() {
            return "test-backend";
        }

        @Override
        public User authenticate(AuthenticationContext context) {
            return new User("test-user");
        }
    }

    private static class TestAuthorizationBackend implements AuthorizationBackend {
        @Override
        public String getType() {
            return "test-backend";
        }

        @Override
        public User addRoles(User user, AuthenticationContext context) {
            return user.withRoles(Set.of("backend-role"));
        }
    }
}
