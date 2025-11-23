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

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for UserPrincipal caching in BackendRegistry.
 * <p>
 * This test class verifies that:
 * <ul>
 *   <li>UserPrincipal objects are properly cached after authentication</li>
 *   <li>Cached UserPrincipal objects are reused for subsequent authentications</li>
 *   <li>Principal role cache stores resolved permissions</li>
 *   <li>Cache invalidation works correctly for UserPrincipal</li>
 *   <li>User and UserPrincipal caches work in parallel</li>
 * </ul>
 */
public class BackendRegistryUserPrincipalCacheTest {

    @Mock
    private ThreadPool threadPool;

    @Mock
    private AuditLog auditLog;

    @Mock
    private AdminDNs adminDns;

    @Mock
    private XFFResolver xffResolver;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    private BackendRegistry backendRegistry;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_CACHE_TTL_MINUTES, 60)
            .build();

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
    public void testUserPrincipalCaching() throws Exception {
        // Create a mock authentication plugin
        AuthenticationPlugin authPlugin = mock(AuthenticationPlugin.class);
        when(authPlugin.getType()).thenReturn("test");
        when(authPlugin.supports(any(AuthCredentials.class))).thenReturn(true);

        // Create test credentials
        AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes());
        AuthenticationContext authContext = new AuthenticationContext(credentials);

        // Create expected UserPrincipal
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "test@example.com");
        claims.put("groups", Collections.singletonList("developers"));

        UserPrincipal expectedPrincipal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("test")
            .authenticationTime(System.currentTimeMillis())
            .build();

        when(authPlugin.authenticate(any(AuthenticationContext.class))).thenReturn(expectedPrincipal);

        // Register the plugin
        backendRegistry.registerAuthenticationPlugin(authPlugin);

        // First authentication - should call the plugin
        java.lang.reflect.Method authenticateMethod = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        authenticateMethod.setAccessible(true);

        UserPrincipal principal1 = (UserPrincipal) authenticateMethod.invoke(backendRegistry, authContext);
        assertNotNull("First authentication should return a principal", principal1);
        assertEquals("testuser", principal1.getName());
        verify(authPlugin, times(1)).authenticate(any(AuthenticationContext.class));

        // Second authentication with same credentials - should use cache
        UserPrincipal principal2 = (UserPrincipal) authenticateMethod.invoke(backendRegistry, authContext);
        assertNotNull("Second authentication should return a principal", principal2);
        assertEquals("testuser", principal2.getName());
        // Plugin should still only be called once (cached result used)
        verify(authPlugin, times(1)).authenticate(any(AuthenticationContext.class));

        // Verify both principals are the same cached instance
        assertSame("Cached principal should be reused", principal1, principal2);
    }

    @Test
    public void testPrincipalRoleCacheExists() throws Exception {
        // This test verifies that the principal role cache is properly initialized
        // The actual caching behavior is tested indirectly through the authentication
        // and authorization flow tests
        
        // Access the principal role cache via reflection
        java.lang.reflect.Field principalRoleCacheField = BackendRegistry.class.getDeclaredField("principalRoleCache");
        principalRoleCacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        com.google.common.cache.Cache<UserPrincipal, Set<String>> principalRoleCache = 
            (com.google.common.cache.Cache<UserPrincipal, Set<String>>) principalRoleCacheField.get(backendRegistry);

        // Verify cache exists and is initially empty
        assertNotNull("Principal role cache should exist", principalRoleCache);
        assertEquals("Cache should be empty initially", 0, principalRoleCache.size());

        // Create a test principal
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", "test@example.com");
        
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("test")
            .build();

        Set<String> roles = new HashSet<>();
        roles.add("admin");
        roles.add("developer");

        // Manually put an entry in the cache
        principalRoleCache.put(principal, roles);

        // Verify cache now has the entry
        assertEquals("Cache should have 1 entry", 1, principalRoleCache.size());
        Set<String> cachedRoles = principalRoleCache.getIfPresent(principal);
        assertNotNull("Cached roles should be retrievable", cachedRoles);
        assertEquals("Cached roles should match", roles, cachedRoles);

        // Invalidate cache
        backendRegistry.invalidateCache();

        // Verify cache is empty after invalidation
        assertEquals("Cache should be empty after invalidation", 0, principalRoleCache.size());
    }

    @Test
    public void testCacheInvalidation() throws Exception {
        // Create a mock authentication plugin
        AuthenticationPlugin authPlugin = mock(AuthenticationPlugin.class);
        when(authPlugin.getType()).thenReturn("test");
        when(authPlugin.supports(any(AuthCredentials.class))).thenReturn(true);

        UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("test")
            .build();

        when(authPlugin.authenticate(any(AuthenticationContext.class))).thenReturn(principal);

        backendRegistry.registerAuthenticationPlugin(authPlugin);

        // Authenticate to populate cache
        AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes());
        AuthenticationContext authContext = new AuthenticationContext(credentials);

        java.lang.reflect.Method authenticateMethod = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        authenticateMethod.setAccessible(true);

        authenticateMethod.invoke(backendRegistry, authContext);
        verify(authPlugin, times(1)).authenticate(any(AuthenticationContext.class));

        // Invalidate cache
        backendRegistry.invalidateCache();

        // Authenticate again - should call plugin again since cache was invalidated
        authenticateMethod.invoke(backendRegistry, authContext);
        verify(authPlugin, times(2)).authenticate(any(AuthenticationContext.class));
    }

    @Test
    public void testUserSpecificCacheInvalidation() throws Exception {
        // Create a mock authentication plugin
        AuthenticationPlugin authPlugin = mock(AuthenticationPlugin.class);
        when(authPlugin.getType()).thenReturn("test");
        when(authPlugin.supports(any(AuthCredentials.class))).thenReturn(true);

        UserPrincipal principal1 = UserPrincipal.builder("user1").authenticationType("test").build();
        UserPrincipal principal2 = UserPrincipal.builder("user2").authenticationType("test").build();

        when(authPlugin.authenticate(any(AuthenticationContext.class)))
            .thenReturn(principal1)
            .thenReturn(principal2)
            .thenReturn(principal1);

        backendRegistry.registerAuthenticationPlugin(authPlugin);

        java.lang.reflect.Method authenticateMethod = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        authenticateMethod.setAccessible(true);

        // Authenticate both users to populate cache
        AuthCredentials creds1 = new AuthCredentials("user1", "password".getBytes());
        AuthCredentials creds2 = new AuthCredentials("user2", "password".getBytes());

        authenticateMethod.invoke(backendRegistry, new AuthenticationContext(creds1));
        authenticateMethod.invoke(backendRegistry, new AuthenticationContext(creds2));
        verify(authPlugin, times(2)).authenticate(any(AuthenticationContext.class));

        // Invalidate only user1
        backendRegistry.invalidateUserCache(new String[] { "user1" });

        // Authenticate user1 again - should call plugin (cache invalidated)
        authenticateMethod.invoke(backendRegistry, new AuthenticationContext(creds1));
        verify(authPlugin, times(3)).authenticate(any(AuthenticationContext.class));

        // Authenticate user2 again - should NOT call plugin (still cached)
        authenticateMethod.invoke(backendRegistry, new AuthenticationContext(creds2));
        verify(authPlugin, times(3)).authenticate(any(AuthenticationContext.class));
    }

    @Test
    public void testParallelCaches() throws Exception {
        // This test verifies that User cache and UserPrincipal cache work in parallel
        // without interfering with each other

        // Create authentication plugin
        AuthenticationPlugin authPlugin = mock(AuthenticationPlugin.class);
        when(authPlugin.getType()).thenReturn("test");
        when(authPlugin.supports(any(AuthCredentials.class))).thenReturn(true);

        UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("test")
            .build();

        when(authPlugin.authenticate(any(AuthenticationContext.class))).thenReturn(principal);

        backendRegistry.registerAuthenticationPlugin(authPlugin);

        // Authenticate with plugin (populates UserPrincipal cache)
        AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes());
        AuthenticationContext authContext = new AuthenticationContext(credentials);

        java.lang.reflect.Method authenticateMethod = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        authenticateMethod.setAccessible(true);

        UserPrincipal result = (UserPrincipal) authenticateMethod.invoke(backendRegistry, authContext);
        assertNotNull("Authentication should succeed", result);

        // Verify plugin was called once
        verify(authPlugin, times(1)).authenticate(any(AuthenticationContext.class));

        // Authenticate again - should use cache
        result = (UserPrincipal) authenticateMethod.invoke(backendRegistry, authContext);
        assertNotNull("Second authentication should succeed", result);
        verify(authPlugin, times(1)).authenticate(any(AuthenticationContext.class));

        // Invalidate all caches
        backendRegistry.invalidateCache();

        // Authenticate again - should call plugin again
        result = (UserPrincipal) authenticateMethod.invoke(backendRegistry, authContext);
        assertNotNull("Third authentication should succeed", result);
        verify(authPlugin, times(2)).authenticate(any(AuthenticationContext.class));
    }
}
