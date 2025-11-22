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
import java.util.List;

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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Tests for BackendRegistry plugin registration methods.
 */
public class BackendRegistryPluginTest {

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
    public void testRegisterAuthenticationPlugin() {
        // Create a test authentication plugin
        AuthenticationPlugin plugin = new TestAuthenticationPlugin();

        // Register the plugin
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Verify the plugin was registered
        List<AuthenticationPlugin> plugins = backendRegistry.getAuthenticationPlugins();
        assertEquals(1, plugins.size());
        assertEquals(plugin, plugins.get(0));
    }

    @Test
    public void testRegisterAuthenticationPluginNull() {
        // Attempt to register null plugin should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            backendRegistry.registerAuthenticationPlugin(null);
        });
    }

    @Test
    public void testRegisterMultipleAuthenticationPlugins() {
        // Register multiple plugins
        AuthenticationPlugin plugin1 = new TestAuthenticationPlugin("plugin1");
        AuthenticationPlugin plugin2 = new TestAuthenticationPlugin("plugin2");

        backendRegistry.registerAuthenticationPlugin(plugin1);
        backendRegistry.registerAuthenticationPlugin(plugin2);

        // Verify both plugins were registered in order
        List<AuthenticationPlugin> plugins = backendRegistry.getAuthenticationPlugins();
        assertEquals(2, plugins.size());
        assertEquals(plugin1, plugins.get(0));
        assertEquals(plugin2, plugins.get(1));
    }

    @Test
    public void testRegisterAuthorizationPlugin() {
        // Create a test authorization plugin
        AuthorizationPlugin plugin = new TestAuthorizationPlugin();

        // Register the plugin
        backendRegistry.registerAuthorizationPlugin(plugin);

        // Verify the plugin was registered
        List<AuthorizationPlugin> plugins = backendRegistry.getAuthorizationPlugins();
        assertEquals(1, plugins.size());
        assertEquals(plugin, plugins.get(0));
    }

    @Test
    public void testRegisterAuthorizationPluginNull() {
        // Attempt to register null plugin should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            backendRegistry.registerAuthorizationPlugin(null);
        });
    }

    @Test
    public void testRegisterMultipleAuthorizationPlugins() {
        // Register multiple plugins
        AuthorizationPlugin plugin1 = new TestAuthorizationPlugin("plugin1");
        AuthorizationPlugin plugin2 = new TestAuthorizationPlugin("plugin2");

        backendRegistry.registerAuthorizationPlugin(plugin1);
        backendRegistry.registerAuthorizationPlugin(plugin2);

        // Verify both plugins were registered in order
        List<AuthorizationPlugin> plugins = backendRegistry.getAuthorizationPlugins();
        assertEquals(2, plugins.size());
        assertEquals(plugin1, plugins.get(0));
        assertEquals(plugin2, plugins.get(1));
    }

    @Test
    public void testRegisterAuthenticationBackend() {
        // Create a test authentication backend
        AuthenticationBackend backend = new TestAuthenticationBackend();

        // Register the backend (should be wrapped with adapter)
        backendRegistry.registerAuthenticationBackend(backend);

        // Verify the backend was registered as a plugin
        List<AuthenticationPlugin> plugins = backendRegistry.getAuthenticationPlugins();
        assertEquals(1, plugins.size());
        assertNotNull(plugins.get(0));
        assertEquals("test-backend", plugins.get(0).getType());
    }

    @Test
    public void testRegisterAuthenticationBackendNull() {
        // Attempt to register null backend should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            backendRegistry.registerAuthenticationBackend(null);
        });
    }

    @Test
    public void testRegisterAuthorizationBackend() {
        // Create a test authorization backend
        AuthorizationBackend backend = new TestAuthorizationBackend();

        // Register the backend (should be wrapped with adapter)
        backendRegistry.registerAuthorizationBackend(backend);

        // Verify the backend was registered as a plugin
        List<AuthorizationPlugin> plugins = backendRegistry.getAuthorizationPlugins();
        assertEquals(1, plugins.size());
        assertNotNull(plugins.get(0));
        assertEquals("test-backend", plugins.get(0).getType());
    }

    @Test
    public void testRegisterAuthorizationBackendNull() {
        // Attempt to register null backend should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            backendRegistry.registerAuthorizationBackend(null);
        });
    }

    @Test
    public void testGetAuthenticationPluginsReturnsUnmodifiableList() {
        // Register a plugin
        backendRegistry.registerAuthenticationPlugin(new TestAuthenticationPlugin());

        // Get the list
        List<AuthenticationPlugin> plugins = backendRegistry.getAuthenticationPlugins();

        // Verify it's unmodifiable
        assertThrows(UnsupportedOperationException.class, () -> {
            plugins.add(new TestAuthenticationPlugin());
        });
    }

    @Test
    public void testGetAuthorizationPluginsReturnsUnmodifiableList() {
        // Register a plugin
        backendRegistry.registerAuthorizationPlugin(new TestAuthorizationPlugin());

        // Get the list
        List<AuthorizationPlugin> plugins = backendRegistry.getAuthorizationPlugins();

        // Verify it's unmodifiable
        assertThrows(UnsupportedOperationException.class, () -> {
            plugins.add(new TestAuthorizationPlugin());
        });
    }

    @Test
    public void testMixedRegistration() {
        // Register both plugins and backends
        AuthenticationPlugin authPlugin = new TestAuthenticationPlugin("plugin");
        AuthenticationBackend authBackend = new TestAuthenticationBackend();
        AuthorizationPlugin authzPlugin = new TestAuthorizationPlugin("plugin");
        AuthorizationBackend authzBackend = new TestAuthorizationBackend();

        backendRegistry.registerAuthenticationPlugin(authPlugin);
        backendRegistry.registerAuthenticationBackend(authBackend);
        backendRegistry.registerAuthorizationPlugin(authzPlugin);
        backendRegistry.registerAuthorizationBackend(authzBackend);

        // Verify all were registered
        assertEquals(2, backendRegistry.getAuthenticationPlugins().size());
        assertEquals(2, backendRegistry.getAuthorizationPlugins().size());
    }

    @Test
    public void testRegisterConvertedAuthenticationPlugin() {
        // Converted backends now only implement AuthenticationPlugin, not AuthenticationBackend
        // They should be registered directly using registerAuthenticationPlugin
        ConvertedAuthenticationPlugin plugin = new ConvertedAuthenticationPlugin();

        // Register the plugin directly
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Verify the plugin was registered
        List<AuthenticationPlugin> plugins = backendRegistry.getAuthenticationPlugins();
        assertEquals(1, plugins.size());
        assertEquals(plugin, plugins.get(0));
        assertEquals("converted-plugin", plugins.get(0).getType());
    }

    @Test
    public void testRegisterConvertedAuthorizationPlugin() {
        // Converted backends now only implement AuthorizationPlugin, not AuthorizationBackend
        // They should be registered directly using registerAuthorizationPlugin
        ConvertedAuthorizationPlugin plugin = new ConvertedAuthorizationPlugin();

        // Register the plugin directly
        backendRegistry.registerAuthorizationPlugin(plugin);

        // Verify the plugin was registered
        List<AuthorizationPlugin> plugins = backendRegistry.getAuthorizationPlugins();
        assertEquals(1, plugins.size());
        assertEquals(plugin, plugins.get(0));
        assertEquals("converted-plugin", plugins.get(0).getType());
    }

    @Test
    public void testRegisterMixedConvertedAndUnconvertedBackends() {
        // Register a mix of converted plugins and unconverted backends
        ConvertedAuthenticationPlugin convertedAuthPlugin = new ConvertedAuthenticationPlugin();
        AuthenticationBackend unconvertedAuthBackend = new TestAuthenticationBackend();
        ConvertedAuthorizationPlugin convertedAuthzPlugin = new ConvertedAuthorizationPlugin();
        AuthorizationBackend unconvertedAuthzBackend = new TestAuthorizationBackend();

        // Converted backends are registered as plugins
        backendRegistry.registerAuthenticationPlugin(convertedAuthPlugin);
        // Unconverted backends are registered as backends (will be wrapped)
        backendRegistry.registerAuthenticationBackend(unconvertedAuthBackend);
        
        backendRegistry.registerAuthorizationPlugin(convertedAuthzPlugin);
        backendRegistry.registerAuthorizationBackend(unconvertedAuthzBackend);

        // Verify all were registered
        List<AuthenticationPlugin> authPlugins = backendRegistry.getAuthenticationPlugins();
        List<AuthorizationPlugin> authzPlugins = backendRegistry.getAuthorizationPlugins();
        
        assertEquals(2, authPlugins.size());
        assertEquals(2, authzPlugins.size());
        
        // Verify converted plugins are registered directly
        assertTrue("First auth plugin should be converted plugin", authPlugins.get(0) instanceof ConvertedAuthenticationPlugin);
        assertTrue("First authz plugin should be converted plugin", authzPlugins.get(0) instanceof ConvertedAuthorizationPlugin);
        
        // Verify unconverted backends are wrapped (not the original backend type)
        assertTrue("Second auth plugin should not be TestAuthenticationBackend", !(authPlugins.get(1) instanceof TestAuthenticationBackend));
        assertTrue("Second authz plugin should not be TestAuthorizationBackend", !(authzPlugins.get(1) instanceof TestAuthorizationBackend));
    }

    @Test
    public void testBackwardCompatibilityWithUnconvertedBackends() {
        // This test ensures that unconverted backends still work correctly
        AuthenticationBackend authBackend = new TestAuthenticationBackend();
        AuthorizationBackend authzBackend = new TestAuthorizationBackend();

        backendRegistry.registerAuthenticationBackend(authBackend);
        backendRegistry.registerAuthorizationBackend(authzBackend);

        // Verify backends were registered (wrapped with adapters)
        List<AuthenticationPlugin> authPlugins = backendRegistry.getAuthenticationPlugins();
        List<AuthorizationPlugin> authzPlugins = backendRegistry.getAuthorizationPlugins();
        
        assertEquals(1, authPlugins.size());
        assertEquals(1, authzPlugins.size());
        
        // Verify the type is preserved through the adapter
        assertEquals("test-backend", authPlugins.get(0).getType());
        assertEquals("test-backend", authzPlugins.get(0).getType());
    }

    // ========== Test Helper Classes ==========

    private static class TestAuthenticationPlugin implements AuthenticationPlugin {
        private final String type;

        public TestAuthenticationPlugin() {
            this("test-plugin");
        }

        public TestAuthenticationPlugin(String type) {
            this.type = type;
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
            return UserPrincipal.builder("test-user")
                .authenticationType(type)
                .build();
        }
    }

    private static class TestAuthorizationPlugin implements AuthorizationPlugin {
        private final String type;

        public TestAuthorizationPlugin() {
            this("test-plugin");
        }

        public TestAuthorizationPlugin(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            return AuthorizationResult.allow();
        }

        @Override
        public java.util.Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
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
            return user;
        }
    }

    /**
     * Test class representing a converted authentication plugin.
     * Converted backends (like InternalAuthenticationBackend, LDAPAuthenticationBackend2, etc.)
     * now ONLY implement AuthenticationPlugin, not AuthenticationBackend.
     * They are registered directly using registerAuthenticationPlugin().
     */
    private static class ConvertedAuthenticationPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "converted-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            return UserPrincipal.builder("converted-user")
                .authenticationType(getType())
                .build();
        }
    }

    /**
     * Test class representing a converted authorization plugin.
     * Converted backends (like LDAPAuthorizationBackend2) now ONLY implement
     * AuthorizationPlugin, not AuthorizationBackend.
     * They are registered directly using registerAuthorizationPlugin().
     */
    private static class ConvertedAuthorizationPlugin implements AuthorizationPlugin {
        @Override
        public String getType() {
            return "converted-plugin";
        }

        @Override
        public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
            return AuthorizationResult.allow();
        }

        @Override
        public java.util.Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }
}
