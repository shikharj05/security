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

import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

/**
 * Integration tests for BackendRegistry authentication plugin flow.
 * Tests the authenticateWithPlugins method and its integration with the registry.
 */
public class BackendRegistryAuthenticationFlowTest {

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
    public void testAuthenticateWithPlugins_NoPluginsRegistered() throws Exception {
        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins via reflection (it's private)
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when no plugins are registered
        assertNull("Should return null when no plugins registered", result);
    }

    @Test
    public void testAuthenticateWithPlugins_NullCredentials() throws Exception {
        // Register a plugin
        backendRegistry.registerAuthenticationPlugin(new SuccessfulAuthenticationPlugin());

        // Create context with null credentials
        AuthenticationContext context = new AuthenticationContext(null);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when credentials are null
        assertNull("Should return null when credentials are null", result);
    }

    @Test
    public void testAuthenticateWithPlugins_SinglePluginSuccess() throws Exception {
        // Register a successful plugin
        SuccessfulAuthenticationPlugin plugin = new SuccessfulAuthenticationPlugin();
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return UserPrincipal from successful plugin
        assertNotNull("Should return UserPrincipal from successful plugin", result);
        assertEquals("testuser", result.getName());
        assertEquals("successful-plugin", result.getAuthenticationType());
    }

    @Test
    public void testAuthenticateWithPlugins_SinglePluginFailure() throws Exception {
        // Register a failing plugin
        FailingAuthenticationPlugin plugin = new FailingAuthenticationPlugin();
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when plugin fails
        assertNull("Should return null when plugin fails", result);
    }

    @Test
    public void testAuthenticateWithPlugins_MultiplePlugins_FirstSucceeds() throws Exception {
        // Register multiple plugins - first one succeeds
        backendRegistry.registerAuthenticationPlugin(new SuccessfulAuthenticationPlugin("plugin1"));
        backendRegistry.registerAuthenticationPlugin(new SuccessfulAuthenticationPlugin("plugin2"));

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return UserPrincipal from first plugin
        assertNotNull("Should return UserPrincipal from first plugin", result);
        assertEquals("testuser", result.getName());
        assertEquals("plugin1", result.getAuthenticationType());
    }

    @Test
    public void testAuthenticateWithPlugins_MultiplePlugins_SecondSucceeds() throws Exception {
        // Register multiple plugins - first fails, second succeeds
        backendRegistry.registerAuthenticationPlugin(new FailingAuthenticationPlugin());
        backendRegistry.registerAuthenticationPlugin(new SuccessfulAuthenticationPlugin("plugin2"));

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return UserPrincipal from second plugin
        assertNotNull("Should return UserPrincipal from second plugin", result);
        assertEquals("testuser", result.getName());
        assertEquals("plugin2", result.getAuthenticationType());
    }

    @Test
    public void testAuthenticateWithPlugins_MultiplePlugins_AllFail() throws Exception {
        // Register multiple failing plugins
        backendRegistry.registerAuthenticationPlugin(new FailingAuthenticationPlugin());
        backendRegistry.registerAuthenticationPlugin(new FailingAuthenticationPlugin());

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when all plugins fail
        assertNull("Should return null when all plugins fail", result);
    }

    @Test
    public void testAuthenticateWithPlugins_PluginDoesNotSupportCredentials() throws Exception {
        // Register a plugin that doesn't support the credentials
        backendRegistry.registerAuthenticationPlugin(new UnsupportedCredentialsPlugin());

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when plugin doesn't support credentials
        assertNull("Should return null when plugin doesn't support credentials", result);
    }

    @Test
    public void testAuthenticateWithPlugins_PluginReturnsNull() throws Exception {
        // Register a plugin that returns null
        backendRegistry.registerAuthenticationPlugin(new NullReturningPlugin());

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when plugin returns null
        assertNull("Should return null when plugin returns null", result);
    }

    @Test
    public void testAuthenticateWithPlugins_PluginThrowsUnexpectedException() throws Exception {
        // Register a plugin that throws unexpected exception
        backendRegistry.registerAuthenticationPlugin(new ExceptionThrowingPlugin());

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return null when plugin throws unexpected exception
        assertNull("Should return null when plugin throws unexpected exception", result);
    }

    @Test
    public void testAuthenticateWithPlugins_MixedPlugins() throws Exception {
        // Register a mix of plugins: unsupported, failing, successful
        backendRegistry.registerAuthenticationPlugin(new UnsupportedCredentialsPlugin());
        backendRegistry.registerAuthenticationPlugin(new FailingAuthenticationPlugin());
        backendRegistry.registerAuthenticationPlugin(new SuccessfulAuthenticationPlugin("working-plugin"));

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should return UserPrincipal from the successful plugin
        assertNotNull("Should return UserPrincipal from successful plugin", result);
        assertEquals("testuser", result.getName());
        assertEquals("working-plugin", result.getAuthenticationType());
    }

    @Test
    public void testAuthenticateWithPlugins_PreservesClaimsFromPlugin() throws Exception {
        // Register a plugin that returns claims
        Map<String, Object> expectedClaims = ImmutableMap.of(
            "email", "test@example.com",
            "groups", Collections.singletonList("developers")
        );
        backendRegistry.registerAuthenticationPlugin(new ClaimsReturningPlugin(expectedClaims));

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Call authenticateWithPlugins
        UserPrincipal result = invokeAuthenticateWithPlugins(context);

        // Should preserve claims from plugin
        assertNotNull("Should return UserPrincipal", result);
        assertEquals("testuser", result.getName());
        assertEquals("test@example.com", result.getClaims().get("email"));
        assertEquals(Collections.singletonList("developers"), result.getClaims().get("groups"));
    }

    // ========== Helper Methods ==========

    /**
     * Invokes the private authenticateWithPlugins method via reflection.
     */
    private UserPrincipal invokeAuthenticateWithPlugins(AuthenticationContext context) throws Exception {
        Method method = BackendRegistry.class.getDeclaredMethod("authenticateWithPlugins", AuthenticationContext.class);
        method.setAccessible(true);
        return (UserPrincipal) method.invoke(backendRegistry, context);
    }

    // ========== Test Plugin Implementations ==========

    /**
     * Plugin that always succeeds authentication.
     */
    private static class SuccessfulAuthenticationPlugin implements AuthenticationPlugin {
        private final String type;

        public SuccessfulAuthenticationPlugin() {
            this("successful-plugin");
        }

        public SuccessfulAuthenticationPlugin(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return credentials != null && credentials.getUsername() != null;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            return UserPrincipal.builder(context.getCredentials().getUsername())
                .authenticationType(type)
                .build();
        }
    }

    /**
     * Plugin that always fails authentication.
     */
    private static class FailingAuthenticationPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "failing-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return credentials != null && credentials.getUsername() != null;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            throw new AuthenticationException("Authentication failed", getType());
        }
    }

    /**
     * Plugin that doesn't support the credentials.
     */
    private static class UnsupportedCredentialsPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "unsupported-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return false; // Never supports any credentials
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            throw new AuthenticationException("Should not be called", getType());
        }
    }

    /**
     * Plugin that returns null.
     */
    private static class NullReturningPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "null-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            return null; // Returns null instead of throwing exception
        }
    }

    /**
     * Plugin that throws unexpected exception.
     */
    private static class ExceptionThrowingPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "exception-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            throw new RuntimeException("Unexpected error");
        }
    }

    /**
     * Plugin that returns claims.
     */
    private static class ClaimsReturningPlugin implements AuthenticationPlugin {
        private final Map<String, Object> claims;

        public ClaimsReturningPlugin(Map<String, Object> claims) {
            this.claims = claims;
        }

        @Override
        public String getType() {
            return "claims-plugin";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            UserPrincipal.Builder builder = UserPrincipal.builder(context.getCredentials().getUsername())
                .authenticationType(getType());
            
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
            
            return builder.build();
        }
    }
}
