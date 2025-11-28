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

package org.opensearch.security.auditlog;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Integration tests for audit logging of authentication and authorization plugin execution.
 */
public class PluginAuditLoggingIntegrationTest {

    private BackendRegistry backendRegistry;
    private AuditLog auditLog;
    private Settings settings;
    private AdminDNs adminDns;
    private XFFResolver xffResolver;
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
    public void testAuthenticationPluginSuccessAuditLogging() throws Exception {
        // Create a successful authentication plugin
        AuthenticationPlugin plugin = new TestAuthenticationPlugin("test-plugin", true);
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Invoke authentication via reflection (private method)
        java.lang.reflect.Method method = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        method.setAccessible(true);
        UserPrincipal result = (UserPrincipal) method.invoke(backendRegistry, context);

        // Verify authentication succeeded
        assertNotNull("Authentication should succeed", result);
        assertEquals("testuser", result.getName());

        // Verify audit log was called
        ArgumentCaptor<String> pluginTypeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> resultCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Long> executionTimeCaptor = ArgumentCaptor.forClass(Long.class);
        ArgumentCaptor<String> principalNameCaptor = ArgumentCaptor.forClass(String.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);

        verify(auditLog, times(1)).logAuthenticationPluginExecution(
            pluginTypeCaptor.capture(),
            resultCaptor.capture(),
            executionTimeCaptor.capture(),
            principalNameCaptor.capture(),
            claimsCaptor.capture(),
            isNull()
        );

        // Verify audit log parameters
        assertEquals("test-plugin", pluginTypeCaptor.getValue());
        assertEquals("SUCCESS", resultCaptor.getValue());
        assertTrue("Execution time should be >= 0", executionTimeCaptor.getValue() >= 0);
        assertEquals("testuser", principalNameCaptor.getValue());
        assertNotNull("Claims should not be null", claimsCaptor.getValue());
    }

    @Test
    public void testAuthenticationPluginFailureAuditLogging() throws Exception {
        // Create a failing authentication plugin
        AuthenticationPlugin plugin = new TestAuthenticationPlugin("test-plugin", false);
        backendRegistry.registerAuthenticationPlugin(plugin);

        // Create authentication context
        AuthCredentials credentials = new AuthCredentials("testuser", "password");
        AuthenticationContext context = new AuthenticationContext(credentials);

        // Invoke authentication via reflection
        java.lang.reflect.Method method = BackendRegistry.class.getDeclaredMethod(
            "authenticateWithPlugins",
            AuthenticationContext.class
        );
        method.setAccessible(true);
        UserPrincipal result = (UserPrincipal) method.invoke(backendRegistry, context);

        // Verify authentication failed
        assertEquals("Authentication should fail", null, result);

        // Verify audit log was called with failure
        ArgumentCaptor<String> resultCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLog, times(1)).logAuthenticationPluginExecution(
            eq("test-plugin"),
            resultCaptor.capture(),
            anyLong(),
            eq("testuser"),
            anyMap(),
            isNull()
        );

        // Verify failure was logged
        assertTrue("Result should indicate failure", resultCaptor.getValue().startsWith("FAILED_EXCEPTION"));
    }

    @Test
    public void testAuthorizationPluginAllowedAuditLogging() throws Exception {
        // Create an authorization plugin that allows access
        AuthorizationPlugin plugin = new TestAuthorizationPlugin("test-authz-plugin", true);
        backendRegistry.registerAuthorizationPlugin(plugin);

        // Create user principal and authorization context
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claim("role", "admin")
            .authenticationType("test")
            .build();
        AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index").build();

        // Invoke authorization via reflection
        java.lang.reflect.Method method = BackendRegistry.class.getDeclaredMethod(
            "authorizeWithPlugins",
            UserPrincipal.class,
            AuthorizationContext.class
        );
        method.setAccessible(true);
        AuthorizationResult result = (AuthorizationResult) method.invoke(backendRegistry, principal, context);

        // Verify authorization succeeded
        assertNotNull("Authorization should return result", result);
        assertTrue("Authorization should be allowed", result.isAllowed());

        // Verify audit log was called
        ArgumentCaptor<String> pluginTypeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> resultCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> actionCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> resourceCaptor = ArgumentCaptor.forClass(String.class);

        verify(auditLog, times(1)).logAuthorizationPluginExecution(
            pluginTypeCaptor.capture(),
            resultCaptor.capture(),
            anyLong(),
            eq("testuser"),
            actionCaptor.capture(),
            resourceCaptor.capture(),
            isNull()
        );

        // Verify audit log parameters
        assertEquals("test-authz-plugin", pluginTypeCaptor.getValue());
        assertEquals("ALLOWED", resultCaptor.getValue());
        assertEquals("indices:data/read/search", actionCaptor.getValue());
        assertEquals("test-index", resourceCaptor.getValue());
    }

    @Test
    public void testAuthorizationPluginDeniedAuditLogging() throws Exception {
        // Create an authorization plugin that denies access
        AuthorizationPlugin plugin = new TestAuthorizationPlugin("test-authz-plugin", false);
        backendRegistry.registerAuthorizationPlugin(plugin);

        // Create user principal and authorization context
        UserPrincipal principal = UserPrincipal.builder("testuser")
            .claim("role", "user")
            .authenticationType("test")
            .build();
        AuthorizationContext context = AuthorizationContext.builder("indices:data/write/index", "test-index").build();

        // Invoke authorization via reflection
        java.lang.reflect.Method method = BackendRegistry.class.getDeclaredMethod(
            "authorizeWithPlugins",
            UserPrincipal.class,
            AuthorizationContext.class
        );
        method.setAccessible(true);
        AuthorizationResult result = (AuthorizationResult) method.invoke(backendRegistry, principal, context);

        // Verify authorization was denied
        assertNotNull("Authorization should return result", result);
        assertTrue("Authorization should be denied", !result.isAllowed());

        // Verify audit log was called with denial
        ArgumentCaptor<String> resultCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditLog, times(1)).logAuthorizationPluginExecution(
            eq("test-authz-plugin"),
            resultCaptor.capture(),
            anyLong(),
            eq("testuser"),
            eq("indices:data/write/index"),
            eq("test-index"),
            isNull()
        );

        // Verify denial was logged
        assertTrue("Result should indicate denial", resultCaptor.getValue().startsWith("DENIED"));
    }

    // Test helper classes

    private static class TestAuthenticationPlugin implements AuthenticationPlugin {
        private final String type;
        private final boolean shouldSucceed;

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
            return credentials != null && credentials.getUsername() != null;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
            if (!shouldSucceed) {
                throw new AuthenticationException(type, "Authentication failed");
            }
            
            return UserPrincipal.builder(context.getCredentials().getUsername())
                .claim("role", "admin")
                .authenticationType(type)
                .build();
        }
    }

    private static class TestAuthorizationPlugin implements AuthorizationPlugin {
        private final String type;
        private final boolean shouldAllow;

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
                return AuthorizationResult.deny("Insufficient permissions");
            }
        }

        @Override
        public java.util.Set<String> resolvePermissions(UserPrincipal principal) {
            return Collections.emptySet();
        }
    }
}
