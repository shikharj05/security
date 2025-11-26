/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.RestLayerPrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Integration tests for SecurityRestFilter with plugin architecture support.
 * Tests the REST filter's ability to use authentication and authorization plugins.
 */
public class SecurityRestFilterPluginIntegrationTest {

    private SecurityRestFilter securityRestFilter;
    private BackendRegistry backendRegistry;
    private RestLayerPrivilegesEvaluator privilegesEvaluator;
    private AuditLog auditLog;
    private ThreadPool threadPool;
    private ThreadContext threadContext;
    private AdminDNs adminDNs;

    /**
     * Test authentication plugin that always succeeds
     */
    private static class TestAuthenticationPlugin implements AuthenticationPlugin {
        @Override
        public String getType() {
            return "test-auth";
        }

        @Override
        public boolean supports(AuthCredentials credentials) {
            return true;
        }

        @Override
        public UserPrincipal authenticate(AuthenticationContext context) {
            return UserPrincipal.builder("testuser")
                .claim("roles", List.of("test-role"))
                .authenticationType("test-auth")
                .build();
        }
    }

    /**
     * Test authorization plugin that allows all access
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
            return ImmutableSet.of("all");
        }
    }

    /**
     * Test authorization plugin that denies all access
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
     * Test REST handler with named route
     */
    private static class TestNamedRouteHandler implements RestHandler {
        private final String routeName;

        public TestNamedRouteHandler(String routeName) {
            this.routeName = routeName;
        }

        @Override
        public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, BytesRestResponse.TEXT_CONTENT_TYPE, BytesArray.EMPTY));
        }

        @Override
        public List<Route> routes() {
            return List.of(
                new NamedRoute.Builder()
                    .method(RestRequest.Method.GET)
                    .path("/test")
                    .uniqueName(routeName)
                    .build()
            );
        }
    }

    @Before
    public void setUp() {
        threadPool = spy(new ThreadPool(Settings.builder().put("node.name", "test-node").build()));
        threadContext = new ThreadContext(Settings.EMPTY);
        doReturn(threadContext).when(threadPool).getThreadContext();

        backendRegistry = mock(BackendRegistry.class);
        privilegesEvaluator = mock(RestLayerPrivilegesEvaluator.class);
        auditLog = mock(AuditLog.class);
        adminDNs = mock(AdminDNs.class);

        securityRestFilter = new SecurityRestFilter(
            backendRegistry,
            privilegesEvaluator,
            auditLog,
            threadPool,
            mock(PrincipalExtractor.class),
            Settings.EMPTY,
            mock(Path.class),
            mock(CompatConfig.class)
        );
    }

    @Test
    public void testAuthorizationWithPluginAllowsAccess() throws Exception {
        // Setup: Create a user and configure plugin to allow access
        User testUser = new User("testuser");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, testUser);

        // Mock BackendRegistry to return allow result from plugin
        AuthorizationResult allowResult = AuthorizationResult.allow();
        when(backendRegistry.authorize(any(User.class), anyString(), anyString())).thenReturn(allowResult);

        // Create test handler with named route
        RestHandler testHandler = new TestNamedRouteHandler("test:action");

        // Create mock request channel
        SecurityRequestChannel requestChannel = mock(SecurityRequestChannel.class);
        when(requestChannel.method()).thenReturn(RestRequest.Method.GET);
        when(requestChannel.path()).thenReturn("/test");
        when(requestChannel.params()).thenReturn(Map.of());
        when(requestChannel.getHeaders()).thenReturn(Map.of());
        when(requestChannel.getQueuedResponse()).thenReturn(java.util.Optional.empty());

        // Execute: Call authorize directly
        securityRestFilter.authorizeRequest(testHandler, requestChannel, testUser);

        // Verify: Plugin authorization was called
        verify(backendRegistry).authorize(eq(testUser), eq("test:action"), eq("/test"));

        // Verify: Audit log recorded granted privileges
        verify(auditLog).logGrantedPrivileges(eq("testuser"), any());

        // Verify: Request was not denied
        verify(requestChannel, never()).queueForSending(any());
    }

    @Test
    public void testAuthorizationWithPluginDeniesAccess() throws Exception {
        // Setup: Create a user and configure plugin to deny access
        User testUser = new User("testuser");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, testUser);

        // Mock BackendRegistry to return deny result from plugin
        AuthorizationResult denyResult = AuthorizationResult.deny("Access denied by test plugin");
        when(backendRegistry.authorize(any(User.class), anyString(), anyString())).thenReturn(denyResult);

        // Create test handler with named route
        RestHandler testHandler = new TestNamedRouteHandler("test:action");

        // Create mock request channel
        SecurityRequestChannel requestChannel = mock(SecurityRequestChannel.class);
        when(requestChannel.method()).thenReturn(RestRequest.Method.GET);
        when(requestChannel.path()).thenReturn("/test");
        when(requestChannel.params()).thenReturn(Map.of());
        when(requestChannel.getHeaders()).thenReturn(Map.of());
        when(requestChannel.getQueuedResponse()).thenReturn(java.util.Optional.empty());

        // Execute: Call authorize directly
        securityRestFilter.authorizeRequest(testHandler, requestChannel, testUser);

        // Verify: Plugin authorization was called
        verify(backendRegistry).authorize(eq(testUser), eq("test:action"), eq("/test"));

        // Verify: Audit log recorded missing privileges
        verify(auditLog).logMissingPrivileges(eq("test:action"), eq("testuser"), any());

        // Verify: Request was denied
        verify(requestChannel).queueForSending(any(SecurityResponse.class));
    }

    @Test
    public void testFallbackToExistingAuthorizationWhenNoPlugins() throws Exception {
        // Setup: Create a user
        User testUser = new User("testuser");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, testUser);

        // Mock BackendRegistry to return null (no plugins configured)
        when(backendRegistry.authorize(any(User.class), anyString(), anyString())).thenReturn(null);

        // Mock existing authorization flow to allow access
        PrivilegesEvaluatorResponse allowResponse = mock(PrivilegesEvaluatorResponse.class);
        when(allowResponse.isAllowed()).thenReturn(true);
        when(privilegesEvaluator.evaluate(any(User.class), anyString(), any())).thenReturn(allowResponse);

        // Create test handler with named route
        RestHandler testHandler = new TestNamedRouteHandler("test:action");

        // Create mock request channel
        SecurityRequestChannel requestChannel = mock(SecurityRequestChannel.class);
        when(requestChannel.method()).thenReturn(RestRequest.Method.GET);
        when(requestChannel.path()).thenReturn("/test");
        when(requestChannel.params()).thenReturn(Map.of());
        when(requestChannel.getHeaders()).thenReturn(Map.of());
        when(requestChannel.getQueuedResponse()).thenReturn(java.util.Optional.empty());

        // Execute: Call authorize directly
        securityRestFilter.authorizeRequest(testHandler, requestChannel, testUser);

        // Verify: Plugin authorization was attempted
        verify(backendRegistry).authorize(eq(testUser), eq("test:action"), eq("/test"));

        // Verify: Existing authorization flow was used
        verify(privilegesEvaluator).evaluate(eq(testUser), eq("test:action"), any());

        // Verify: Audit log recorded granted privileges
        verify(auditLog).logGrantedPrivileges(eq("testuser"), any());

        // Verify: Request was not denied
        verify(requestChannel, never()).queueForSending(any());
    }

    @Test
    public void testAuthorizationContextCreation() throws Exception {
        // Setup: Create a user
        User testUser = new User("testuser");
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, testUser);

        // Mock BackendRegistry to capture the authorization call
        when(backendRegistry.authorize(any(User.class), anyString(), anyString())).thenReturn(AuthorizationResult.allow());

        // Create test handler with named route
        RestHandler testHandler = new TestNamedRouteHandler("test:action");

        // Create mock request channel with matching path
        SecurityRequestChannel requestChannel = mock(SecurityRequestChannel.class);
        when(requestChannel.method()).thenReturn(RestRequest.Method.GET);
        when(requestChannel.path()).thenReturn("/test");
        when(requestChannel.params()).thenReturn(Map.of());
        when(requestChannel.getHeaders()).thenReturn(Map.of());
        when(requestChannel.getQueuedResponse()).thenReturn(java.util.Optional.empty());

        // Execute: Call authorize directly
        securityRestFilter.authorizeRequest(testHandler, requestChannel, testUser);

        // Verify: Authorization was called with correct action and resource
        verify(backendRegistry).authorize(eq(testUser), eq("test:action"), eq("/test"));
    }

    @Test
    public void testUserPrincipalConversion() {
        // Test that User can be converted to UserPrincipal and back
        User originalUser = new User("testuser");

        // Convert to UserPrincipal
        UserPrincipal principal = originalUser.toPrincipal();

        assertNotNull(principal);
        assertEquals("testuser", principal.getName());
        assertEquals("legacy", principal.getAuthenticationType());

        // Verify claims exist
        Map<String, Object> claims = principal.getClaims();
        assertNotNull(claims);

        // Convert back to User
        User convertedUser = User.fromPrincipal(principal, ImmutableSet.of("security-role1"));

        assertNotNull(convertedUser);
        assertEquals("testuser", convertedUser.getName());
        assertEquals(ImmutableSet.of("security-role1"), convertedUser.getSecurityRoles());
    }
}
