/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.search.PitService;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.extensions.ExtensionsManager;
import org.opensearch.indices.IndicesService;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.support.Base64Helper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserFactory;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.telemetry.tracing.noop.NoopTracer;
import org.opensearch.test.transport.MockTransport;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport.Connection;
import org.opensearch.transport.TransportInterceptor.AsyncSender;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestOptions;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.TransportService;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static java.util.Collections.emptySet;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for transport layer plugin support.
 * Tests that User objects are serialized for inter-node communication
 * while UserPrincipal objects are used internally.
 */
public class TransportPluginIntegrationTest {

    private SecurityInterceptor securityInterceptor;

    @Mock
    private BackendRegistry backendRegistry;

    @Mock
    private AuditLog auditLog;

    @Mock
    private PrincipalExtractor principalExtractor;

    @Mock
    private InterClusterRequestEvaluator requestEvalProvider;

    @Mock
    private ClusterService clusterService;

    @Mock
    private SslExceptionHandler sslExceptionHandler;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    @Mock
    private SSLConfig sslConfig;

    @Mock
    private TransportRequest request;

    @Mock
    private TransportRequestOptions options;

    @SuppressWarnings("unchecked")
    private TransportResponseHandler<TransportResponse> handler = mock(TransportResponseHandler.class);

    private Settings settings;
    private ThreadPool threadPool;
    private ClusterName clusterName = ClusterName.DEFAULT;
    private MockTransport transport;
    private TransportService transportService;
    private OpenSearchSecurityPlugin.GuiceHolder guiceHolder;
    private User user;
    private UserPrincipal userPrincipal;
    private String action = "testAction";

    private InetAddress localAddress;
    private DiscoveryNode localNode;
    private Connection localConnection;
    private DiscoveryNode remoteNode;
    private Connection remoteConnection;

    private CountDownLatch senderLatch;

    @Before
    public void setup() throws Exception {
        MockitoAnnotations.openMocks(this);
        
        settings = Settings.builder()
            .put("node.name", TransportPluginIntegrationTest.class.getSimpleName())
            .build();
        threadPool = new ThreadPool(settings);
        
        securityInterceptor = new SecurityInterceptor(
            settings,
            threadPool,
            backendRegistry,
            auditLog,
            principalExtractor,
            requestEvalProvider,
            clusterService,
            sslExceptionHandler,
            clusterInfoHolder,
            sslConfig,
            () -> false,
            new UserFactory.Simple()
        );

        clusterName = ClusterName.DEFAULT;
        when(clusterService.getClusterName()).thenReturn(clusterName);

        transport = new MockTransport();
        transportService = transport.createTransportService(
            Settings.EMPTY,
            threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            boundTransportAddress -> clusterService.state().nodes().get(TransportPluginIntegrationTest.class.getSimpleName()),
            null,
            emptySet(),
            NoopTracer.INSTANCE
        );

        guiceHolder = new OpenSearchSecurityPlugin.GuiceHolder(
            mock(RepositoriesService.class),
            transportService,
            mock(IndicesService.class),
            mock(PitService.class),
            mock(ExtensionsManager.class)
        );

        // Create test user and principal
        user = new User("testuser");
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", Collections.singletonList("admin"));
        claims.put("email", "test@example.com");
        userPrincipal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        when(options.type()).thenReturn(TransportRequestOptions.Type.REG);

        localAddress = InetAddress.getByName("0.0.0.0");
        localNode = new DiscoveryNode("local-node", new TransportAddress(localAddress, 1234), Version.CURRENT);
        localConnection = transportService.getConnection(localNode);

        remoteNode = new DiscoveryNode("remote-node", new TransportAddress(localAddress, 5678), Version.CURRENT);
        remoteConnection = transportService.getConnection(remoteNode);

        senderLatch = new CountDownLatch(1);
    }

    /**
     * Test that User objects are serialized for remote node communication.
     */
    @Test
    public void testUserSerializationForRemoteNode() throws Exception {
        // Put User in thread context
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify User is serialized in header for remote nodes
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertNotNull("User header should be present for remote node", serializedUserHeader);
                
                User deserializedUser = (User) Base64Helper.deserializeObject(serializedUserHeader);
                assertEquals("Serialized user should match original", user.getName(), deserializedUser.getName());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, remoteConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }

    /**
     * Test that UserPrincipal is converted to User for serialization.
     */
    @Test
    public void testUserPrincipalConversionForSerialization() throws Exception {
        // Put UserPrincipal in thread context (simulating plugin architecture)
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_PRINCIPAL, userPrincipal);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify UserPrincipal is converted to User and serialized
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertNotNull("User header should be present after UserPrincipal conversion", serializedUserHeader);
                
                User deserializedUser = (User) Base64Helper.deserializeObject(serializedUserHeader);
                assertEquals("Converted user should have same name as principal", userPrincipal.getName(), deserializedUser.getName());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, remoteConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }

    /**
     * Test that User objects remain as transient for same-node requests.
     */
    @Test
    public void testUserTransientForSameNode() throws Exception {
        // Put User in thread context
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify User remains as transient for same-node requests
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertNotNull("User should be in transient for same node", transientUser);
                assertEquals("Transient user should match original", user.getName(), transientUser.getName());
                
                // Verify no serialization header for same-node
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertThat("User header should not be present for same node", serializedUserHeader, nullValue());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, localConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }

    /**
     * Test that UserPrincipal is converted to User for same-node requests.
     */
    @Test
    public void testUserPrincipalConversionForSameNode() throws Exception {
        // Put UserPrincipal in thread context
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_PRINCIPAL, userPrincipal);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify UserPrincipal is converted to User for same-node
                User transientUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                assertNotNull("Converted User should be in transient for same node", transientUser);
                assertEquals("Converted user should have same name as principal", userPrincipal.getName(), transientUser.getName());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, localConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }

    /**
     * Test backward compatibility: existing behavior unchanged when no plugins configured.
     */
    @Test
    public void testBackwardCompatibilityWithoutPlugins() throws Exception {
        // Put User in thread context (old behavior)
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify existing behavior is maintained
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertNotNull("User header should be present", serializedUserHeader);
                
                User deserializedUser = (User) Base64Helper.deserializeObject(serializedUserHeader);
                assertEquals("User should be serialized correctly", user.getName(), deserializedUser.getName());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, remoteConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }

    /**
     * Test that User takes precedence over UserPrincipal when both are present.
     */
    @Test
    public void testUserTakesPrecedenceOverUserPrincipal() throws Exception {
        // Put both User and UserPrincipal in thread context
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER_PRINCIPAL, userPrincipal);

        AsyncSender sender = new AsyncSender() {
            @Override
            public <T extends TransportResponse> void sendRequest(
                Connection connection,
                String action,
                TransportRequest request,
                TransportRequestOptions options,
                TransportResponseHandler<T> handler
            ) {
                // Verify User takes precedence
                String serializedUserHeader = threadPool.getThreadContext().getHeader(ConfigConstants.OPENDISTRO_SECURITY_USER_HEADER);
                assertNotNull("User header should be present", serializedUserHeader);
                
                User deserializedUser = (User) Base64Helper.deserializeObject(serializedUserHeader);
                assertEquals("User should take precedence over UserPrincipal", user.getName(), deserializedUser.getName());
                
                senderLatch.countDown();
            }
        };

        securityInterceptor.sendRequestDecorate(sender, remoteConnection, action, request, options, handler, localNode);
        
        senderLatch.await(1, TimeUnit.SECONDS);
    }
}
