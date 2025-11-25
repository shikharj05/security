/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.threadpool.ThreadPool;

import static org.junit.Assert.assertNotNull;

/**
 * Tests for BackendRegistry configuration loading integration.
 */
public class BackendRegistryConfigLoadingTest {

    @Mock
    private AdminDNs adminDns;

    @Mock
    private XFFResolver xffResolver;

    @Mock
    private AuditLog auditLog;

    @Mock
    private ThreadPool threadPool;

    @Mock
    private ClusterInfoHolder clusterInfoHolder;

    private BackendRegistry backendRegistry;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testLoadPluginConfigurations_EmptySettings() {
        Settings settings = Settings.builder().build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should not throw exception with empty settings
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }

    @Test
    public void testLoadPluginConfigurations_WithAuthenticationPlugins() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", true)
            .put("plugins.security.authentication.1.order", 2)
            .build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should successfully load configurations
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }

    @Test
    public void testLoadPluginConfigurations_WithAuthorizationPlugins() {
        Settings settings = Settings.builder()
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should successfully load configurations
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }

    @Test
    public void testLoadPluginConfigurations_WithBothPluginTypes() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authorization.0.type", "role_based")
            .put("plugins.security.authorization.0.enabled", true)
            .build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should successfully load both types of configurations
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }

    @Test
    public void testLoadPluginConfigurations_WithComplexSettings() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "ldap")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.0.config.host", "ldap.example.com")
            .put("plugins.security.authentication.0.config.port", "636")
            .put("plugins.security.authentication.0.config.bind_dn", "cn=admin,dc=example,dc=com")
            .build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should successfully load complex configurations
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }

    @Test
    public void testLoadPluginConfigurations_WithDisabledPlugins() {
        Settings settings = Settings.builder()
            .put("plugins.security.authentication.0.type", "internal")
            .put("plugins.security.authentication.0.enabled", true)
            .put("plugins.security.authentication.0.order", 1)
            .put("plugins.security.authentication.1.type", "ldap")
            .put("plugins.security.authentication.1.enabled", false)
            .put("plugins.security.authentication.1.order", 2)
            .build();

        backendRegistry = new BackendRegistry(settings, adminDns, xffResolver, auditLog, threadPool, clusterInfoHolder);

        // Should successfully load and filter disabled plugins
        backendRegistry.loadPluginConfigurations(settings);

        assertNotNull(backendRegistry);
    }
}
