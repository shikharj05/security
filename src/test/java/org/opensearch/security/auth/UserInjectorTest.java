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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;

import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

public class UserInjectorTest {

    private ThreadPool threadPool;
    private ThreadContext threadContext;
    private UserInjector userInjector;
    private TransportRequest transportRequest;
    private Task task;

    @Before
    public void setup() {
        threadPool = mock(ThreadPool.class);
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true).build();
        threadContext = new ThreadContext(settings);
        Mockito.when(threadPool.getThreadContext()).thenReturn(threadContext);
        transportRequest = mock(TransportRequest.class);
        task = mock(Task.class);
        userInjector = new UserInjector(settings, threadPool, mock(AuditLog.class), mock(XFFResolver.class));
    }

    @Test
    public void testValidInjectUser() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "user|role1,role2");
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertThat("user", is(injectedUser.getUser().getName()));
        assertThat(roles, is(injectedUser.getUser().getRoles()));
        
        // Verify UserPrincipal is created
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        assertThat("user", is(injectedUser.getPrincipal().getName()));
        assertThat("injected", is(injectedUser.getPrincipal().getAuthenticationType()));
        
        // Verify claims contain backend roles
        Map<String, Object> claims = injectedUser.getPrincipal().getClaims();
        assertNotNull("Claims should not be null", claims);
        assertThat(true, is(claims.get("injected")));
    }

    @Test
    public void testValidInjectUserIpV6() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
            "user|role1,role2|2001:db8:3333:4444:5555:6666:7777:8888:9200"
        );
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertThat(injectedUser.getUser().getName(), is("user"));
        assertThat(injectedUser.getTransportAddress().getPort(), is(9200));
        assertThat(injectedUser.getTransportAddress().getAddress(), is("2001:db8:3333:4444:5555:6666:7777:8888"));
        
        // Verify UserPrincipal is created
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        assertThat("user", is(injectedUser.getPrincipal().getName()));
    }

    @Test
    public void testValidInjectUserIpV6ShortFormat() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "user|role1,role2|2001:db8::1:9200");
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertThat(injectedUser.getUser().getName(), is("user"));
        assertThat(injectedUser.getTransportAddress().getPort(), is(9200));
        assertThat(injectedUser.getTransportAddress().getAddress(), is("2001:db8::1"));
    }

    @Test
    public void testInvalidInjectUserIpV6() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
            "user|role1,role2|2001:db8:3333:5555:6666:7777:8888:9200"
        );
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertNull(injectedUser);
    }

    @Test
    public void testValidInjectUserBracketsIpV6() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
            "user|role1,role2|[2001:db8:3333:4444:5555:6666:7777:8888]:9200"
        );
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertThat(injectedUser.getUser().getName(), is("user"));
        assertThat(injectedUser.getUser().getRoles(), is(roles));
        assertThat(injectedUser.getTransportAddress().getPort(), is(9200));
        assertThat(injectedUser.getTransportAddress().getAddress(), is("2001:db8:3333:4444:5555:6666:7777:8888"));
        
        // Verify UserPrincipal is created
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        assertThat("user", is(injectedUser.getPrincipal().getName()));
    }

    @Test
    public void testInvalidInjectUser() {
        HashSet<String> roles = new HashSet<>();
        roles.addAll(Arrays.asList("role1", "role2"));
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "|role1,role2");
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertNull(injectedUser);
    }

    @Test
    public void testEmptyInjectUserHeader() {
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        assertNull(injectedUser);
    }

    @Test
    public void testMapFromArray() {
        Map<String, String> map = userInjector.mapFromArray((String) null);
        assertNull(map);

        map = userInjector.mapFromArray("key");
        assertNull(map);

        map = userInjector.mapFromArray("key", "value", "otherkey");
        assertNull(map);

        map = userInjector.mapFromArray("key", "value");
        assertNotNull(map);
        assertThat(map.size(), is(1));
        assertThat(map.get("key"), is("value"));

        map = userInjector.mapFromArray("key", "value", "key", "value");
        assertNotNull(map);
        assertThat(map.size(), is(1));
        assertThat(map.get("key"), is("value"));

        map = userInjector.mapFromArray("key1", "value1", "key2", "value2");
        assertNotNull(map);
        assertThat(map.size(), is(2));
        assertThat(map.get("key1"), is("value1"));
        assertThat(map.get("key2"), is("value2"));

    }

    @Test
    public void testInjectedUserWithCustomAttributes() {
        threadContext.putTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
            "user|role1,role2||attr1,value1,attr2,value2"
        );
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        
        assertNotNull("Injected user should not be null", injectedUser);
        assertThat("user", is(injectedUser.getUser().getName()));
        
        // Verify User has custom attributes
        Map<String, String> userAttributes = injectedUser.getUser().getCustomAttributesMap();
        assertThat(2, is(userAttributes.size()));
        assertThat("value1", is(userAttributes.get("attr1")));
        assertThat("value2", is(userAttributes.get("attr2")));
        
        // Verify UserPrincipal has custom attributes in claims
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        Map<String, Object> claims = injectedUser.getPrincipal().getClaims();
        assertThat("value1", is(claims.get("attr1")));
        assertThat("value2", is(claims.get("attr2")));
    }

    @Test
    public void testInjectedUserMarkedAsInjected() {
        threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "testuser|admin");
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        
        assertNotNull("Injected user should not be null", injectedUser);
        
        // Verify User is marked as injected
        assertThat(true, is(injectedUser.getUser().isInjected()));
        
        // Verify UserPrincipal has injected claim
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        Map<String, Object> claims = injectedUser.getPrincipal().getClaims();
        assertThat(true, is(claims.get("injected")));
        assertThat("injected", is(injectedUser.getPrincipal().getAuthenticationType()));
    }

    @Test
    public void testInjectedUserWithRequestedTenant() {
        threadContext.putTransient(
            ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER,
            "user|role1,role2|||my_tenant"
        );
        UserInjector.Result injectedUser = userInjector.getInjectedUser();
        
        assertNotNull("Injected user should not be null", injectedUser);
        assertThat("user", is(injectedUser.getUser().getName()));
        assertThat("my_tenant", is(injectedUser.getUser().getRequestedTenant()));
        
        // Verify UserPrincipal is created
        assertNotNull("UserPrincipal should be created", injectedUser.getPrincipal());
        assertThat("user", is(injectedUser.getPrincipal().getName()));
    }

}
