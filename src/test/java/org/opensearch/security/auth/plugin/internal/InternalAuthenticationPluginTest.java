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

package org.opensearch.security.auth.plugin.internal;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.InternalUsersModel;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class InternalAuthenticationPluginTest {

    @Mock
    private PasswordHasher passwordHasher;

    @Mock
    private InternalUsersModel internalUsersModel;

    private InternalAuthenticationPlugin plugin;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        plugin = new InternalAuthenticationPlugin(passwordHasher);
        plugin.onInternalUsersModelChanged(internalUsersModel);
    }

    @Test
    public void testConstructorWithNullPasswordHasher() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new InternalAuthenticationPlugin(null)
        );
        assertThat(exception.getMessage(), is("passwordHasher must not be null"));
    }

    @Test
    public void testGetType() {
        // act
        final String type = plugin.getType();

        // assert
        assertThat(type, is("internal"));
    }

    @Test
    public void testSupportsWithValidCredentials() {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes(StandardCharsets.UTF_8));

        // act
        final boolean supports = plugin.supports(credentials);

        // assert
        assertTrue(supports);
    }

    @Test
    public void testSupportsWithNullCredentials() {
        // act
        final boolean supports = plugin.supports(null);

        // assert
        assertThat(supports, is(false));
    }

    @Test
    public void testSupportsWithCredentialsWithoutPassword() {
        // arrange - using constructor that doesn't require password
        final AuthCredentials credentials = new AuthCredentials("user", "role1");

        // act
        final boolean supports = plugin.supports(credentials);

        // assert - should return false because password is null
        assertThat(supports, is(false));
    }

    @Test
    public void testAuthenticateWithoutInternalUsersModel() {
        // arrange
        final InternalAuthenticationPlugin pluginWithoutModel = new InternalAuthenticationPlugin(passwordHasher);
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> pluginWithoutModel.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("internal"));
        assertThat(exception.getReason(), containsString("not configured"));
    }

    @Test
    public void testAuthenticateWithNullCredentials() {
        // arrange
        final AuthenticationContext context = new AuthenticationContext(null);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> plugin.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("internal"));
        assertThat(exception.getReason(), containsString("Credentials or username is null"));
    }

    @Test
    public void testAuthenticateWithCredentialsWithoutPassword() {
        // arrange - using constructor that doesn't require password
        final AuthCredentials credentials = new AuthCredentials("user", "role1");
        final AuthenticationContext context = new AuthenticationContext(credentials);
        when(internalUsersModel.exists("user")).thenReturn(true);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> plugin.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("internal"));
        assertThat(exception.getReason(), is("empty passwords not supported"));
    }

    @Test
    public void testAuthenticateUserNotFound() {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("nonexistent", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);
        when(internalUsersModel.exists("nonexistent")).thenReturn(false);
        when(passwordHasher.check(any(char[].class), any(String.class))).thenReturn(false);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> plugin.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("internal"));
        assertThat(exception.getReason(), containsString("not found"));
    }

    @Test
    public void testAuthenticateInvalidPassword() {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("user", "wrongpassword".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);
        when(internalUsersModel.exists("user")).thenReturn(true);
        when(internalUsersModel.getHash("user")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(false);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> plugin.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("internal"));
        assertThat(exception.getReason(), is("password does not match"));
    }

    @Test
    public void testAuthenticateSuccess() throws AuthenticationException {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);

        when(internalUsersModel.exists("testuser")).thenReturn(true);
        when(internalUsersModel.getHash("testuser")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(true);
        when(internalUsersModel.getBackendRoles("testuser")).thenReturn(ImmutableSet.of("role1", "role2"));
        when(internalUsersModel.getSecurityRoles("testuser")).thenReturn(ImmutableSet.of("security_role1"));
        when(internalUsersModel.getAttributes("testuser")).thenReturn(ImmutableMap.of("email", "test@example.com"));

        // act
        final UserPrincipal principal = plugin.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("testuser"));
        assertThat(principal.getAuthenticationType(), is("internal"));

        final Map<String, Object> claims = principal.getClaims();
        assertThat(claims, is(notNullValue()));

        // Verify backend roles
        @SuppressWarnings("unchecked")
        final List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertThat(backendRoles, is(notNullValue()));
        assertThat(backendRoles.size(), is(2));
        assertThat(backendRoles, hasItem("role1"));
        assertThat(backendRoles, hasItem("role2"));

        // Verify security roles
        @SuppressWarnings("unchecked")
        final List<String> securityRoles = (List<String>) claims.get("security_roles");
        assertThat(securityRoles, is(notNullValue()));
        assertThat(securityRoles.size(), is(1));
        assertThat(securityRoles, hasItem("security_role1"));

        // Verify attributes with prefix
        assertThat(claims.get("attr.internal.email"), is("test@example.com"));
    }

    @Test
    public void testAuthenticateWithEmptyRolesAndAttributes() throws AuthenticationException {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("simpleuser", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);

        when(internalUsersModel.exists("simpleuser")).thenReturn(true);
        when(internalUsersModel.getHash("simpleuser")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(true);
        when(internalUsersModel.getBackendRoles("simpleuser")).thenReturn(ImmutableSet.of());
        when(internalUsersModel.getSecurityRoles("simpleuser")).thenReturn(ImmutableSet.of());
        when(internalUsersModel.getAttributes("simpleuser")).thenReturn(ImmutableMap.of());

        // act
        final UserPrincipal principal = plugin.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("simpleuser"));
        assertThat(principal.getAuthenticationType(), is("internal"));
        assertThat(principal.getClaims(), is(notNullValue()));
    }

    @Test
    public void testAuthenticateWithCredentialAttributes() throws AuthenticationException {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes(StandardCharsets.UTF_8));
        credentials.addAttribute("request_id", "12345");
        credentials.addAttribute("client_ip", "192.168.1.1");
        final AuthenticationContext context = new AuthenticationContext(credentials);

        when(internalUsersModel.exists("testuser")).thenReturn(true);
        when(internalUsersModel.getHash("testuser")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(true);
        when(internalUsersModel.getBackendRoles("testuser")).thenReturn(ImmutableSet.of("role1"));
        when(internalUsersModel.getSecurityRoles("testuser")).thenReturn(ImmutableSet.of());
        when(internalUsersModel.getAttributes("testuser")).thenReturn(ImmutableMap.of());

        // act
        final UserPrincipal principal = plugin.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        final Map<String, Object> claims = principal.getClaims();
        assertThat(claims.get("request_id"), is("12345"));
        assertThat(claims.get("client_ip"), is("192.168.1.1"));
    }

    @Test
    public void testAuthenticateWithComplexAttributes() throws AuthenticationException {
        // arrange
        final AuthCredentials credentials = new AuthCredentials("complexuser", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);

        when(internalUsersModel.exists("complexuser")).thenReturn(true);
        when(internalUsersModel.getHash("complexuser")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(true);
        when(internalUsersModel.getBackendRoles("complexuser")).thenReturn(ImmutableSet.of("developers", "admins"));
        when(internalUsersModel.getSecurityRoles("complexuser")).thenReturn(ImmutableSet.of("kibana_user", "all_access"));
        when(internalUsersModel.getAttributes("complexuser")).thenReturn(
            ImmutableMap.of("email", "user@example.com", "department", "Engineering", "location", "Seattle", "employee_id", "12345")
        );

        // act
        final UserPrincipal principal = plugin.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("complexuser"));

        final Map<String, Object> claims = principal.getClaims();

        // Verify backend roles
        @SuppressWarnings("unchecked")
        final List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertThat(backendRoles, hasItem("developers"));
        assertThat(backendRoles, hasItem("admins"));

        // Verify security roles
        @SuppressWarnings("unchecked")
        final List<String> securityRoles = (List<String>) claims.get("security_roles");
        assertThat(securityRoles, hasItem("kibana_user"));
        assertThat(securityRoles, hasItem("all_access"));

        // Verify attributes
        assertThat(claims.get("attr.internal.email"), is("user@example.com"));
        assertThat(claims.get("attr.internal.department"), is("Engineering"));
        assertThat(claims.get("attr.internal.location"), is("Seattle"));
        assertThat(claims.get("attr.internal.employee_id"), is("12345"));
    }

    @Test
    public void testOnInternalUsersModelChanged() {
        // arrange
        final InternalAuthenticationPlugin newPlugin = new InternalAuthenticationPlugin(passwordHasher);
        final InternalUsersModel newModel = internalUsersModel;

        // act
        newPlugin.onInternalUsersModelChanged(newModel);

        // assert - verify plugin can authenticate after model is set
        final AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes(StandardCharsets.UTF_8));
        final AuthenticationContext context = new AuthenticationContext(credentials);

        when(newModel.exists("testuser")).thenReturn(true);
        when(newModel.getHash("testuser")).thenReturn("$2y$12$validhash");
        when(passwordHasher.check(any(char[].class), eq("$2y$12$validhash"))).thenReturn(true);
        when(newModel.getBackendRoles("testuser")).thenReturn(ImmutableSet.of("role1"));
        when(newModel.getSecurityRoles("testuser")).thenReturn(ImmutableSet.of());
        when(newModel.getAttributes("testuser")).thenReturn(ImmutableMap.of());

        // Should not throw exception
        try {
            final UserPrincipal principal = newPlugin.authenticate(context);
            assertThat(principal, is(notNullValue()));
        } catch (AuthenticationException e) {
            throw new AssertionError("Should not throw exception after model is set", e);
        }
    }
}
