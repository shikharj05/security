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

package org.opensearch.security.auth.plugin.adapter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AuthenticationBackendAdapterTest {

    @Test
    public void testConstructorWithNullBackend() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new AuthenticationBackendAdapter(null)
        );
        assertThat(exception.getMessage(), is("backend must not be null"));
    }

    @Test
    public void testGetType() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("test-type");
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);

        // act
        final String type = adapter.getType();

        // assert
        assertThat(type, is("test-type"));
    }

    @Test
    public void testSupportsAlwaysReturnsTrue() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("test");
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes());

        // act
        final boolean supports = adapter.supports(credentials);

        // assert
        assertTrue(supports);
    }

    @Test
    public void testSupportsWithNullCredentials() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("test");
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);

        // act
        final boolean supports = adapter.supports(null);

        // assert
        assertTrue(supports);
    }

    @Test
    public void testAuthenticateSuccess() throws AuthenticationException {
        // arrange
        final User user = new User(
            "testuser",
            ImmutableSet.of("role1", "role2"),
            ImmutableSet.of("security_role1"),
            null,
            ImmutableMap.of("email", "test@example.com", "department", "Engineering"),
            false
        );
        final AuthenticationBackend backend = new TestAuthenticationBackend("ldap", user);
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("testuser", "password".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act
        final UserPrincipal principal = adapter.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("testuser"));
        assertThat(principal.getAuthenticationType(), is("legacy"));

        // Verify backend roles are in claims
        final Map<String, Object> claims = principal.getClaims();
        assertThat(claims, is(notNullValue()));
        assertThat(claims.containsKey("backend_roles"), is(true));

        @SuppressWarnings("unchecked")
        final List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertThat(backendRoles, is(notNullValue()));
        assertThat(backendRoles.size(), is(2));
        assertTrue(backendRoles.contains("role1"));
        assertTrue(backendRoles.contains("role2"));

        // Verify attributes are in claims
        assertThat(claims.get("email"), is("test@example.com"));
        assertThat(claims.get("department"), is("Engineering"));
    }

    @Test
    public void testAuthenticateWithEmptyRolesAndAttributes() throws AuthenticationException {
        // arrange
        final User user = new User("simpleuser");
        final AuthenticationBackend backend = new TestAuthenticationBackend("internal", user);
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("simpleuser", "password".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act
        final UserPrincipal principal = adapter.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("simpleuser"));
        assertThat(principal.getAuthenticationType(), is("legacy"));
        assertThat(principal.getClaims(), is(notNullValue()));
    }

    @Test
    public void testAuthenticateBackendReturnsNull() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("test", null);
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> adapter.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("test"));
        assertThat(exception.getReason(), containsString("Backend returned null user"));
    }

    @Test
    public void testAuthenticateBackendThrowsOpenSearchSecurityException() {
        // arrange
        final AuthenticationBackend backend = new FailingAuthenticationBackend(
            "ldap",
            new OpenSearchSecurityException("Invalid credentials")
        );
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("user", "wrongpassword".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> adapter.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("ldap"));
        assertThat(exception.getReason(), is("Invalid credentials"));
        assertThat(exception.getCause(), is(instanceOf(OpenSearchSecurityException.class)));
    }

    @Test
    public void testAuthenticateBackendThrowsRuntimeException() {
        // arrange
        final AuthenticationBackend backend = new FailingAuthenticationBackend(
            "saml",
            new RuntimeException("Connection timeout")
        );
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> adapter.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("saml"));
        assertThat(exception.getReason(), containsString("Unexpected error during authentication"));
        assertThat(exception.getReason(), containsString("Connection timeout"));
        assertThat(exception.getCause(), is(instanceOf(RuntimeException.class)));
    }

    @Test
    public void testGetBackend() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("test");
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);

        // act
        final AuthenticationBackend retrievedBackend = adapter.getBackend();

        // assert
        assertThat(retrievedBackend, is(backend));
    }

    @Test
    public void testToString() {
        // arrange
        final AuthenticationBackend backend = new TestAuthenticationBackend("ldap");
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);

        // act
        final String string = adapter.toString();

        // assert
        assertThat(string, containsString("AuthenticationBackendAdapter"));
        assertThat(string, containsString("TestAuthenticationBackend"));
        assertThat(string, containsString("ldap"));
    }

    @Test
    public void testAuthenticateWithComplexAttributes() throws AuthenticationException {
        // arrange
        final Map<String, String> attributes = new HashMap<>();
        attributes.put("email", "user@example.com");
        attributes.put("department", "Engineering");
        attributes.put("location", "Seattle");
        attributes.put("employee_id", "12345");

        final User user = new User(
            "complexuser",
            ImmutableSet.of("developers", "admins"),
            ImmutableSet.of("kibana_user", "all_access"),
            "tenant1",
            ImmutableMap.copyOf(attributes),
            false
        );

        final AuthenticationBackend backend = new TestAuthenticationBackend("ldap", user);
        final AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(backend);
        final AuthCredentials credentials = new AuthCredentials("complexuser", "password".getBytes());
        final AuthenticationContext context = new AuthenticationContext(credentials);

        // act
        final UserPrincipal principal = adapter.authenticate(context);

        // assert
        assertThat(principal, is(notNullValue()));
        assertThat(principal.getName(), is("complexuser"));

        final Map<String, Object> claims = principal.getClaims();
        assertThat(claims.get("email"), is("user@example.com"));
        assertThat(claims.get("department"), is("Engineering"));
        assertThat(claims.get("location"), is("Seattle"));
        assertThat(claims.get("employee_id"), is("12345"));

        @SuppressWarnings("unchecked")
        final List<String> backendRoles = (List<String>) claims.get("backend_roles");
        assertThat(backendRoles, is(notNullValue()));
        assertTrue(backendRoles.contains("developers"));
        assertTrue(backendRoles.contains("admins"));
    }

    // Test helper classes

    /**
     * Simple test implementation of AuthenticationBackend
     */
    private static class TestAuthenticationBackend implements AuthenticationBackend {
        private final String type;
        private final User userToReturn;

        public TestAuthenticationBackend(String type) {
            this(type, new User("testuser"));
        }

        public TestAuthenticationBackend(String type, User userToReturn) {
            this.type = type;
            this.userToReturn = userToReturn;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
            return userToReturn;
        }
    }

    /**
     * Test implementation that throws exceptions
     */
    private static class FailingAuthenticationBackend implements AuthenticationBackend {
        private final String type;
        private final Exception exceptionToThrow;

        public FailingAuthenticationBackend(String type, Exception exceptionToThrow) {
            this.type = type;
            this.exceptionToThrow = exceptionToThrow;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
            if (exceptionToThrow instanceof OpenSearchSecurityException) {
                throw (OpenSearchSecurityException) exceptionToThrow;
            } else if (exceptionToThrow instanceof RuntimeException) {
                throw (RuntimeException) exceptionToThrow;
            } else {
                throw new RuntimeException(exceptionToThrow);
            }
        }
    }
}
