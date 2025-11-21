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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AuthorizationBackendAdapterTest {

    @Test
    public void testConstructorWithNullBackend() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new AuthorizationBackendAdapter(null)
        );
        assertThat(exception.getMessage(), is("backend must not be null"));
    }

    @Test
    public void testGetType() {
        // arrange
        final AuthorizationBackend backend = new TestAuthorizationBackend("ldap");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        // act
        final String type = adapter.getType();

        // assert
        assertThat(type, is("ldap"));
    }

    @Test
    public void testAuthorizeSuccess() {
        // arrange
        final AuthorizationBackend backend = new TestAuthorizationBackend("ldap");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of("backend_roles", java.util.Arrays.asList("role1", "role2")))
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "myindex")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeWithRolesAdded() {
        // arrange
        final Set<String> rolesToAdd = new HashSet<>();
        rolesToAdd.add("admin");
        rolesToAdd.add("developer");

        final AuthorizationBackend backend = new RoleAddingAuthorizationBackend("ldap", rolesToAdd);
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of("email", "test@example.com"))
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/write/index", "myindex")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeBackendReturnsNull() {
        // arrange
        final AuthorizationBackend backend = new NullReturningAuthorizationBackend("test");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of())
            .authenticationType("internal")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("cluster:monitor/health", "_cluster")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(false));
        assertThat(result.getReason(), containsString("Backend returned null user"));
    }

    @Test
    public void testAuthorizeBackendThrowsOpenSearchSecurityException() {
        // arrange
        final AuthorizationBackend backend = new FailingAuthorizationBackend(
            "ldap",
            new OpenSearchSecurityException("LDAP server unavailable")
        );
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of())
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/get", "myindex")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(false));
        assertThat(result.getReason(), is("LDAP server unavailable"));
    }

    @Test
    public void testAuthorizeBackendThrowsRuntimeException() {
        // arrange
        final AuthorizationBackend backend = new FailingAuthorizationBackend(
            "saml",
            new RuntimeException("Connection timeout")
        );
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of())
            .authenticationType("saml")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:admin/create", "newindex")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(false));
        assertThat(result.getReason(), containsString("Unexpected error during authorization"));
        assertThat(result.getReason(), containsString("Connection timeout"));
    }

    @Test
    public void testResolvePermissions() {
        // arrange
        final Set<String> rolesToAdd = new HashSet<>();
        rolesToAdd.add("kibana_user");
        rolesToAdd.add("all_access");

        final AuthorizationBackend backend = new RoleAddingAuthorizationBackend("ldap", rolesToAdd);
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of("backend_roles", java.util.Arrays.asList("developers", "admins")))
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        // act
        final Set<String> permissions = adapter.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(4)); // 2 backend roles + 2 added roles
        assertThat(permissions, hasItems("developers", "admins", "kibana_user", "all_access"));
    }

    @Test
    public void testResolvePermissionsWithNoRoles() {
        // arrange
        final AuthorizationBackend backend = new TestAuthorizationBackend("internal");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("simpleuser")
            .claims(ImmutableMap.of())
            .authenticationType("internal")
            .authenticationTime(System.currentTimeMillis())
            .build();

        // act
        final Set<String> permissions = adapter.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        // May be empty or contain default roles depending on backend behavior
    }

    @Test
    public void testResolvePermissionsBackendReturnsNull() {
        // arrange
        final AuthorizationBackend backend = new NullReturningAuthorizationBackend("test");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of())
            .authenticationType("internal")
            .authenticationTime(System.currentTimeMillis())
            .build();

        // act
        final Set<String> permissions = adapter.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testResolvePermissionsBackendThrowsException() {
        // arrange
        final AuthorizationBackend backend = new FailingAuthorizationBackend(
            "ldap",
            new OpenSearchSecurityException("LDAP connection failed")
        );
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(ImmutableMap.of())
            .authenticationType("ldap")
            .authenticationTime(System.currentTimeMillis())
            .build();

        // act
        final Set<String> permissions = adapter.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testGetBackend() {
        // arrange
        final AuthorizationBackend backend = new TestAuthorizationBackend("test");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        // act
        final AuthorizationBackend retrievedBackend = adapter.getBackend();

        // assert
        assertThat(retrievedBackend, is(backend));
    }

    @Test
    public void testToString() {
        // arrange
        final AuthorizationBackend backend = new TestAuthorizationBackend("ldap");
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        // act
        final String string = adapter.toString();

        // assert
        assertThat(string, containsString("AuthorizationBackendAdapter"));
        assertThat(string, containsString("TestAuthorizationBackend"));
        assertThat(string, containsString("ldap"));
    }

    @Test
    public void testAuthorizeWithComplexPrincipal() {
        // arrange
        final Set<String> rolesToAdd = new HashSet<>();
        rolesToAdd.add("custom_role");

        final AuthorizationBackend backend = new RoleAddingAuthorizationBackend("saml", rolesToAdd);
        final AuthorizationBackendAdapter adapter = new AuthorizationBackendAdapter(backend);

        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", java.util.Arrays.asList("developers", "testers"));
        claims.put("email", "user@example.com");
        claims.put("department", "Engineering");
        claims.put("groups", java.util.Arrays.asList("group1", "group2"));

        final UserPrincipal principal = UserPrincipal.builder("complexuser")
            .claims(claims)
            .authenticationType("saml")
            .authenticationTime(System.currentTimeMillis())
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "myindex")
            .build();

        // act
        final AuthorizationResult result = adapter.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    // Test helper classes

    /**
     * Simple test implementation of AuthorizationBackend that returns the user unchanged
     */
    private static class TestAuthorizationBackend implements AuthorizationBackend {
        private final String type;

        public TestAuthorizationBackend(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
            // Return user unchanged (no roles added)
            return user;
        }
    }

    /**
     * Test implementation that adds specific roles to the user
     */
    private static class RoleAddingAuthorizationBackend implements AuthorizationBackend {
        private final String type;
        private final Set<String> rolesToAdd;

        public RoleAddingAuthorizationBackend(String type, Set<String> rolesToAdd) {
            this.type = type;
            this.rolesToAdd = rolesToAdd;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
            // Add roles to the user
            return user.withSecurityRoles(rolesToAdd);
        }
    }

    /**
     * Test implementation that returns null
     */
    private static class NullReturningAuthorizationBackend implements AuthorizationBackend {
        private final String type;

        public NullReturningAuthorizationBackend(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
            return null;
        }
    }

    /**
     * Test implementation that throws exceptions
     */
    private static class FailingAuthorizationBackend implements AuthorizationBackend {
        private final String type;
        private final Exception exceptionToThrow;

        public FailingAuthorizationBackend(String type, Exception exceptionToThrow) {
            this.type = type;
            this.exceptionToThrow = exceptionToThrow;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public User addRoles(User user, AuthenticationContext context) throws OpenSearchSecurityException {
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
