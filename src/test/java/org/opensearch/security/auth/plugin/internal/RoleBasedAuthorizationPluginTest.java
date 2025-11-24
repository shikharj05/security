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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.UserPrincipal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

public class RoleBasedAuthorizationPluginTest {

    private RoleBasedAuthorizationPlugin plugin;

    @Before
    public void setUp() {
        plugin = new RoleBasedAuthorizationPlugin();
    }

    @Test
    public void testGetType() {
        // act
        final String type = plugin.getType();

        // assert
        assertThat(type, is("role_based"));
    }

    @Test
    public void testAuthorizeWithNullPrincipal() {
        // arrange
        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .build();

        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> plugin.authorize(null, context)
        );
        assertThat(exception.getMessage(), is("principal must not be null"));
    }

    @Test
    public void testAuthorizeWithNullContext() {
        // arrange
        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("internal")
            .build();

        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> plugin.authorize(principal, null)
        );
        assertThat(exception.getMessage(), is("context must not be null"));
    }

    @Test
    public void testAuthorizeWithNoRoles() {
        // arrange
        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("internal")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(false));
        assertThat(result.getReason(), containsString("No roles found"));
        assertThat(result.getReason(), containsString("testuser"));
        assertThat(result.getReason(), containsString("test-index"));
    }

    @Test
    public void testAuthorizeWithBackendRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("developers", "admins"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeWithSecurityRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("security_roles", List.of("kibana_user", "all_access"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/write/index", "logs-*")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeWithBothBackendAndSecurityRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("ldap_developers"));
        claims.put("security_roles", List.of("kibana_user"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/get", "documents")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeWithEmptyRoleLists() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", Collections.emptyList());
        claims.put("security_roles", Collections.emptyList());

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "test-index")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(false));
        assertThat(result.getReason(), containsString("No roles found"));
    }

    @Test
    public void testResolvePermissionsWithNullPrincipal() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> plugin.resolvePermissions(null)
        );
        assertThat(exception.getMessage(), is("principal must not be null"));
    }

    @Test
    public void testResolvePermissionsWithNoRoles() {
        // arrange
        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testResolvePermissionsWithBackendRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("developers", "admins"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(2));
        assertThat(permissions, containsInAnyOrder("developers", "admins"));
    }

    @Test
    public void testResolvePermissionsWithSecurityRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("security_roles", List.of("kibana_user", "all_access"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(2));
        assertThat(permissions, containsInAnyOrder("kibana_user", "all_access"));
    }

    @Test
    public void testResolvePermissionsWithBothBackendAndSecurityRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("ldap_developers", "ldap_admins"));
        claims.put("security_roles", List.of("kibana_user", "all_access"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(4));
        assertThat(permissions, containsInAnyOrder("ldap_developers", "ldap_admins", "kibana_user", "all_access"));
    }

    @Test
    public void testResolvePermissionsWithDuplicateRoles() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("admin", "developer"));
        claims.put("security_roles", List.of("admin", "kibana_user"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert - duplicates should be removed (Set behavior)
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(3));
        assertThat(permissions, containsInAnyOrder("admin", "developer", "kibana_user"));
    }

    @Test
    public void testResolvePermissionsWithNullClaims() {
        // arrange
        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(null)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testResolvePermissionsWithEmptyClaims() {
        // arrange
        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(Collections.emptyMap())
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testResolvePermissionsWithNonListRoleClaims() {
        // arrange - claims with non-List values should be ignored
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", "not-a-list");
        claims.put("security_roles", 12345);

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions, is(empty()));
    }

    @Test
    public void testResolvePermissionsWithOtherClaims() {
        // arrange - other claims should not affect role extraction
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("developer"));
        claims.put("email", "user@example.com");
        claims.put("department", "Engineering");
        claims.put("attr.internal.location", "Seattle");

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert - only backend_roles should be extracted
        assertThat(permissions, is(notNullValue()));
        assertThat(permissions.size(), is(1));
        assertThat(permissions, containsInAnyOrder("developer"));
    }

    @Test
    public void testResolvePermissionsReturnsImmutableSet() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("developer"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // act
        final Set<String> permissions = plugin.resolvePermissions(principal);

        // assert - should throw UnsupportedOperationException when trying to modify
        assertThrows(UnsupportedOperationException.class, () -> permissions.add("new-role"));
    }

    @Test
    public void testAuthorizeWithComplexResourcePattern() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("backend_roles", List.of("log_reader"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("ldap")
            .build();

        final AuthorizationContext context = AuthorizationContext.builder("indices:data/read/search", "logs-2024-*")
            .build();

        // act
        final AuthorizationResult result = plugin.authorize(principal, context);

        // assert
        assertThat(result, is(notNullValue()));
        assertThat(result.isAllowed(), is(true));
    }

    @Test
    public void testAuthorizeWithMultipleActions() {
        // arrange
        final Map<String, Object> claims = new HashMap<>();
        claims.put("security_roles", List.of("data_writer"));

        final UserPrincipal principal = UserPrincipal.builder("testuser")
            .claims(claims)
            .authenticationType("internal")
            .build();

        // Test different actions
        final String[] actions = {
            "indices:data/write/index",
            "indices:data/write/update",
            "indices:data/write/delete",
            "indices:data/read/search"
        };

        for (String action : actions) {
            final AuthorizationContext context = AuthorizationContext.builder(action, "data-index")
                .build();

            // act
            final AuthorizationResult result = plugin.authorize(principal, context);

            // assert
            assertThat("Action " + action + " should be allowed", result.isAllowed(), is(true));
        }
    }
}
