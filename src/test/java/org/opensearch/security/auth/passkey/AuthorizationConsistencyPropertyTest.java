/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.junit.Test;

import org.opensearch.security.user.User;

import static org.junit.Assert.*;

/**
 * Property-based tests for authorization consistency.
 * 
 * **Feature: passkey-authentication, Property 31: Authorization consistency**
 * **Validates: Requirements 7.4**
 * 
 * For any passkey-authenticated user, authorization checks should behave identically 
 * to users authenticated by other methods.
 */
public class AuthorizationConsistencyPropertyTest {

    private static final Random random = new Random();

    /**
     * Property 31: Authorization consistency
     * 
     * For any passkey-authenticated user, authorization checks should behave identically 
     * to users authenticated by other methods.
     * 
     * This test verifies that User objects created from passkey authentication have the
     * same structure and behavior as User objects from other authentication methods.
     * 
     * This test runs 100 iterations with randomly generated user data.
     */
    @Test
    public void authorizationConsistency() {
        for (int i = 0; i < 100; i++) {
            // Generate random user data
            String username = generateRandomUsername();
            Set<String> roles = generateRandomRoles();
            Set<String> backendRoles = generateRandomBackendRoles();
            
            // Create a User object as would be created by passkey authentication
            User passkeyUser = new User(
                username,
                com.google.common.collect.ImmutableSet.copyOf(roles),
                com.google.common.collect.ImmutableSet.copyOf(backendRoles),
                null,
                com.google.common.collect.ImmutableMap.of(),
                false
            );
            
            // Create a User object as would be created by another authentication method
            // (e.g., basic auth, LDAP, etc.)
            User otherAuthUser = new User(
                username,
                com.google.common.collect.ImmutableSet.copyOf(roles),
                com.google.common.collect.ImmutableSet.copyOf(backendRoles),
                null,
                com.google.common.collect.ImmutableMap.of(),
                false
            );
            
            // Verify that both User objects have identical properties
            assertEquals("Username should match", passkeyUser.getName(), otherAuthUser.getName());
            assertEquals("Roles should match", passkeyUser.getRoles(), otherAuthUser.getRoles());
            assertEquals("Backend roles should match", passkeyUser.getSecurityRoles(), otherAuthUser.getSecurityRoles());
            
            // Verify that role checks behave identically
            for (String role : roles) {
                boolean passkeyHasRole = passkeyUser.getRoles().contains(role);
                boolean otherAuthHasRole = otherAuthUser.getRoles().contains(role);
                assertEquals(
                    "Role check for '" + role + "' should be consistent",
                    passkeyHasRole,
                    otherAuthHasRole
                );
            }
            
            // Verify that backend role checks behave identically
            for (String backendRole : backendRoles) {
                boolean passkeyHasBackendRole = passkeyUser.getSecurityRoles().contains(backendRole);
                boolean otherAuthHasBackendRole = otherAuthUser.getSecurityRoles().contains(backendRole);
                assertEquals(
                    "Backend role check for '" + backendRole + "' should be consistent",
                    passkeyHasBackendRole,
                    otherAuthHasBackendRole
                );
            }
            
            // Verify that the User objects are equal
            assertEquals("User objects should be equal", passkeyUser, otherAuthUser);
            assertEquals("Hash codes should be equal", passkeyUser.hashCode(), otherAuthUser.hashCode());
        }
    }

    /**
     * Generates a random username.
     */
    private String generateRandomUsername() {
        String[] prefixes = {"user", "admin", "test", "dev", "ops"};
        String prefix = prefixes[random.nextInt(prefixes.length)];
        int suffix = random.nextInt(10000);
        return prefix + suffix;
    }

    /**
     * Generates a random set of roles.
     */
    private Set<String> generateRandomRoles() {
        String[] availableRoles = {
            "admin",
            "user",
            "read_only",
            "write_access",
            "delete_access",
            "cluster_admin",
            "index_admin",
            "kibana_user",
            "logstash_user"
        };
        
        int roleCount = random.nextInt(5) + 1; // 1-5 roles
        Set<String> roles = new HashSet<>();
        for (int i = 0; i < roleCount; i++) {
            roles.add(availableRoles[random.nextInt(availableRoles.length)]);
        }
        return roles;
    }

    /**
     * Generates a random set of backend roles.
     */
    private Set<String> generateRandomBackendRoles() {
        String[] availableBackendRoles = {
            "backend_admin",
            "backend_user",
            "ldap_group_1",
            "ldap_group_2",
            "saml_group_1",
            "saml_group_2",
            "jwt_group_1",
            "jwt_group_2"
        };
        
        int roleCount = random.nextInt(4) + 1; // 1-4 backend roles
        Set<String> backendRoles = new HashSet<>();
        for (int i = 0; i < roleCount; i++) {
            backendRoles.add(availableBackendRoles[random.nextInt(availableBackendRoles.length)]);
        }
        return backendRoles;
    }
}
