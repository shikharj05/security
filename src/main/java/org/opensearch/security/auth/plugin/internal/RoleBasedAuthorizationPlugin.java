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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.UserPrincipal;

/**
 * Role-based authorization plugin for OpenSearch Security.
 * <p>
 * This plugin implements role-based access control (RBAC) by mapping claims from
 * the authenticated user principal to security roles, then evaluating permissions
 * based on those roles and resource patterns.
 * <p>
 * The plugin extracts roles from various claim sources:
 * <ul>
 *   <li>backend_roles - Roles from authentication backends (LDAP groups, SAML assertions, etc.)</li>
 *   <li>security_roles - Pre-assigned security roles from internal user database</li>
 * </ul>
 * <p>
 * This implementation provides a reference authorization plugin that demonstrates
 * the separation between authentication and authorization in the new plugin architecture.
 *
 * @see AuthorizationPlugin
 * @see UserPrincipal
 */
public class RoleBasedAuthorizationPlugin implements AuthorizationPlugin {

    /**
     * Creates a new role-based authorization plugin.
     */
    public RoleBasedAuthorizationPlugin() {
        // Default constructor
    }

    @Override
    public String getType() {
        return "role_based";
    }

    @Override
    public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
        if (principal == null) {
            throw new IllegalArgumentException("principal must not be null");
        }
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }

        // Extract roles from claims
        Set<String> roles = extractRolesFromClaims(principal.getClaims());

        // For this reference implementation, we perform basic role-based authorization
        // In a production implementation, this would evaluate against configured role permissions
        
        // If user has any roles, allow access (simplified logic for reference implementation)
        // A real implementation would check specific permissions for the action and resource
        if (!roles.isEmpty()) {
            return AuthorizationResult.allow();
        }

        // Deny access if no roles found
        return AuthorizationResult.deny(
            "No roles found for user '" + principal.getName() + "' to access resource '" + context.getResource() + "'"
        );
    }

    @Override
    public Set<String> resolvePermissions(UserPrincipal principal) {
        if (principal == null) {
            throw new IllegalArgumentException("principal must not be null");
        }

        // Extract and return all roles from claims
        return extractRolesFromClaims(principal.getClaims());
    }

    /**
     * Extracts roles from the user principal's claims.
     * <p>
     * This method looks for roles in multiple claim sources:
     * <ul>
     *   <li>backend_roles - Roles from authentication backends</li>
     *   <li>security_roles - Pre-assigned security roles</li>
     * </ul>
     *
     * @param claims The claims map from the user principal
     * @return A set of role names extracted from claims, never null
     */
    private Set<String> extractRolesFromClaims(java.util.Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> roles = new HashSet<>();

        // Extract backend roles
        Object backendRolesObj = claims.get("backend_roles");
        if (backendRolesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> backendRoles = (List<String>) backendRolesObj;
            roles.addAll(backendRoles);
        }

        // Extract security roles
        Object securityRolesObj = claims.get("security_roles");
        if (securityRolesObj instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> securityRoles = (List<String>) securityRolesObj;
            roles.addAll(securityRoles);
        }

        return Collections.unmodifiableSet(roles);
    }
}
