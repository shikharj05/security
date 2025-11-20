/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin;

import java.util.Set;

import org.opensearch.security.user.UserPrincipal;

/**
 * Plugin interface for authorization in the OpenSearch Security plugin.
 *
 * <p>Authorization plugins are responsible for making access control decisions based on
 * an authenticated user principal. They evaluate whether a user should be granted access
 * to specific resources and actions within the OpenSearch cluster.</p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Evaluate access control policies for authenticated users</li>
 *   <li>Map user claims to authorization roles and permissions</li>
 *   <li>Make allow/deny decisions for resource access requests</li>
 *   <li>Resolve effective permissions for caching and optimization</li>
 * </ul>
 *
 * <h2>Contract and Guarantees</h2>
 * <ul>
 *   <li><strong>Input:</strong> Receives a {@link UserPrincipal} that has been verified by an authentication plugin</li>
 *   <li><strong>No Authentication:</strong> Must NOT perform credential verification or authentication</li>
 *   <li><strong>Claims-Based:</strong> Makes decisions based solely on the principal's identity and claims</li>
 *   <li><strong>Stateless:</strong> Should be stateless and thread-safe for concurrent requests</li>
 *   <li><strong>Idempotent:</strong> Same principal and context should produce same authorization result</li>
 * </ul>
 *
 * <h2>Separation of Concerns</h2>
 * <p>Authorization plugins are strictly separated from authentication:</p>
 * <ul>
 *   <li>They receive an already-authenticated {@link UserPrincipal}</li>
 *   <li>They do NOT verify credentials or perform authentication</li>
 *   <li>They do NOT modify the principal or its claims</li>
 *   <li>They only evaluate access control based on provided information</li>
 * </ul>
 *
 * <h2>Implementation Guidelines</h2>
 * <ul>
 *   <li><strong>Claims Mapping:</strong> Extract relevant claims from the principal for authorization decisions</li>
 *   <li><strong>Policy Evaluation:</strong> Implement your authorization logic (RBAC, ABAC, etc.)</li>
 *   <li><strong>Performance:</strong> Cache resolved permissions when possible using {@link #resolvePermissions}</li>
 *   <li><strong>Error Handling:</strong> Return deny results with clear reasons rather than throwing exceptions</li>
 *   <li><strong>Logging:</strong> Log authorization decisions for audit and debugging purposes</li>
 * </ul>
 *
 * <h2>Example Implementation</h2>
 * <pre>{@code
 * public class RoleBasedAuthorizationPlugin implements AuthorizationPlugin {
 *
 *     @Override
 *     public String getType() {
 *         return "role_based";
 *     }
 *
 *     @Override
 *     public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
 *         // Extract roles from claims
 *         Set<String> roles = extractRolesFromClaims(principal.getClaims());
 *
 *         // Evaluate permissions based on roles
 *         boolean allowed = evaluatePermissions(roles, context.getAction(), context.getResource());
 *
 *         if (allowed) {
 *             return AuthorizationResult.allow();
 *         } else {
 *             return AuthorizationResult.deny("Insufficient permissions for action: " + context.getAction());
 *         }
 *     }
 *
 *     @Override
 *     public Set<String> resolvePermissions(UserPrincipal principal) {
 *         // Map claims to security roles for caching
 *         return mapClaimsToRoles(principal.getClaims());
 *     }
 * }
 * }</pre>
 *
 * <h2>Multiple Authorization Plugins</h2>
 * <p>When multiple authorization plugins are configured, the Security Plugin coordinates their evaluation.
 * Typically, all plugins must allow access for the request to proceed (AND logic), though this behavior
 * may be configurable.</p>
 *
 * @see UserPrincipal
 * @see AuthorizationContext
 * @see AuthorizationResult
 * @see AuthenticationPlugin
 */
public interface AuthorizationPlugin {

    /**
     * Returns the unique type identifier for this authorization plugin.
     *
     * <p>The type identifier is used for:</p>
     * <ul>
     *   <li>Plugin registration and configuration</li>
     *   <li>Logging and audit trails</li>
     *   <li>Distinguishing between multiple authorization plugins</li>
     * </ul>
     *
     * <p>Examples: "role_based", "attribute_based", "policy_based", "ldap_groups"</p>
     *
     * @return a unique string identifier for this plugin type, must not be null or empty
     */
    String getType();

    /**
     * Makes an authorization decision for a resource access request.
     *
     * <p>This method evaluates whether the authenticated user principal should be granted
     * access to perform a specific action on a specific resource. The decision is based on:</p>
     * <ul>
     *   <li>The user's identity from the principal</li>
     *   <li>Claims extracted during authentication (roles, groups, attributes)</li>
     *   <li>The requested action (e.g., "indices:data/read/search")</li>
     *   <li>The target resource (e.g., index name, pattern)</li>
     *   <li>Additional context (remote address, resource attributes)</li>
     * </ul>
     *
     * <h3>Implementation Requirements</h3>
     * <ul>
     *   <li><strong>Thread-Safe:</strong> Must be safe to call concurrently from multiple threads</li>
     *   <li><strong>No Side Effects:</strong> Must not modify the principal or context</li>
     *   <li><strong>Deterministic:</strong> Same inputs should produce same output</li>
     *   <li><strong>Fast:</strong> Should complete quickly; use caching for expensive operations</li>
     *   <li><strong>Clear Reasons:</strong> Deny results should include helpful reason messages</li>
     * </ul>
     *
     * <h3>Error Handling</h3>
     * <p>Implementations should generally return {@link AuthorizationResult#deny} rather than
     * throwing exceptions. Exceptions should only be thrown for unexpected errors (e.g.,
     * configuration problems, system failures), not for authorization denials.</p>
     *
     * @param principal the authenticated user principal containing identity and claims, must not be null
     * @param context the authorization context containing the resource, action, and request metadata, must not be null
     * @return an {@link AuthorizationResult} indicating whether access is allowed or denied, must not be null
     * @throws AuthorizationException only for unexpected system errors, not for authorization denials
     * @throws IllegalArgumentException if principal or context is null
     */
    AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context);

    /**
     * Resolves the effective permissions for a user principal.
     *
     * <p>This method maps the user's claims to a set of resolved permissions or roles that
     * can be used for caching and optimization. The returned set represents the effective
     * permissions that the user has based on their claims.</p>
     *
     * <h3>Purpose</h3>
     * <ul>
     *   <li><strong>Caching:</strong> Results can be cached to avoid repeated claims mapping</li>
     *   <li><strong>Optimization:</strong> Pre-compute expensive claims-to-permissions mappings</li>
     *   <li><strong>Auditing:</strong> Provide visibility into effective user permissions</li>
     * </ul>
     *
     * <h3>Implementation Guidelines</h3>
     * <ul>
     *   <li>Extract relevant claims from the principal (e.g., "groups", "roles", "backend_roles")</li>
     *   <li>Map claims to your authorization system's permission model</li>
     *   <li>Return a set of permission identifiers or role names</li>
     *   <li>The returned set should be immutable or defensively copied</li>
     *   <li>Return an empty set if no permissions can be resolved</li>
     * </ul>
     *
     * <h3>Example</h3>
     * <pre>{@code
     * // For a role-based system:
     * public Set<String> resolvePermissions(UserPrincipal principal) {
     *     List<String> groups = (List<String>) principal.getClaims().get("groups");
     *     Set<String> roles = new HashSet<>();
     *
     *     for (String group : groups) {
     *         // Map LDAP groups to security roles
     *         if (group.contains("cn=admins")) {
     *             roles.add("admin");
     *         } else if (group.contains("cn=developers")) {
     *             roles.add("developer");
     *         }
     *     }
     *
     *     return Collections.unmodifiableSet(roles);
     * }
     * }</pre>
     *
     * @param principal the authenticated user principal containing identity and claims, must not be null
     * @return a set of resolved permission identifiers or role names, must not be null (may be empty)
     * @throws IllegalArgumentException if principal is null
     */
    Set<String> resolvePermissions(UserPrincipal principal);
}
