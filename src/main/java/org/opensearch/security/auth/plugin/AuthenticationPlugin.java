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

package org.opensearch.security.auth.plugin;

import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

/**
 * Plugin interface for authentication in the OpenSearch Security plugin.
 *
 * <p>Authentication plugins are responsible for verifying user credentials and extracting
 * claims from authentication sources. They focus solely on identity verification and
 * should NOT make authorization decisions about resource access.</p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Verify user credentials against an authentication source (e.g., LDAP, SAML, internal database)</li>
 *   <li>Extract claims from the authentication source (e.g., groups, roles, attributes)</li>
 *   <li>Return a {@link UserPrincipal} containing the verified identity and extracted claims</li>
 *   <li>Indicate which credential types are supported via {@link #supports(AuthCredentials)}</li>
 * </ul>
 *
 * <h2>Non-Responsibilities</h2>
 * <ul>
 *   <li>Making authorization decisions about resource access</li>
 *   <li>Evaluating permissions or roles for authorization purposes</li>
 *   <li>Interpreting the authorization meaning of extracted claims</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * <p>Implementations must:</p>
 * <ul>
 *   <li>Return a unique type identifier via {@link #getType()}</li>
 *   <li>Implement {@link #supports(AuthCredentials)} to indicate credential compatibility</li>
 *   <li>Implement {@link #authenticate(AuthenticationContext)} to perform authentication</li>
 *   <li>Throw {@link AuthenticationException} when authentication fails</li>
 *   <li>Never return null from {@link #authenticate(AuthenticationContext)}</li>
 *   <li>Ensure {@link UserPrincipal} contains all relevant claims from the authentication source</li>
 * </ul>
 *
 * <h2>Claims Extraction</h2>
 * <p>Claims are attributes or assertions about a user provided by the authentication source.
 * Examples include:</p>
 * <ul>
 *   <li>LDAP: groups (memberOf), email, department, custom attributes</li>
 *   <li>SAML: assertion attributes, groups, email, custom claims</li>
 *   <li>OIDC: standard claims (email, groups, etc.) and custom claims</li>
 *   <li>Internal: roles, custom attributes from internal user database</li>
 * </ul>
 *
 * <p>Claims should be stored in the {@link UserPrincipal} as key-value pairs without
 * interpretation of their authorization meaning. Authorization plugins will later
 * map these claims to permissions and roles.</p>
 *
 * <h2>Thread Safety</h2>
 * <p>Implementations must be thread-safe as they may be called concurrently by multiple
 * threads processing different requests.</p>
 *
 * <h2>Example Implementation</h2>
 * <pre>{@code
 * public class LDAPAuthenticationPlugin implements AuthenticationPlugin {
 *
 *     @Override
 *     public String getType() {
 *         return "ldap";
 *     }
 *
 *     @Override
 *     public boolean supports(AuthCredentials credentials) {
 *         return credentials != null && credentials.getUsername() != null;
 *     }
 *
 *     @Override
 *     public UserPrincipal authenticate(AuthenticationContext context)
 *             throws AuthenticationException {
 *         AuthCredentials credentials = context.getCredentials();
 *
 *         // Verify credentials against LDAP
 *         LdapUser ldapUser = ldapClient.authenticate(
 *             credentials.getUsername(),
 *             credentials.getPassword()
 *         );
 *
 *         // Extract claims from LDAP
 *         Map<String, Object> claims = new HashMap<>();
 *         claims.put("groups", ldapUser.getGroups());
 *         claims.put("email", ldapUser.getEmail());
 *         claims.put("department", ldapUser.getDepartment());
 *
 *         // Return UserPrincipal with identity and claims
 *         return new UserPrincipal(
 *             credentials.getUsername(),
 *             ImmutableMap.copyOf(claims),
 *             getType(),
 *             System.currentTimeMillis()
 *         );
 *     }
 * }
 * }</pre>
 *
 * <h2>Integration with Security Plugin</h2>
 * <p>Authentication plugins are registered with the {@code BackendRegistry} and are
 * invoked during the authentication phase of request processing. The {@link UserPrincipal}
 * returned by successful authentication is passed to authorization plugins for access
 * control decisions.</p>
 *
 * <h2>Backward Compatibility</h2>
 * <p>This interface is part of the new plugin architecture that separates authentication
 * and authorization concerns. Existing {@code AuthenticationBackend} implementations
 * continue to work through adapter classes that wrap them to implement this interface.</p>
 *
 * @see UserPrincipal
 * @see AuthenticationContext
 * @see AuthenticationException
 * @see org.opensearch.security.auth.plugin.AuthorizationPlugin
 */
public interface AuthenticationPlugin {

    /**
     * Returns the unique type identifier for this authentication plugin.
     *
     * <p>The type identifier is used for:</p>
     * <ul>
     *   <li>Configuration - identifying which plugin to use in config files</li>
     *   <li>Logging - tracking which plugin authenticated a user</li>
     *   <li>Auditing - recording the authentication method used</li>
     *   <li>Debugging - troubleshooting authentication issues</li>
     * </ul>
     *
     * <p>Type identifiers should be:</p>
     * <ul>
     *   <li>Lowercase alphanumeric strings (e.g., "ldap", "saml", "internal")</li>
     *   <li>Unique across all authentication plugins in the system</li>
     *   <li>Stable across versions (not changed in updates)</li>
     * </ul>
     *
     * @return the unique type identifier for this plugin, never null or empty
     */
    String getType();

    /**
     * Authenticates a user and extracts claims from the authentication source.
     *
     * <p>This method performs the core authentication logic:</p>
     * <ol>
     *   <li>Extract credentials from the {@link AuthenticationContext}</li>
     *   <li>Verify credentials against the authentication source</li>
     *   <li>Extract claims (groups, attributes, etc.) from the authentication source</li>
     *   <li>Return a {@link UserPrincipal} with the verified identity and claims</li>
     * </ol>
     *
     * <p>The returned {@link UserPrincipal} must contain:</p>
     * <ul>
     *   <li>The verified user identifier (username or unique ID)</li>
     *   <li>All relevant claims extracted from the authentication source</li>
     *   <li>The authentication type (from {@link #getType()})</li>
     *   <li>The authentication timestamp</li>
     * </ul>
     *
     * <p><strong>Important:</strong> This method should NOT:</p>
     * <ul>
     *   <li>Make authorization decisions about resource access</li>
     *   <li>Evaluate permissions or roles for authorization</li>
     *   <li>Filter or interpret claims based on authorization policies</li>
     * </ul>
     *
     * <p>Claims should be extracted as-is from the authentication source without
     * interpretation. Authorization plugins will later map these claims to permissions.</p>
     *
     * <h3>Error Handling</h3>
     * <p>Implementations should throw {@link AuthenticationException} for authentication
     * failures, including:</p>
     * <ul>
     *   <li>Invalid credentials (wrong username/password)</li>
     *   <li>Expired credentials</li>
     *   <li>Locked or disabled accounts</li>
     *   <li>Authentication source unavailable</li>
     *   <li>Configuration errors</li>
     * </ul>
     *
     * <p>The exception should include a descriptive reason for the failure to aid
     * in debugging and auditing.</p>
     *
     * <h3>Performance Considerations</h3>
     * <p>This method may be called frequently and should be optimized for performance:</p>
     * <ul>
     *   <li>Use connection pooling for external authentication sources</li>
     *   <li>Implement appropriate timeouts to prevent hanging</li>
     *   <li>Consider caching where appropriate (handled by the registry)</li>
     *   <li>Log performance metrics for monitoring</li>
     * </ul>
     *
     * @param context the authentication context containing credentials and request metadata,
     *                never null
     * @return a {@link UserPrincipal} containing the verified identity and extracted claims,
     *         never null
     * @throws AuthenticationException if authentication fails for any reason
     * @throws IllegalArgumentException if context is null or invalid
     */
    UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException;

    /**
     * Indicates whether this plugin supports the given credentials type.
     *
     * <p>This method is called by the {@code BackendRegistry} to determine which
     * authentication plugin should handle a request. It allows plugins to indicate
     * compatibility with specific credential types without attempting full authentication.</p>
     *
     * <p>Implementations should check:</p>
     * <ul>
     *   <li>Whether the credentials object is non-null</li>
     *   <li>Whether required credential fields are present (e.g., username, password)</li>
     *   <li>Whether the credential type matches what this plugin expects</li>
     *   <li>Whether any special markers or attributes indicate compatibility</li>
     * </ul>
     *
     * <p>This method should be fast and lightweight as it may be called multiple times
     * per request when iterating through available plugins.</p>
     *
     * <h3>Examples</h3>
     * <pre>{@code
     * // Basic username/password check
     * public boolean supports(AuthCredentials credentials) {
     *     return credentials != null
     *         && credentials.getUsername() != null
     *         && credentials.getPassword() != null;
     * }
     *
     * // SAML token check
     * public boolean supports(AuthCredentials credentials) {
     *     return credentials != null
     *         && credentials.getNativeCredentials() instanceof SAMLCredential;
     * }
     *
     * // JWT token check
     * public boolean supports(AuthCredentials credentials) {
     *     return credentials != null
     *         && credentials.getNativeCredentials() instanceof JwtToken;
     * }
     * }</pre>
     *
     * <p><strong>Note:</strong> Returning {@code true} does not guarantee that
     * authentication will succeed, only that this plugin can attempt to authenticate
     * the given credentials.</p>
     *
     * @param credentials the credentials to check for support, may be null
     * @return {@code true} if this plugin can attempt to authenticate the given credentials,
     *         {@code false} otherwise
     */
    boolean supports(AuthCredentials credentials);
}
