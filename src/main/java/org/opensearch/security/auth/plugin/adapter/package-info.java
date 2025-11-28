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

/**
 * Adapter classes for backward compatibility with legacy authentication and authorization backends.
 * <p>
 * <b>IMPORTANT - Current Usage:</b> As of the current release, all built-in authentication and
 * authorization backends have been converted to implement the new plugin interfaces directly.
 * The adapters in this package are now <b>ONLY</b> used for third-party custom backends that
 * haven't migrated to the new interfaces yet.
 * <p>
 * <b>Built-in Backends (Converted - No Longer Use Adapters):</b>
 * <ul>
 *   <li>{@code InternalAuthenticationBackend} - implements {@code AuthenticationPlugin}</li>
 *   <li>{@code LDAPAuthenticationBackend2} - implements {@code AuthenticationPlugin}</li>
 *   <li>{@code LDAPAuthorizationBackend2} - implements {@code AuthorizationPlugin}</li>
 *   <li>{@code HTTPSamlAuthenticator} - implements {@code AuthenticationPlugin}</li>
 *   <li>{@code HTTPJwtAuthenticator} - implements {@code AuthenticationPlugin}</li>
 *   <li>{@code HTTPSpnegoAuthenticator} - implements {@code AuthenticationPlugin}</li>
 * </ul>
 * <p>
 * <b>Adapter Purpose:</b>
 * <ul>
 *   <li>{@link org.opensearch.security.auth.plugin.adapter.AuthenticationBackendAdapter} - 
 *       Wraps {@code AuthenticationBackend} to implement {@code AuthenticationPlugin}</li>
 *   <li>{@link org.opensearch.security.auth.plugin.adapter.AuthorizationBackendAdapter} - 
 *       Wraps {@code AuthorizationBackend} to implement {@code AuthorizationPlugin}</li>
 * </ul>
 * <p>
 * <b>When Adapters Are Used:</b>
 * <ul>
 *   <li>When {@code BackendRegistry.registerAuthenticationBackend()} is called with a backend
 *       that does NOT implement {@code AuthenticationPlugin}</li>
 *   <li>When {@code BackendRegistry.registerAuthorizationBackend()} is called with a backend
 *       that does NOT implement {@code AuthorizationPlugin}</li>
 *   <li>Automatically by {@code BackendRegistry} for backward compatibility</li>
 * </ul>
 * <p>
 * <b>Migration Path for Third-Party Plugins:</b>
 * <ol>
 *   <li>Update your backend class to implement {@code AuthenticationPlugin} or {@code AuthorizationPlugin}</li>
 *   <li>Change return types and method signatures to match new interfaces</li>
 *   <li>Extract claims into {@code UserPrincipal} instead of returning {@code User}</li>
 *   <li>Register using {@code registerAuthenticationPlugin()} or {@code registerAuthorizationPlugin()}</li>
 *   <li>Remove dependency on old {@code AuthenticationBackend} or {@code AuthorizationBackend} interfaces</li>
 * </ol>
 * <p>
 * <b>Benefits of Migration:</b>
 * <ul>
 *   <li>Eliminates adapter overhead</li>
 *   <li>Improves performance (direct method calls)</li>
 *   <li>Clearer stack traces for debugging</li>
 *   <li>Access to new plugin features</li>
 *   <li>Prepares for eventual removal of old interfaces</li>
 * </ul>
 * <p>
 * <b>Deprecation Timeline:</b>
 * <ul>
 *   <li>Current Release: Adapters maintained for third-party plugins</li>
 *   <li>Next Release: Old interfaces will be marked {@code @Deprecated}</li>
 *   <li>Future Major Release: Old interfaces will be removed</li>
 * </ul>
 * <p>
 * For detailed migration instructions, see the Plugin Migration Guide in the project documentation.
 *
 * @see org.opensearch.security.auth.plugin.AuthenticationPlugin
 * @see org.opensearch.security.auth.plugin.AuthorizationPlugin
 * @see org.opensearch.security.auth.AuthenticationBackend
 * @see org.opensearch.security.auth.AuthorizationBackend
 */
package org.opensearch.security.auth.plugin.adapter;
