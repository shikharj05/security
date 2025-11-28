/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/**
 * HTTP authenticator implementations for extracting credentials from HTTP requests.
 * 
 * <h2>Plugin Architecture Compatibility</h2>
 * 
 * <p>HTTPAuthenticator implementations are fully compatible with the new plugin architecture
 * without requiring any modifications. The authenticators continue to extract {@link org.opensearch.security.user.AuthCredentials}
 * from HTTP requests, which are then processed by authentication plugins in the {@link org.opensearch.security.auth.BackendRegistry}.
 * 
 * <h3>How HTTPAuthenticators Work with Plugins</h3>
 * 
 * <ol>
 *   <li><strong>Credential Extraction</strong>: HTTPAuthenticator implementations (JWT, SAML, Kerberos, etc.) 
 *       extract credentials from HTTP requests and return {@link org.opensearch.security.user.AuthCredentials}</li>
 *   <li><strong>Plugin Processing</strong>: The BackendRegistry receives the extracted credentials and passes them 
 *       to registered authentication plugins</li>
 *   <li><strong>Principal Creation</strong>: Authentication plugins create {@link org.opensearch.security.user.UserPrincipal} 
 *       objects from the credentials, including all extracted claims and attributes</li>
 *   <li><strong>Authorization</strong>: Authorization plugins receive the UserPrincipal and make access control decisions</li>
 * </ol>
 * 
 * <h3>Key Design Principles</h3>
 * 
 * <ul>
 *   <li><strong>No Interface Changes</strong>: The {@link org.opensearch.security.auth.HTTPAuthenticator} interface 
 *       remains unchanged</li>
 *   <li><strong>Backward Compatibility</strong>: All existing HTTPAuthenticator implementations work without modification</li>
 *   <li><strong>Attribute Preservation</strong>: All attributes extracted by HTTPAuthenticators (JWT claims, SAML assertions, etc.) 
 *       are preserved and available to plugins</li>
 *   <li><strong>Role Extraction</strong>: Backend roles extracted by HTTPAuthenticators are converted to claims in UserPrincipal</li>
 * </ul>
 * 
 * <h3>Tested Authenticator Types</h3>
 * 
 * <p>The following authenticator types have been verified to work correctly with the plugin architecture:
 * <ul>
 *   <li><strong>JWT</strong>: {@link org.opensearch.security.auth.http.jwt.HTTPJwtAuthenticator} - Extracts JWT claims as attributes</li>
 *   <li><strong>SAML</strong>: {@link org.opensearch.security.auth.http.saml.HTTPSamlAuthenticator} - Extracts SAML assertions</li>
 *   <li><strong>Kerberos</strong>: {@link org.opensearch.security.auth.http.kerberos.HTTPSpnegoAuthenticator} - Handles SPNEGO authentication</li>
 *   <li><strong>Basic Auth</strong>: Standard username/password extraction</li>
 * </ul>
 * 
 * @see org.opensearch.security.auth.HTTPAuthenticator
 * @see org.opensearch.security.auth.plugin.AuthenticationPlugin
 * @see org.opensearch.security.user.AuthCredentials
 * @see org.opensearch.security.user.UserPrincipal
 */
package org.opensearch.security.auth.http;
