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

package org.opensearch.security.auth.plugin.saml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

/**
 * Authentication plugin for SAML-based authentication.
 * <p>
 * This plugin processes SAML-authenticated credentials and extracts
 * SAML attributes as claims in the UserPrincipal. It supports configurable
 * attribute name mapping for SAML attributes.
 * <p>
 * Note: SAML assertion validation is handled by the HTTP layer
 * ({@code HTTPSamlAuthenticator}). This plugin processes the already-validated
 * credentials and extracts claims for authorization.
 * <p>
 * This implementation follows the new plugin architecture that separates
 * authentication from authorization.
 *
 * @see org.opensearch.security.auth.http.saml.HTTPSamlAuthenticator
 * @see org.opensearch.security.auth.http.saml.AuthTokenProcessorHandler
 */
public class SAMLAuthenticationPlugin implements AuthenticationPlugin {

    private static final Logger log = LogManager.getLogger(SAMLAuthenticationPlugin.class);

    private final Map<String, String> attributeMapping;

    /**
     * Creates a new SAML authentication plugin.
     *
     * @param attributeMapping Optional mapping of SAML attribute names to claim names
     */
    public SAMLAuthenticationPlugin(Map<String, String> attributeMapping) {
        this.attributeMapping = attributeMapping != null ? new HashMap<>(attributeMapping) : new HashMap<>();
    }

    @Override
    public String getType() {
        return "saml";
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // SAML authentication is typically handled through HTTP authenticators
        // This plugin processes SAML assertions that have already been validated
        return credentials != null && credentials.getUsername() != null;
    }

    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        AuthCredentials credentials = context.getCredentials();

        if (credentials == null || credentials.getUsername() == null) {
            throw new AuthenticationException(getType(), "Credentials or username is null");
        }

        try {
            // Build claims map from credentials
            Map<String, Object> claims = new HashMap<>();

            // Extract backend roles from credentials
            if (credentials.getBackendRoles() != null && !credentials.getBackendRoles().isEmpty()) {
                claims.put("backend_roles", new ArrayList<>(credentials.getBackendRoles()));
            }

            // Extract security roles from credentials
            if (credentials.getSecurityRoles() != null && !credentials.getSecurityRoles().isEmpty()) {
                claims.put("security_roles", new ArrayList<>(credentials.getSecurityRoles()));
            }

            // Add all attributes from credentials with saml.attr prefix
            if (credentials.getAttributes() != null && !credentials.getAttributes().isEmpty()) {
                for (Map.Entry<String, String> entry : credentials.getAttributes().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();

                    // Apply attribute mapping if configured
                    String mappedKey = attributeMapping.getOrDefault(key, key);

                    // Store with saml.attr prefix
                    claims.put("saml.attr." + mappedKey, value);

                    // Also store original key if mapping was applied
                    if (!key.equals(mappedKey)) {
                        claims.put("saml.attr." + key, value);
                    }
                }
            }

            // Return UserPrincipal with identity and claims
            return UserPrincipal.builder(credentials.getUsername())
                .claims(claims)
                .authenticationType(getType())
                .authenticationTime(System.currentTimeMillis())
                .build();

        } catch (Exception e) {
            if (e instanceof AuthenticationException) {
                throw (AuthenticationException) e;
            }
            log.error("Error extracting claims from SAML credentials", e);
            throw new AuthenticationException(getType(), "Error processing SAML credentials: " + e.getMessage());
        }
    }



    /**
     * Builder for creating SAMLAuthenticationPlugin instances with fluent API.
     */
    public static class Builder {
        private Map<String, String> attributeMapping = new HashMap<>();

        public Builder attributeMapping(Map<String, String> attributeMapping) {
            if (attributeMapping != null) {
                this.attributeMapping = new HashMap<>(attributeMapping);
            }
            return this;
        }

        public Builder addAttributeMapping(String samlAttribute, String claimName) {
            this.attributeMapping.put(samlAttribute, claimName);
            return this;
        }

        public SAMLAuthenticationPlugin build() {
            return new SAMLAuthenticationPlugin(attributeMapping);
        }
    }

    /**
     * Creates a new builder for SAMLAuthenticationPlugin.
     */
    public static Builder builder() {
        return new Builder();
    }
}
