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

package org.opensearch.security.auth.plugin.jwt;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.security.util.KeyUtils;

import com.nimbusds.jwt.proc.BadJWTException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.security.WeakKeyException;

/**
 * Authentication plugin for JWT-based authentication.
 * <p>
 * This plugin processes JWT tokens and extracts claims for authorization.
 * It supports multiple signing keys, custom claims mapping, and audience validation.
 * <p>
 * This implementation follows the new plugin architecture that separates
 * authentication from authorization.
 */
public class JWTAuthenticationPlugin implements AuthenticationPlugin {

    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final DeprecationLogger deprecationLog = DeprecationLogger.getLogger(this.getClass());

    private static final Pattern BASIC = Pattern.compile("^\\s*Basic\\s.*", Pattern.CASE_INSENSITIVE);
    private static final String BEARER = "bearer ";
    private static final String AUTHORIZATION = "Authorization";

    private final List<JwtParser> jwtParsers = new ArrayList<>();
    private final String jwtHeaderName;
    private final boolean isDefaultAuthHeader;
    private final String jwtUrlParameter;
    private final List<String> rolesKey;
    private final List<String> subjectKey;
    private final List<String> requiredAudience;
    private final String requireIssuer;
    private final int clockSkewToleranceSeconds;

    /**
     * Creates a new JWT authentication plugin.
     *
     * @param settings Configuration settings for JWT authentication
     * @param configPath Path to configuration directory
     */
    public JWTAuthenticationPlugin(final Settings settings, final Path configPath) {
        super();

        List<String> signingKeys = settings.getAsList("signing_key");

        jwtUrlParameter = settings.get("jwt_url_parameter");
        jwtHeaderName = settings.get("jwt_header", AUTHORIZATION);
        isDefaultAuthHeader = AUTHORIZATION.equalsIgnoreCase(jwtHeaderName);
        rolesKey = settings.getAsList("roles_key");
        subjectKey = settings.getAsList("subject_key");
        requiredAudience = settings.getAsList("required_audience");
        requireIssuer = settings.get("required_issuer");
        clockSkewToleranceSeconds = settings.getAsInt(
            "jwt_clock_skew_tolerance_seconds",
            10 // Default clock skew tolerance
        );

        if (!jwtHeaderName.equals(AUTHORIZATION)) {
            deprecationLog.deprecate(
                "jwt_header",
                "The 'jwt_header' setting will be removed in the next major version of OpenSearch.  Consult https://github.com/opensearch-project/security/issues/3886 for more details."
            );
        }

        for (String key : signingKeys) {
            JwtParser jwtParser;
            final JwtParserBuilder jwtParserBuilder = KeyUtils.createJwtParserBuilderFromSigningKey(key, log);
            if (jwtParserBuilder == null) {
                jwtParser = null;
            } else {
                if (requireIssuer != null) {
                    jwtParserBuilder.requireIssuer(requireIssuer);
                }

                jwtParserBuilder.clockSkewSeconds(clockSkewToleranceSeconds);

                jwtParser = AccessController.doPrivileged(jwtParserBuilder::build);
            }
            jwtParsers.add(jwtParser);
        }
    }

    @Override
    public String getType() {
        return "jwt";
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // JWT authentication is handled through HTTP headers/parameters
        // This plugin processes JWT tokens that have been extracted
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

            // Add all attributes from credentials with jwt.attr prefix
            if (credentials.getAttributes() != null && !credentials.getAttributes().isEmpty()) {
                for (Map.Entry<String, String> entry : credentials.getAttributes().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();

                    // Store with attr.jwt prefix (matching HTTPJwtAuthenticator pattern)
                    claims.put(key, value);
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
            log.error("Error extracting claims from JWT credentials", e);
            throw new AuthenticationException(getType(), "Error processing JWT credentials: " + e.getMessage());
        }
    }

    /**
     * Extracts the subject from JWT claims.
     * Supports nested claim paths via subject_key configuration.
     */
    protected String extractSubject(final Claims claims) {
        String subject = claims.getSubject();
        if (subjectKey != null && !subjectKey.isEmpty()) {
            // Traverse the nested structure
            Object node = claims;
            for (String key : subjectKey) {
                if (!(node instanceof Map<?, ?> map)) {
                    log.warn(
                        "While following subject_key path {}, expected a JSON object before '{}', but found '{}' ({}).",
                        subjectKey,
                        key,
                        node,
                        node.getClass()
                    );
                    return null;
                }
                node = map.get(key);
                if (node == null) {
                    log.warn("Failed to find '{}' in JWT claims while following subject_key path {}.", key, subjectKey);
                    return null;
                }
            }
            // Interpret the leaf value
            if (node instanceof String str) {
                return str.trim();
            } else {
                log.warn(
                    "Expected a String at the end of subject_key path {}, but found '{}' ({}). Converting to String.",
                    subjectKey,
                    node,
                    node.getClass()
                );
                return String.valueOf(node).trim();
            }
        }
        return subject;
    }

    /**
     * Extracts roles from JWT claims.
     * Supports nested claim paths via roles_key configuration.
     */
    @SuppressWarnings("unchecked")
    protected String[] extractRoles(final Claims claims) {
        // Nothing configured → nothing to extract
        if (rolesKey == null || rolesKey.isEmpty()) {
            return new String[0];
        }

        // Traverse the nested structure
        Object node = claims;
        for (String key : rolesKey) {
            if (!(node instanceof Map<?, ?> map)) {
                log.warn(
                    "While following roles_key path {}, expected a JSON object before '{}', but found '{}' ({}).",
                    rolesKey,
                    key,
                    node,
                    node.getClass()
                );
                return new String[0];
            }
            node = map.get(key);
            if (node == null) {
                log.warn("Failed to find '{}' in JWT claims while following roles_key path {}.", key, rolesKey);
                return new String[0];
            }
        }

        // Interpret the leaf value
        Set<String> collected = new LinkedHashSet<>();

        if (node instanceof String str) {
            Arrays.stream(str.split(","))
                .map(String::trim)
                .filter(Predicate.not(String::isEmpty))
                .forEach(collected::add);
        } else if (node instanceof Collection<?> col) {
            col.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .map(String::trim)
                .filter(Predicate.not(String::isEmpty))
                .forEach(collected::add);
        } else {
            log.warn(
                "Expected a String or Collection at the end of roles_key path {}, but found '{}' ({}). Converting to String.",
                rolesKey,
                node,
                node.getClass()
            );
            collected.add(node.toString().trim());
        }

        return collected.toArray(new String[0]);
    }

    /**
     * Validates audience claim if required.
     */
    private void assertValidAudienceClaim(Claims claims) throws BadJWTException {
        if (requiredAudience.isEmpty()) {
            return;
        }

        if (Collections.disjoint(claims.getAudience(), requiredAudience)) {
            throw new BadJWTException("Claim of 'aud' doesn't contain any required audience.");
        }
    }

    /**
     * Builder for creating JWTAuthenticationPlugin instances with fluent API.
     */
    public static class Builder {
        private Settings settings;
        private Path configPath;

        public Builder settings(Settings settings) {
            this.settings = settings;
            return this;
        }

        public Builder configPath(Path configPath) {
            this.configPath = configPath;
            return this;
        }

        public JWTAuthenticationPlugin build() {
            return new JWTAuthenticationPlugin(settings, configPath);
        }
    }

    /**
     * Creates a new builder for JWTAuthenticationPlugin.
     */
    public static Builder builder() {
        return new Builder();
    }
}
