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

package org.opensearch.security.auth.plugin.kerberos;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.http.kerberos.util.JaasKrbUtil;
import org.opensearch.security.auth.http.kerberos.util.KrbConstants;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;

/**
 * Authentication plugin for Kerberos/SPNEGO-based authentication.
 * <p>
 * This plugin processes Kerberos-authenticated credentials and extracts
 * user information as claims in the UserPrincipal.
 * <p>
 * Note: Kerberos ticket validation is handled by the HTTP layer
 * ({@code HTTPSpnegoAuthenticator}). This plugin processes the already-validated
 * credentials and extracts claims for authorization.
 * <p>
 * This implementation follows the new plugin architecture that separates
 * authentication from authorization.
 *
 * @see org.opensearch.security.auth.http.kerberos.HTTPSpnegoAuthenticator
 */
public class KerberosAuthenticationPlugin implements AuthenticationPlugin {

    protected final Logger log = LogManager.getLogger(this.getClass());

    private boolean stripRealmFromPrincipalName;
    private Set<String> acceptorPrincipal;
    private Path acceptorKeyTabPath;

    /**
     * Creates a new Kerberos authentication plugin.
     *
     * @param settings Configuration settings for Kerberos authentication
     * @param configPath Path to configuration directory
     */
    public KerberosAuthenticationPlugin(final Settings settings, final Path configPath) {
        super();
        try {
            final Path configDir = new Environment(settings, configPath).configDir();
            final String krb5PathSetting = settings.get("plugins.security.kerberos.krb5_filepath");

            AccessController.doPrivileged(() -> {

                try {
                    if (settings.getAsBoolean("krb_debug", false)) {
                        JaasKrbUtil.setDebug(true);
                        System.setProperty("sun.security.krb5.debug", "true");
                        System.setProperty("java.security.debug", "gssloginconfig,logincontext,configparser,configfile");
                        System.setProperty("sun.security.spnego.debug", "true");
                        log.info("Kerberos debug is enabled on stdout");
                    } else {
                        log.debug("Kerberos debug is NOT enabled");
                    }
                } catch (Throwable e) {
                    log.error("Unable to enable krb_debug due to ", e);
                    log.debug("Unable to enable krb_debug due to " + ExceptionsHelper.stackTrace(e));
                }

                System.setProperty(KrbConstants.USE_SUBJECT_CREDS_ONLY_PROP, "false");

                String krb5Path = krb5PathSetting;

                if (!Strings.isNullOrEmpty(krb5Path)) {
                    if (Paths.get(krb5Path).isAbsolute()) {
                        log.debug("krb5_filepath: {}", krb5Path);
                        System.setProperty(KrbConstants.KRB5_CONF_PROP, krb5Path);
                    } else {
                        krb5Path = configDir.resolve(krb5Path).toAbsolutePath().toString();
                        log.debug("krb5_filepath (resolved from {}): {}", configDir, krb5Path);
                    }

                    System.setProperty(KrbConstants.KRB5_CONF_PROP, krb5Path);
                } else {
                    if (Strings.isNullOrEmpty(System.getProperty(KrbConstants.KRB5_CONF_PROP))) {
                        System.setProperty(KrbConstants.KRB5_CONF_PROP, "/etc/krb5.conf");
                        log.debug("krb5_filepath (was not set or configured, set to default): /etc/krb5.conf");
                    }
                }

                stripRealmFromPrincipalName = settings.getAsBoolean("strip_realm_from_principal", true);
                acceptorPrincipal = new HashSet<>(
                    settings.getAsList("plugins.security.kerberos.acceptor_principal", Collections.emptyList())
                );
                final String _acceptorKeyTabPath = settings.get("plugins.security.kerberos.acceptor_keytab_filepath");

                if (acceptorPrincipal == null || acceptorPrincipal.size() == 0) {
                    log.error("acceptor_principal must not be null or empty. Kerberos authentication will not work");
                    acceptorPrincipal = null;
                }

                if (_acceptorKeyTabPath == null || _acceptorKeyTabPath.length() == 0) {
                    log.error(
                        "plugins.security.kerberos.acceptor_keytab_filepath must not be null or empty. Kerberos authentication will not work"
                    );
                    acceptorKeyTabPath = null;
                } else {
                    acceptorKeyTabPath = configDir.resolve(settings.get("plugins.security.kerberos.acceptor_keytab_filepath"));

                    if (!Files.exists(acceptorKeyTabPath)) {
                        log.error(
                            "Unable to read keytab from {} - Maybe the file does not exist or is not readable. Kerberos authentication will not work",
                            acceptorKeyTabPath
                        );
                        acceptorKeyTabPath = null;
                    }
                }

                return null;
            });

            log.debug("strip_realm_from_principal {}", stripRealmFromPrincipalName);
            log.debug("acceptor_principal {}", acceptorPrincipal);
            log.debug("acceptor_keytab_filepath {}", acceptorKeyTabPath);

        } catch (Throwable e) {
            log.error("Cannot construct KerberosAuthenticationPlugin due to {}", e.getMessage(), e);
            log.error(
                "Please make sure you configured 'plugins.security.kerberos.acceptor_keytab_filepath' relative to the ES config/ dir!"
            );
            throw e;
        }
    }

    @Override
    public String getType() {
        return "spnego";
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // Kerberos authentication is handled through HTTP authenticators
        // This plugin processes Kerberos tickets that have already been validated
        return credentials != null && credentials.getUsername() != null;
    }

    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        AuthCredentials credentials = context.getCredentials();

        if (credentials == null || credentials.getUsername() == null) {
            throw new AuthenticationException(getType(), "Credentials or username is null");
        }

        if (acceptorPrincipal == null || acceptorKeyTabPath == null) {
            log.error("Missing acceptor principal or keytab configuration. Kerberos authentication will not work");
            throw new AuthenticationException(getType(), "Kerberos configuration is incomplete");
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

            // Add all attributes from credentials with kerberos.attr prefix
            if (credentials.getAttributes() != null && !credentials.getAttributes().isEmpty()) {
                for (Map.Entry<String, String> entry : credentials.getAttributes().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();

                    // Store with kerberos.attr prefix
                    claims.put("kerberos.attr." + key, value);
                }
            }

            // Add Kerberos-specific metadata
            claims.put("kerberos.strip_realm", stripRealmFromPrincipalName);
            claims.put("kerberos.acceptor_principal", new ArrayList<>(acceptorPrincipal));

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
            log.error("Error extracting claims from Kerberos credentials", e);
            throw new AuthenticationException(getType(), "Error processing Kerberos credentials: " + e.getMessage());
        }
    }

    /**
     * Builder for creating KerberosAuthenticationPlugin instances with fluent API.
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

        public KerberosAuthenticationPlugin build() {
            return new KerberosAuthenticationPlugin(settings, configPath);
        }
    }

    /**
     * Creates a new builder for KerberosAuthenticationPlugin.
     */
    public static Builder builder() {
        return new Builder();
    }
}
