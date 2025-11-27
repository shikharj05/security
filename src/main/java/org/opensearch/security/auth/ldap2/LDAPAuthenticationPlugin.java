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

package org.opensearch.security.auth.ldap2;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.Destroyable;
import org.opensearch.security.auth.ldap.backend.LDAPAuthenticationBackend;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.ldap.util.Utils;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.security.util.SettingsBasedSSLConfigurator.SSLConfigException;

import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.pool.ConnectionPool;

/**
 * Authentication plugin for LDAP authentication.
 * <p>
 * This plugin authenticates users against an LDAP directory server. It verifies
 * credentials by binding to the LDAP server and extracts LDAP attributes and groups
 * as claims in the UserPrincipal.
 * <p>
 * This implementation is based on {@code LDAPAuthenticationBackend2} but follows
 * the new plugin architecture that separates authentication from authorization.
 *
 * @see LDAPAuthenticationBackend2
 */
public class LDAPAuthenticationPlugin implements AuthenticationPlugin, Destroyable {

    protected static final Logger log = LogManager.getLogger(LDAPAuthenticationPlugin.class);

    private final Settings settings;
    private ConnectionPool connectionPool;
    private ConnectionFactory connectionFactory;
    private ConnectionFactory authConnectionFactory;
    private LDAPUserSearcher userSearcher;
    private final int customAttrMaxValueLen;
    private final WildcardMatcher allowlistedCustomLdapAttrMatcher;
    private final String[] returnAttributes;
    private final boolean shouldFollowReferrals;

    /**
     * Creates a new LDAP authentication plugin.
     *
     * @param settings The settings for LDAP configuration
     * @param configPath The path to the configuration directory
     * @throws SSLConfigException if SSL configuration is invalid
     */
    public LDAPAuthenticationPlugin(final Settings settings, final Path configPath) throws SSLConfigException {
        this.settings = settings;

        LDAPConnectionFactoryFactory ldapConnectionFactoryFactory = new LDAPConnectionFactoryFactory(settings, configPath);

        this.connectionPool = ldapConnectionFactoryFactory.createConnectionPool();
        this.connectionFactory = ldapConnectionFactoryFactory.createConnectionFactory(this.connectionPool);

        if (this.connectionPool != null) {
            this.authConnectionFactory = ldapConnectionFactoryFactory.createBasicConnectionFactory();
        } else {
            this.authConnectionFactory = this.connectionFactory;
        }

        this.userSearcher = new LDAPUserSearcher(settings);
        this.returnAttributes = settings.getAsList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, Arrays.asList(ReturnAttributes.ALL.value()))
            .toArray(new String[0]);
        this.shouldFollowReferrals = settings.getAsBoolean(ConfigConstants.FOLLOW_REFERRALS, ConfigConstants.FOLLOW_REFERRALS_DEFAULT);
        customAttrMaxValueLen = settings.getAsInt(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36);
        allowlistedCustomLdapAttrMatcher = WildcardMatcher.from(
            settings.getAsList(ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST, Collections.singletonList("*"))
        );
    }

    @Override
    public String getType() {
        return "ldap";
    }

    @Override
    public boolean supports(AuthCredentials credentials) {
        // LDAP authentication supports username/password credentials
        return credentials != null && credentials.getUsername() != null && credentials.getPassword() != null;
    }

    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        try {
            return AccessController.doPrivilegedChecked(() -> authenticate0(context));
        } catch (Exception e) {
            if (e instanceof AuthenticationException) {
                throw (AuthenticationException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new AuthenticationException(getType(), e.getMessage(), e);
            }
        }
    }

    private UserPrincipal authenticate0(AuthenticationContext context) throws AuthenticationException {
        if (context.getCredentials() == null || context.getCredentials().getUsername() == null) {
            throw new AuthenticationException(getType(), "Credentials or username is null");
        }

        Connection ldapConnection = null;
        final String user = context.getCredentials().getUsername();
        byte[] password = context.getCredentials().getPassword();

        try {
            ldapConnection = connectionFactory.getConnection();
            ldapConnection.open();

            LdapEntry entry = userSearcher.exists(ldapConnection, user, this.returnAttributes, this.shouldFollowReferrals);

            // fake a user that no exists
            // makes guessing if a user exists or not harder when looking on the
            // authentication delay time
            if (entry == null && settings.getAsBoolean(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, false)) {
                String fakeLognDn = settings.get(
                    ConfigConstants.LDAP_FAKE_LOGIN_DN,
                    "CN=faketomakebindfail,DC=" + UUID.randomUUID().toString()
                );
                entry = new LdapEntry(fakeLognDn);
                password = settings.get(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakeLoginPwd123").getBytes(StandardCharsets.UTF_8);
            } else if (entry == null) {
                throw new AuthenticationException(getType(), "No user " + user + " found");
            }

            final String dn = entry.getDn();

            if (log.isTraceEnabled()) {
                log.trace("Try to authenticate dn {}", dn);
            }

            if (this.connectionPool == null) {
                authenticateByLdapServer(ldapConnection, dn, password);
            } else {
                authenticateByLdapServerWithSeparateConnection(dn, password);
            }

            final String usernameAttribute = settings.get(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.getAttribute(usernameAttribute) != null) {
                username = Utils.getSingleStringValue(entry.getAttribute(usernameAttribute));
            }

            if (log.isDebugEnabled()) {
                log.debug("Authenticated username {}", username);
            }

            // Make LdapEntry available to authz backends by adding it to the AuthenticationContext
            context.addContextData(LdapEntry.class, entry);

            // Extract LDAP attributes and groups as claims
            Map<String, Object> claims = extractLdapClaims(user, entry);

            // Add attributes from credentials if present
            if (context.getCredentials().getAttributes() != null && !context.getCredentials().getAttributes().isEmpty()) {
                claims.putAll(context.getCredentials().getAttributes());
            }

            // Return UserPrincipal with identity and claims
            return UserPrincipal.builder(username)
                .claims(claims)
                .authenticationType(getType())
                .authenticationTime(System.currentTimeMillis())
                .build();

        } catch (final Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to authenticate user due to ", e);
            }
            if (e instanceof AuthenticationException) {
                throw (AuthenticationException) e;
            }
            throw new AuthenticationException(getType(), e.getMessage(), e);
        } finally {
            Arrays.fill(password, (byte) '\0');
            password = null;
            Utils.unbindAndCloseSilently(ldapConnection);
        }
    }

    /**
     * Extracts LDAP attributes and groups as claims from an LDAP entry.
     * <p>
     * This method extracts:
     * <ul>
     *     <li>ldap.dn - The distinguished name of the user</li>
     *     <li>ldap.original.username - The original username used for authentication</li>
     *     <li>attr.ldap.* - LDAP attributes that match the allowlist and size constraints</li>
     * </ul>
     *
     * @param originalUsername The original username used for authentication
     * @param userEntry The LDAP entry for the user
     * @return Map of claims extracted from LDAP
     */
    private Map<String, Object> extractLdapClaims(String originalUsername, LdapEntry userEntry) {
        Map<String, Object> claims = new HashMap<>();

        // Add DN and original username
        claims.put("ldap.dn", userEntry.getDn());
        claims.put("ldap.original.username", originalUsername);

        // Extract LDAP attributes
        if (customAttrMaxValueLen > 0) {
            List<String> groups = new ArrayList<>();

            for (LdapAttribute attr : userEntry.getAttributes()) {
                if (attr != null && !attr.isBinary() && !attr.getName().toLowerCase().contains("password")) {
                    final String val = Utils.getSingleStringValue(attr);

                    // only consider attributes which are not binary and where its value is not
                    // longer than customAttrMaxValueLen characters
                    if (val != null && !val.isEmpty() && val.length() <= customAttrMaxValueLen) {
                        if (allowlistedCustomLdapAttrMatcher.test(attr.getName())) {
                            // Store as claim with attr.ldap prefix
                            claims.put("attr.ldap." + attr.getName(), val);

                            // Collect group memberships
                            if (attr.getName().equalsIgnoreCase("memberOf") || attr.getName().equalsIgnoreCase("member")) {
                                groups.add(val);
                            }
                        }
                    }
                }
            }

            // Add groups as a separate claim if any were found
            if (!groups.isEmpty()) {
                claims.put("ldap.groups", groups);
            }
        }

        return claims;
    }

    private void authenticateByLdapServer(final Connection connection, final String dn, byte[] password) throws LdapException {
        try {
            AccessController.doPrivilegedChecked(
                () -> connection.getProviderConnection().bind(new BindRequest(dn, new Credential(password)))
            );
        } catch (Exception e) {
            if (e instanceof LdapException) {
                throw (LdapException) e;
            } else if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private void authenticateByLdapServerWithSeparateConnection(final String dn, byte[] password) throws LdapException {
        try (Connection unpooledConnection = this.authConnectionFactory.getConnection()) {
            unpooledConnection.open();
            authenticateByLdapServer(unpooledConnection, dn, password);
        }
    }

    @Override
    public void destroy() {
        if (this.connectionPool != null) {
            this.connectionPool.close();
            this.connectionPool = null;
        }
    }
}
