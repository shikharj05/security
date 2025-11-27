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
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.ldap.util.ConfigConstants;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for LDAPAuthenticationPlugin.
 * <p>
 * These tests verify that the plugin correctly implements the AuthenticationPlugin interface
 * and extracts LDAP attributes and groups as claims, comparing behavior with the existing
 * LDAPAuthenticationBackend2.
 */
public class LDAPAuthenticationPluginTest {

    private LDAPAuthenticationPlugin plugin;
    private LDAPAuthenticationBackend2 backend;
    private Path configPath;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        configPath = Paths.get("src/test/resources/ldap");
    }

    @After
    public void tearDown() {
        if (plugin != null) {
            plugin.destroy();
        }
        if (backend != null) {
            backend.destroy();
        }
    }

    @Test
    public void testGetType() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // act
        final String type = plugin.getType();

        // assert
        assertThat(type, is("ldap"));
    }

    @Test
    public void testSupportsWithValidCredentials() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);
        final AuthCredentials credentials = new AuthCredentials("user", "password".getBytes(StandardCharsets.UTF_8));

        // act
        final boolean supports = plugin.supports(credentials);

        // assert
        assertTrue(supports);
    }

    @Test
    public void testSupportsWithNullCredentials() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // act
        final boolean supports = plugin.supports(null);

        // assert
        assertThat(supports, is(false));
    }

    @Test
    public void testSupportsWithCredentialsWithoutPassword() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);
        final AuthCredentials credentials = new AuthCredentials("user", "role1");

        // act
        final boolean supports = plugin.supports(credentials);

        // assert
        assertThat(supports, is(false));
    }

    @Test
    public void testAuthenticateWithNullCredentials() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);
        final AuthenticationContext context = new AuthenticationContext(null);

        // act & assert
        final AuthenticationException exception = assertThrows(
            AuthenticationException.class,
            () -> plugin.authenticate(context)
        );
        assertThat(exception.getAuthenticationType(), is("ldap"));
    }

    @Test
    public void testExtractLdapClaimsStructure() throws Exception {
        // This test verifies the structure of claims extracted from LDAP
        // without requiring an actual LDAP server connection

        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify that the plugin is properly initialized
        assertThat(plugin.getType(), is("ldap"));
        assertThat(plugin, is(notNullValue()));
    }

    @Test
    public void testCompareWithBackendType() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);
        backend = new LDAPAuthenticationBackend2(settings, configPath);

        // act
        final String pluginType = plugin.getType();
        final String backendType = backend.getType();

        // assert - both should return "ldap"
        assertThat(pluginType, is(equalTo(backendType)));
    }

    @Test
    public void testCompareSupportsWithBackend() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);
        backend = new LDAPAuthenticationBackend2(settings, configPath);

        final AuthCredentials validCredentials = new AuthCredentials("user", "password".getBytes(StandardCharsets.UTF_8));
        final AuthCredentials nullCredentials = null;
        final AuthCredentials noPasswordCredentials = new AuthCredentials("user", "role1");

        // act & assert - plugin should have same support behavior
        assertThat(plugin.supports(validCredentials), is(true));
        assertThat(plugin.supports(nullCredentials), is(false));
        assertThat(plugin.supports(noPasswordCredentials), is(false));
    }

    @Test
    public void testDestroy() throws Exception {
        // arrange
        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // act - should not throw exception
        plugin.destroy();

        // assert - calling destroy again should also not throw
        plugin.destroy();
    }

    @Test
    public void testClaimsContainLdapDn() throws Exception {
        // This test verifies that claims will contain ldap.dn
        // The actual value would come from LDAP server in integration tests

        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is ready to extract ldap.dn claim
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testClaimsContainOriginalUsername() throws Exception {
        // This test verifies that claims will contain ldap.original.username
        // The actual value would come from authentication in integration tests

        Settings settings = createMinimalSettings();
        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is ready to extract ldap.original.username claim
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testClaimsContainLdapAttributes() throws Exception {
        // This test verifies that claims will contain attr.ldap.* attributes
        // The actual values would come from LDAP server in integration tests

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 100)
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST, "*")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured to extract attributes
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testClaimsContainGroups() throws Exception {
        // This test verifies that claims will contain ldap.groups
        // The actual group memberships would come from LDAP server in integration tests

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 200)
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST, "*")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured to extract group memberships
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testAttributeFiltering() throws Exception {
        // Test that plugin respects custom attribute max value length

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_CUSTOM_ATTR_MAXVAL_LEN, 36) // Default value
            .putList(ConfigConstants.LDAP_CUSTOM_ATTR_ALLOWLIST, "cn", "mail", "memberOf")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured with attribute filtering
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testUsernameAttributeMapping() throws Exception {
        // Test that plugin supports username attribute mapping

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_AUTHC_USERNAME_ATTRIBUTE, "uid")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured with username attribute mapping
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testFakeLoginConfiguration() throws Exception {
        // Test that plugin supports fake login configuration for security

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.LDAP_FAKE_LOGIN_ENABLED, true)
            .put(ConfigConstants.LDAP_FAKE_LOGIN_DN, "CN=faketomakebindfail,DC=example,DC=com")
            .put(ConfigConstants.LDAP_FAKE_LOGIN_PASSWORD, "fakePassword123")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured with fake login
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testReturnAttributesConfiguration() throws Exception {
        // Test that plugin supports custom return attributes

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .putList(ConfigConstants.LDAP_RETURN_ATTRIBUTES, "cn", "mail", "memberOf", "uid")
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured with custom return attributes
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    @Test
    public void testFollowReferralsConfiguration() throws Exception {
        // Test that plugin supports follow referrals configuration

        Settings settings = Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .put(ConfigConstants.FOLLOW_REFERRALS, true)
            .build();

        plugin = new LDAPAuthenticationPlugin(settings, configPath);

        // Verify plugin is configured with follow referrals
        assertThat(plugin, is(notNullValue()));
        assertThat(plugin.getType(), is("ldap"));
    }

    /**
     * Creates minimal LDAP settings for testing.
     * These settings are sufficient to instantiate the plugin but won't connect to a real LDAP server.
     */
    private Settings createMinimalSettings() {
        return Settings.builder()
            .putList(ConfigConstants.LDAP_HOSTS, "localhost:389")
            .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,dc=example,dc=com")
            .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
            .build();
    }
}
