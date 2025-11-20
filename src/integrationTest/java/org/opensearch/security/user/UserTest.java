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
package org.opensearch.security.user;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import org.opensearch.security.support.Base64Helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class UserTest {
    @Test
    public void serialization() {
        User user = new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
            .withSecurityRoles(Arrays.asList("sr1", "sr2"))
            .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));

        String serialized = Base64Helper.serializeObject(user);
        User user2 = User.fromSerializedBase64(serialized);
        assertEquals(user, user2);

    }

    @Test
    public void deserializationFrom2_19() {
        // The following base64 string was produced by the following code on OpenSearch 2.19
        // User user = new User("serialization_test_user");
        // user.addRoles(Arrays.asList("br1", "br2", "br3"));
        // user.addSecurityRoles(Arrays.asList("sr1", "sr2"));
        // user.addAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));
        // println(Base64JDKHelper.serializeObject(user));
        String serialized =
            "rO0ABXNyACFvcmcub3BlbnNlYXJjaC5zZWN1cml0eS51c2VyLlVzZXKzqL2T65dH3AIABloACmlzSW5qZWN0ZWRMAAphdHRyaWJ1dGVzdAAPTGphdmEvdXRpbC9NYXA7TAAEbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAD3JlcXVlc3RlZFRlbmFudHEAfgACTAAFcm9sZXN0AA9MamF2YS91dGlsL1NldDtMAA1zZWN1cml0eVJvbGVzcQB+AAN4cABzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZE1hcBtz+QlLSzl7AwACTAABbXEAfgABTAAFbXV0ZXh0ABJMamF2YS9sYW5nL09iamVjdDt4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAN3CAAAAAQAAAACdAABYXQAA3ZfYXQAAWJ0AAN2X2J4cQB+AAd4dAAXc2VyaWFsaXphdGlvbl90ZXN0X3VzZXJwc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRTZXQGw8J5Au7fPAIAAHhyACxqYXZhLnV0aWwuQ29sbGVjdGlvbnMkU3luY2hyb25pemVkQ29sbGVjdGlvbiph+E0JnJm1AwACTAABY3QAFkxqYXZhL3V0aWwvQ29sbGVjdGlvbjtMAAVtdXRleHEAfgAGeHBzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAN0AANicjF0AANicjN0AANicjJ4cQB+ABJ4c3EAfgAPc3EAfgATdwwAAAAQP0AAAAAAAAJ0AANzcjJ0AANzcjF4cQB+ABh4";

        User user = User.fromSerializedBase64(serialized);
        assertEquals(
            new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
                .withSecurityRoles(Arrays.asList("sr1", "sr2"))
                .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b")),
            user
        );
    }

    @Test
    public void deserializationLdapUserFrom2_19() {
        // The following base64 string was produced by the following code on OpenSearch 2.19
        // LdapUser user = new LdapUser("serialization_test_user",
        // "original_user_name",
        // new LdapEntry("cn=test,ou=people,o=TEST", new LdapAttribute("test_ldap_attr", "test_ldap_attr_value")),
        // new AuthCredentials("test_user", "secret".getBytes(StandardCharsets.UTF_8)),
        // 100,
        // WildcardMatcher.ANY);
        // user.addRoles(Arrays.asList("br1", "br2", "br3"));
        // user.addSecurityRoles(Arrays.asList("sr1", "sr2"));
        // user.addAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));
        // println(Base64JDKHelper.serializeObject(user));
        String serialized =
            "rO0ABXNyACJjb20uYW1hem9uLmRsaWMuYXV0aC5sZGFwLkxkYXBVc2VyAAAAAAAAAAECAAFMABBvcmlnaW5hbFVzZXJuYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7eHIAIW9yZy5vcGVuc2VhcmNoLnNlY3VyaXR5LnVzZXIuVXNlcrOovZPrl0fcAgAGWgAKaXNJbmplY3RlZEwACmF0dHJpYnV0ZXN0AA9MamF2YS91dGlsL01hcDtMAARuYW1lcQB+AAFMAA9yZXF1ZXN0ZWRUZW5hbnRxAH4AAUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAANc2VjdXJpdHlSb2xlc3EAfgAEeHAAc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRNYXAbc/kJS0s5ewMAAkwAAW1xAH4AA0wABW11dGV4dAASTGphdmEvbGFuZy9PYmplY3Q7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAGdwgAAAAIAAAABXQAB2xkYXAuZG50ABhjbj10ZXN0LG91PXBlb3BsZSxvPVRFU1R0AAFhdAADdl9hdAAYYXR0ci5sZGFwLnRlc3RfbGRhcF9hdHRydAAUdGVzdF9sZGFwX2F0dHJfdmFsdWV0AAFidAADdl9idAAWbGRhcC5vcmlnaW5hbC51c2VybmFtZXQAEm9yaWdpbmFsX3VzZXJfbmFtZXhxAH4ACHh0ABdzZXJpYWxpemF0aW9uX3Rlc3RfdXNlcnBzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZFNldAbDwnkC7t88AgAAeHIALGphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRDb2xsZWN0aW9uKmH4TQmcmbUDAAJMAAFjdAAWTGphdmEvdXRpbC9Db2xsZWN0aW9uO0wABW11dGV4cQB+AAd4cHNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAABA/QAAAAAAAA3QAA2JyMXQAA2JyM3QAA2JyMnhxAH4AGXhzcQB+ABZzcQB+ABp3DAAAABA/QAAAAAAAAnQAA3NyMnQAA3NyMXhxAH4AH3hxAH4AFA==";

        User user = User.fromSerializedBase64(serialized);
        assertEquals(
            new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
                .withSecurityRoles(Arrays.asList("sr1", "sr2"))
                .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b")),
            user
        );
    }

    @Test
    public void withRoles() {
        User original = new User("test_user").withRoles("a");
        User modified = original.withRoles("b");

        assertEquals(ImmutableSet.of("a"), original.getRoles());
        assertEquals(ImmutableSet.of("a", "b"), modified.getRoles());
    }

    @Test
    public void withRoles_unmodified() {
        User original = new User("test_user").withRoles("a");
        User unmodified = original.withRoles(ImmutableSet.of());

        assertSame(original, unmodified);
    }

    @Test
    public void withAttributes() {
        User original = new User("test_user").withAttributes(Map.of("a", "1"));
        User modified = original.withAttributes(Map.of("b", "2"));

        assertEquals(ImmutableMap.of("a", "1"), original.getCustomAttributesMap());
        assertEquals(ImmutableMap.of("a", "1", "b", "2"), modified.getCustomAttributesMap());
    }

    @Test
    public void withAttributes_unmodified() {
        User original = new User("test_user").withAttributes(Map.of("a", "1"));
        User unmodified = original.withAttributes(Map.of());

        assertSame(original, unmodified);
    }

    @Test
    public void withRequestedTenant() {
        User original = new User("test_user").withRequestedTenant("a");
        User modified = original.withRequestedTenant("b");

        assertEquals("a", original.getRequestedTenant());
        assertEquals("b", modified.getRequestedTenant());
    }

    @Test
    public void withRequestedTenant_unmodified() {
        User original = new User("test_user").withRequestedTenant("a");
        User unmodified = original.withRequestedTenant("a");

        assertSame(original, unmodified);
    }

    @Test(expected = IllegalArgumentException.class)
    public void illegalName() {
        new User("");
    }

    @Test
    public void toPrincipal() {
        User user = new User("test_user").withRoles(Arrays.asList("role1", "role2"))
            .withAttributes(ImmutableMap.of("email", "test@example.com", "department", "Engineering"));

        UserPrincipal principal = user.toPrincipal();

        assertEquals("test_user", principal.getName());
        assertEquals("legacy", principal.getAuthenticationType());

        // Verify backend roles are in claims
        Object backendRoles = principal.getClaims().get("backend_roles");
        assertEquals(Arrays.asList("role1", "role2"), backendRoles);

        // Verify attributes are in claims
        assertEquals("test@example.com", principal.getClaims().get("email"));
        assertEquals("Engineering", principal.getClaims().get("department"));
    }

    @Test
    public void toPrincipal_emptyRolesAndAttributes() {
        User user = new User("test_user");

        UserPrincipal principal = user.toPrincipal();

        assertEquals("test_user", principal.getName());
        assertEquals("legacy", principal.getAuthenticationType());
        // Should not have backend_roles claim if no roles
        assertEquals(null, principal.getClaims().get("backend_roles"));
    }

    @Test
    public void fromPrincipal_withBackendRoles() {
        UserPrincipal principal = UserPrincipal.builder("test_user")
            .claim("backend_roles", Arrays.asList("role1", "role2"))
            .claim("email", "test@example.com")
            .authenticationType("internal")
            .build();

        User user = User.fromPrincipal(principal, ImmutableSet.of("security_role1", "security_role2"));

        assertEquals("test_user", user.getName());
        assertEquals(ImmutableSet.of("role1", "role2"), user.getRoles());
        assertEquals(ImmutableSet.of("security_role1", "security_role2"), user.getSecurityRoles());
        assertEquals("test@example.com", user.getCustomAttributesMap().get("email"));
    }

    @Test
    public void fromPrincipal_withGroupsClaim() {
        UserPrincipal principal = UserPrincipal.builder("test_user")
            .claim("groups", Arrays.asList("group1", "group2"))
            .claim("email", "test@example.com")
            .authenticationType("ldap")
            .build();

        User user = User.fromPrincipal(principal, ImmutableSet.of("security_role1"));

        assertEquals("test_user", user.getName());
        assertEquals(ImmutableSet.of("group1", "group2"), user.getRoles());
        assertEquals(ImmutableSet.of("security_role1"), user.getSecurityRoles());
    }

    @Test
    public void fromPrincipal_withRolesClaim() {
        UserPrincipal principal = UserPrincipal.builder("test_user")
            .claim("roles", Arrays.asList("jwt_role1", "jwt_role2"))
            .authenticationType("jwt")
            .build();

        User user = User.fromPrincipal(principal, ImmutableSet.of());

        assertEquals("test_user", user.getName());
        assertEquals(ImmutableSet.of("jwt_role1", "jwt_role2"), user.getRoles());
    }

    @Test
    public void fromPrincipal_withNullSecurityRoles() {
        UserPrincipal principal = UserPrincipal.builder("test_user")
            .claim("backend_roles", Arrays.asList("role1"))
            .build();

        User user = User.fromPrincipal(principal, null);

        assertEquals("test_user", user.getName());
        assertEquals(ImmutableSet.of("role1"), user.getRoles());
        assertEquals(ImmutableSet.of(), user.getSecurityRoles());
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromPrincipal_nullPrincipal() {
        User.fromPrincipal(null, ImmutableSet.of());
    }

    @Test
    public void roundTripConversion() {
        // Create a User
        User originalUser = new User("test_user").withRoles(Arrays.asList("role1", "role2"))
            .withSecurityRoles(Arrays.asList("sec_role1", "sec_role2"))
            .withAttributes(ImmutableMap.of("email", "test@example.com", "department", "Engineering"));

        // Convert to UserPrincipal
        UserPrincipal principal = originalUser.toPrincipal();

        // Convert back to User
        User convertedUser = User.fromPrincipal(principal, originalUser.getSecurityRoles());

        // Verify key properties are preserved
        assertEquals(originalUser.getName(), convertedUser.getName());
        assertEquals(originalUser.getRoles(), convertedUser.getRoles());
        assertEquals(originalUser.getSecurityRoles(), convertedUser.getSecurityRoles());
        assertEquals(originalUser.getCustomAttributesMap(), convertedUser.getCustomAttributesMap());
    }

    @Test
    public void serializationUnchangedAfterAddingConversionMethods() {
        // Create a user with the same properties as in the serialization test
        User user = new User("serialization_test_user").withRoles(Arrays.asList("br1", "br2", "br3"))
            .withSecurityRoles(Arrays.asList("sr1", "sr2"))
            .withAttributes(ImmutableMap.of("a", "v_a", "b", "v_b"));

        // Serialize the user
        String serialized = Base64Helper.serializeObject(user);

        // Deserialize it
        User deserialized = User.fromSerializedBase64(serialized);

        // Verify it matches the original
        assertEquals(user, deserialized);
        assertEquals(user.getRoles(), deserialized.getRoles());
        assertEquals(user.getSecurityRoles(), deserialized.getSecurityRoles());
        assertEquals(user.getCustomAttributesMap(), deserialized.getCustomAttributesMap());
    }

    @Test
    public void serializationFormatUnchanged() {
        // This test verifies that the serialization format has not changed
        // by deserializing a known serialized string from before the conversion methods were added
        // This is the same serialized string used in deserializationFrom2_19 test
        String serializedFrom2_19 =
            "rO0ABXNyACFvcmcub3BlbnNlYXJjaC5zZWN1cml0eS51c2VyLlVzZXKzqL2T65dH3AIABloACmlzSW5qZWN0ZWRMAAphdHRyaWJ1dGVzdAAPTGphdmEvdXRpbC9NYXA7TAAEbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAD3JlcXVlc3RlZFRlbmFudHEAfgACTAAFcm9sZXN0AA9MamF2YS91dGlsL1NldDtMAA1zZWN1cml0eVJvbGVzcQB+AAN4cABzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZE1hcBtz+QlLSzl7AwACTAABbXEAfgABTAAFbXV0ZXh0ABJMamF2YS9sYW5nL09iamVjdDt4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAN3CAAAAAQAAAACdAABYXQAA3ZfYXQAAWJ0AAN2X2J4cQB+AAd4dAAXc2VyaWFsaXphdGlvbl90ZXN0X3VzZXJwc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRTZXQGw8J5Au7fPAIAAHhyACxqYXZhLnV0aWwuQ29sbGVjdGlvbnMkU3luY2hyb25pemVkQ29sbGVjdGlvbiph+E0JnJm1AwACTAABY3QAFkxqYXZhL3V0aWwvQ29sbGVjdGlvbjtMAAVtdXRleHEAfgAGeHBzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAN0AANicjF0AANicjN0AANicjJ4cQB+ABJ4c3EAfgAPc3EAfgATdwwAAAAQP0AAAAAAAAJ0AANzcjJ0AANzcjF4cQB+ABh4";

        User user = User.fromSerializedBase64(serializedFrom2_19);

        // Verify the user was deserialized correctly
        assertEquals("serialization_test_user", user.getName());
        assertEquals(ImmutableSet.of("br1", "br2", "br3"), user.getRoles());
        assertEquals(ImmutableSet.of("sr1", "sr2"), user.getSecurityRoles());
        assertEquals(ImmutableMap.of("a", "v_a", "b", "v_b"), user.getCustomAttributesMap());

        // Now serialize it again and verify it can be deserialized
        String reSerialized = Base64Helper.serializeObject(user);
        User reDeserialized = User.fromSerializedBase64(reSerialized);

        assertEquals(user, reDeserialized);
    }

    @Test
    public void mixedVersionClusterScenario_newNodeToOldNode() {
        // Simulate a new node (with UserPrincipal support) sending a User to an old node
        // The new node creates a UserPrincipal internally, then converts to User for serialization

        // Step 1: New node creates UserPrincipal from authentication
        UserPrincipal principal = UserPrincipal.builder("mixed_version_user")
            .claim("backend_roles", Arrays.asList("role1", "role2"))
            .claim("email", "user@example.com")
            .claim("department", "Engineering")
            .authenticationType("ldap")
            .build();

        // Step 2: New node converts UserPrincipal to User for inter-node communication
        User userForWire = User.fromPrincipal(principal, ImmutableSet.of("sec_role1", "sec_role2"));

        // Step 3: Serialize User (simulating sending over wire)
        String serialized = Base64Helper.serializeObject(userForWire);

        // Step 4: Old node deserializes User (should work without any knowledge of UserPrincipal)
        User receivedByOldNode = User.fromSerializedBase64(serialized);

        // Verify old node can process the User correctly
        assertEquals("mixed_version_user", receivedByOldNode.getName());
        assertEquals(ImmutableSet.of("role1", "role2"), receivedByOldNode.getRoles());
        assertEquals(ImmutableSet.of("sec_role1", "sec_role2"), receivedByOldNode.getSecurityRoles());
        assertEquals("user@example.com", receivedByOldNode.getCustomAttributesMap().get("email"));
        assertEquals("Engineering", receivedByOldNode.getCustomAttributesMap().get("department"));
    }

    @Test
    public void mixedVersionClusterScenario_oldNodeToNewNode() {
        // Simulate an old node (without UserPrincipal support) sending a User to a new node

        // Step 1: Old node creates User using traditional methods
        User userFromOldNode = new User("old_node_user").withRoles(Arrays.asList("old_role1", "old_role2"))
            .withSecurityRoles(Arrays.asList("old_sec_role1"))
            .withAttributes(ImmutableMap.of("legacy_attr", "legacy_value"));

        // Step 2: Serialize User (simulating sending over wire)
        String serialized = Base64Helper.serializeObject(userFromOldNode);

        // Step 3: New node deserializes User
        User receivedByNewNode = User.fromSerializedBase64(serialized);

        // Step 4: New node converts User to UserPrincipal for internal processing
        UserPrincipal principal = receivedByNewNode.toPrincipal();

        // Verify new node can process the User correctly
        assertEquals("old_node_user", principal.getName());
        assertEquals("legacy", principal.getAuthenticationType());

        // Verify backend roles are in claims (order may vary, so compare as sets)
        Object backendRoles = principal.getClaims().get("backend_roles");
        assertEquals(ImmutableSet.copyOf(Arrays.asList("old_role1", "old_role2")), ImmutableSet.copyOf((Iterable<?>) backendRoles));

        // Verify attributes are in claims
        assertEquals("legacy_value", principal.getClaims().get("legacy_attr"));

        // Step 5: New node can convert back to User for further wire communication
        User userForNextHop = User.fromPrincipal(principal, receivedByNewNode.getSecurityRoles());
        assertEquals(userFromOldNode.getName(), userForNextHop.getName());
        assertEquals(userFromOldNode.getRoles(), userForNextHop.getRoles());
        assertEquals(userFromOldNode.getSecurityRoles(), userForNextHop.getSecurityRoles());
    }

    @Test
    public void mixedVersionClusterScenario_roundTripThroughMultipleNodes() {
        // Simulate a User traveling through a mixed-version cluster:
        // New Node A -> Old Node B -> New Node C

        // Node A (new): Creates UserPrincipal and converts to User
        UserPrincipal originalPrincipal = UserPrincipal.builder("cluster_user")
            .claim("backend_roles", Arrays.asList("cluster_role1", "cluster_role2"))
            .claim("email", "cluster@example.com")
            .authenticationType("saml")
            .build();

        User userFromNodeA = User.fromPrincipal(originalPrincipal, ImmutableSet.of("sec_role1"));

        // Node A -> Node B: Serialize and send
        String serializedAtoB = Base64Helper.serializeObject(userFromNodeA);
        User userAtNodeB = User.fromSerializedBase64(serializedAtoB);

        // Node B (old): Processes User normally, then forwards
        // Old node doesn't know about UserPrincipal, just works with User
        String serializedBtoC = Base64Helper.serializeObject(userAtNodeB);

        // Node C (new): Receives User and converts to UserPrincipal
        User userAtNodeC = User.fromSerializedBase64(serializedBtoC);
        UserPrincipal principalAtNodeC = userAtNodeC.toPrincipal();

        // Verify data integrity through the entire journey (order may vary, so compare as sets)
        assertEquals("cluster_user", principalAtNodeC.getName());
        assertEquals(
            ImmutableSet.copyOf(Arrays.asList("cluster_role1", "cluster_role2")),
            ImmutableSet.copyOf((Iterable<?>) principalAtNodeC.getClaims().get("backend_roles"))
        );
        assertEquals("cluster@example.com", principalAtNodeC.getClaims().get("email"));

        // Verify User properties are preserved
        assertEquals(userFromNodeA.getName(), userAtNodeC.getName());
        assertEquals(userFromNodeA.getRoles(), userAtNodeC.getRoles());
        assertEquals(userFromNodeA.getSecurityRoles(), userAtNodeC.getSecurityRoles());
    }

    @Test
    public void wireProtocolCompatibility_userWithAllFields() {
        // Test that User objects with all fields populated serialize/deserialize correctly
        User fullUser = new User("wire_test_user").withRoles(Arrays.asList("wr1", "wr2", "wr3"))
            .withSecurityRoles(Arrays.asList("wsr1", "wsr2"))
            .withAttributes(ImmutableMap.of("attr1", "value1", "attr2", "value2", "attr3", "value3"))
            .withRequestedTenant("test_tenant");

        // Serialize
        String serialized = Base64Helper.serializeObject(fullUser);

        // Deserialize
        User deserialized = User.fromSerializedBase64(serialized);

        // Verify all fields are preserved
        assertEquals(fullUser.getName(), deserialized.getName());
        assertEquals(fullUser.getRoles(), deserialized.getRoles());
        assertEquals(fullUser.getSecurityRoles(), deserialized.getSecurityRoles());
        assertEquals(fullUser.getCustomAttributesMap(), deserialized.getCustomAttributesMap());
        assertEquals(fullUser.getRequestedTenant(), deserialized.getRequestedTenant());
        assertEquals(fullUser.isInjected(), deserialized.isInjected());
    }

    @Test
    public void wireProtocolCompatibility_userWithMinimalFields() {
        // Test that User objects with minimal fields serialize/deserialize correctly
        User minimalUser = new User("minimal_user");

        // Serialize
        String serialized = Base64Helper.serializeObject(minimalUser);

        // Deserialize
        User deserialized = User.fromSerializedBase64(serialized);

        // Verify fields are preserved
        assertEquals(minimalUser.getName(), deserialized.getName());
        assertEquals(minimalUser.getRoles(), deserialized.getRoles());
        assertEquals(minimalUser.getSecurityRoles(), deserialized.getSecurityRoles());
        assertEquals(minimalUser.getCustomAttributesMap(), deserialized.getCustomAttributesMap());
    }

    @Test
    public void wireProtocolCompatibility_userAfterPrincipalConversion() {
        // Test that User -> UserPrincipal -> User conversion maintains wire protocol compatibility

        // Original User
        User originalUser = new User("protocol_user").withRoles(Arrays.asList("pr1", "pr2"))
            .withSecurityRoles(Arrays.asList("psr1"))
            .withAttributes(ImmutableMap.of("protocol_attr", "protocol_value"));

        // Convert to UserPrincipal (internal processing)
        UserPrincipal principal = originalUser.toPrincipal();

        // Convert back to User (for wire transmission)
        User convertedUser = User.fromPrincipal(principal, originalUser.getSecurityRoles());

        // Serialize both
        String originalSerialized = Base64Helper.serializeObject(originalUser);
        String convertedSerialized = Base64Helper.serializeObject(convertedUser);

        // Deserialize both
        User originalDeserialized = User.fromSerializedBase64(originalSerialized);
        User convertedDeserialized = User.fromSerializedBase64(convertedSerialized);

        // Verify both deserialize to equivalent Users
        assertEquals(originalDeserialized.getName(), convertedDeserialized.getName());
        assertEquals(originalDeserialized.getRoles(), convertedDeserialized.getRoles());
        assertEquals(originalDeserialized.getSecurityRoles(), convertedDeserialized.getSecurityRoles());
        assertEquals(originalDeserialized.getCustomAttributesMap(), convertedDeserialized.getCustomAttributesMap());
    }

    @Test
    public void wireProtocolCompatibility_noBreakingChanges() {
        // This test verifies that the wire protocol has not changed by comparing
        // serialization output before and after adding UserPrincipal support

        // Create a User with known properties
        User user = new User("protocol_check_user").withRoles(Arrays.asList("pcr1", "pcr2"))
            .withSecurityRoles(Arrays.asList("pcsr1"))
            .withAttributes(ImmutableMap.of("pc_attr", "pc_value"));

        // Serialize
        String serialized = Base64Helper.serializeObject(user);

        // Deserialize using the old deserialization path (which should still work)
        User deserialized = User.fromSerializedBase64(serialized);

        // Verify exact equality
        assertEquals(user, deserialized);
        assertEquals(user.getName(), deserialized.getName());
        assertEquals(user.getRoles(), deserialized.getRoles());
        assertEquals(user.getSecurityRoles(), deserialized.getSecurityRoles());
        assertEquals(user.getCustomAttributesMap(), deserialized.getCustomAttributesMap());
        assertEquals(user.isInjected(), deserialized.isInjected());

        // Verify that deserializing from 2.19 still works (regression test)
        // This is the same serialized string used in deserializationFrom2_19 test
        String serializedFrom2_19 =
            "rO0ABXNyACFvcmcub3BlbnNlYXJjaC5zZWN1cml0eS51c2VyLlVzZXKzqL2T65dH3AIABloACmlzSW5qZWN0ZWRMAAphdHRyaWJ1dGVzdAAPTGphdmEvdXRpbC9NYXA7TAAEbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAD3JlcXVlc3RlZFRlbmFudHEAfgACTAAFcm9sZXN0AA9MamF2YS91dGlsL1NldDtMAA1zZWN1cml0eVJvbGVzcQB+AAN4cABzcgAlamF2YS51dGlsLkNvbGxlY3Rpb25zJFN5bmNocm9uaXplZE1hcBtz+QlLSzl7AwACTAABbXEAfgABTAAFbXV0ZXh0ABJMamF2YS9sYW5nL09iamVjdDt4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAN3CAAAAAQAAAACdAABYXQAA3ZfYXQAAWJ0AAN2X2J4cQB+AAd4dAAXc2VyaWFsaXphdGlvbl90ZXN0X3VzZXJwc3IAJWphdmEudXRpbC5Db2xsZWN0aW9ucyRTeW5jaHJvbml6ZWRTZXQGw8J5Au7fPAIAAHhyACxqYXZhLnV0aWwuQ29sbGVjdGlvbnMkU3luY2hyb25pemVkQ29sbGVjdGlvbiph+E0JnJm1AwACTAABY3QAFkxqYXZhL3V0aWwvQ29sbGVjdGlvbjtMAAVtdXRleHEAfgAGeHBzcgARamF2YS51dGlsLkhhc2hTZXS6RIWVlri3NAMAAHhwdwwAAAAQP0AAAAAAAAN0AANicjF0AANicjN0AANicjJ4cQB+ABJ4c3EAfgAPc3EAfgATdwwAAAAQP0AAAAAAAAJ0AANzcjJ0AANzcjF4cQB+ABh4";
        User oldVersionUser = User.fromSerializedBase64(serializedFrom2_19);
        assertEquals("serialization_test_user", oldVersionUser.getName());
    }
}
