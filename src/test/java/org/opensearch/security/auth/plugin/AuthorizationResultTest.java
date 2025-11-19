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

import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AuthorizationResultTest {

    @Test
    public void testAllow() {
        // act
        final AuthorizationResult result = AuthorizationResult.allow();

        // assert
        assertTrue(result.isAllowed());
        assertThat(result.getReason(), is(nullValue()));
        assertThat(result.getAppliedPolicies(), is(notNullValue()));
        assertThat(result.getAppliedPolicies().size(), is(0));
    }

    @Test
    public void testDeny() {
        // act
        final AuthorizationResult result = AuthorizationResult.deny("Insufficient permissions");

        // assert
        assertFalse(result.isAllowed());
        assertThat(result.getReason(), is("Insufficient permissions"));
        assertThat(result.getAppliedPolicies(), is(notNullValue()));
        assertThat(result.getAppliedPolicies().size(), is(0));
    }

    @Test
    public void testDenyWithNullReason() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> AuthorizationResult.deny(null));
        assertThat(exception.getMessage(), is("reason must not be null or empty for deny result"));
    }

    @Test
    public void testDenyWithEmptyReason() {
        // act & assert
        final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> AuthorizationResult.deny(""));
        assertThat(exception.getMessage(), is("reason must not be null or empty for deny result"));
    }

    @Test
    public void testBuilderAllow() {
        // arrange
        final Set<String> policies = new HashSet<>();
        policies.add("policy1");
        policies.add("policy2");

        // act
        final AuthorizationResult result = AuthorizationResult.builder(true).appliedPolicies(policies).build();

        // assert
        assertTrue(result.isAllowed());
        assertThat(result.getReason(), is(nullValue()));
        assertThat(result.getAppliedPolicies(), is(ImmutableSet.of("policy1", "policy2")));
    }

    @Test
    public void testBuilderDeny() {
        // arrange
        final Set<String> policies = new HashSet<>();
        policies.add("deny-policy");

        // act
        final AuthorizationResult result = AuthorizationResult.builder(false)
            .reason("User not in required group")
            .appliedPolicies(policies)
            .build();

        // assert
        assertFalse(result.isAllowed());
        assertThat(result.getReason(), is("User not in required group"));
        assertThat(result.getAppliedPolicies(), is(ImmutableSet.of("deny-policy")));
    }

    @Test
    public void testBuilderWithAppliedPolicy() {
        // act
        final AuthorizationResult result = AuthorizationResult.builder(true)
            .appliedPolicy("policy1")
            .appliedPolicy("policy2")
            .appliedPolicy("policy3")
            .build();

        // assert
        assertTrue(result.isAllowed());
        assertThat(result.getAppliedPolicies(), is(ImmutableSet.of("policy1", "policy2", "policy3")));
    }

    @Test
    public void testBuilderWithNullAppliedPolicies() {
        // act
        final AuthorizationResult result = AuthorizationResult.builder(true).appliedPolicies(null).build();

        // assert
        assertTrue(result.isAllowed());
        assertThat(result.getAppliedPolicies(), is(notNullValue()));
        assertThat(result.getAppliedPolicies().size(), is(0));
    }

    @Test
    public void testBuilderWithNullAppliedPolicy() {
        // act & assert
        final NullPointerException exception = assertThrows(
            NullPointerException.class,
            () -> AuthorizationResult.builder(true).appliedPolicy(null)
        );
        assertThat(exception.getMessage(), is("policy must not be null"));
    }

    @Test
    public void testEqualsAndHashCode() {
        // arrange
        final AuthorizationResult result1 = AuthorizationResult.allow();
        final AuthorizationResult result2 = AuthorizationResult.allow();
        final AuthorizationResult result3 = AuthorizationResult.deny("Access denied");
        final AuthorizationResult result4 = AuthorizationResult.deny("Access denied");
        final AuthorizationResult result5 = AuthorizationResult.deny("Different reason");

        // assert
        assertThat(result1, is(equalTo(result2)));
        assertThat(result1.hashCode(), is(result2.hashCode()));

        assertThat(result3, is(equalTo(result4)));
        assertThat(result3.hashCode(), is(result4.hashCode()));

        assertFalse(result1.equals(result3));
        assertFalse(result3.equals(result5));
    }

    @Test
    public void testEqualsWithAppliedPolicies() {
        // arrange
        final Set<String> policies1 = ImmutableSet.of("policy1", "policy2");
        final Set<String> policies2 = ImmutableSet.of("policy1", "policy2");
        final Set<String> policies3 = ImmutableSet.of("policy1", "policy3");

        final AuthorizationResult result1 = AuthorizationResult.builder(true).appliedPolicies(policies1).build();
        final AuthorizationResult result2 = AuthorizationResult.builder(true).appliedPolicies(policies2).build();
        final AuthorizationResult result3 = AuthorizationResult.builder(true).appliedPolicies(policies3).build();

        // assert
        assertThat(result1, is(equalTo(result2)));
        assertThat(result1.hashCode(), is(result2.hashCode()));
        assertFalse(result1.equals(result3));
    }

    @Test
    public void testToString() {
        // arrange
        final AuthorizationResult allowResult = AuthorizationResult.allow();
        final AuthorizationResult denyResult = AuthorizationResult.deny("Access denied");
        final AuthorizationResult resultWithPolicies = AuthorizationResult.builder(true)
            .appliedPolicy("policy1")
            .appliedPolicy("policy2")
            .build();

        // act & assert
        assertThat(allowResult.toString(), is("AuthorizationResult{allowed=true, reason='null', appliedPoliciesCount=0}"));
        assertThat(denyResult.toString(), is("AuthorizationResult{allowed=false, reason='Access denied', appliedPoliciesCount=0}"));
        assertThat(resultWithPolicies.toString(), is("AuthorizationResult{allowed=true, reason='null', appliedPoliciesCount=2}"));
    }

    @Test
    public void testImmutability() {
        // arrange
        final Set<String> policies = new HashSet<>();
        policies.add("policy1");

        // act
        final AuthorizationResult result = AuthorizationResult.builder(true).appliedPolicies(policies).build();

        // Modify the original set
        policies.add("policy2");

        // assert - the result should not be affected
        assertThat(result.getAppliedPolicies(), is(ImmutableSet.of("policy1")));
    }

    @Test
    public void testAppliedPoliciesImmutable() {
        // arrange
        final AuthorizationResult result = AuthorizationResult.builder(true).appliedPolicy("policy1").build();

        // act & assert - attempting to modify the returned set should throw an exception
        assertThrows(UnsupportedOperationException.class, () -> result.getAppliedPolicies().add("policy2"));
    }
}
