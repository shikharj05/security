/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

/**
 * Integration tests for Passkey authentication REST API endpoints.
 * Validates: Requirements 2.1, 2.2, 3.1, 3.2, 5.1, 5.2, 5.3, 5.4
 */
public class PasskeyAuthenticationTests {

    protected static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    @Rule
    public LocalCluster cluster = new LocalCluster.Builder()
        .clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .build();

    @Test
    public void testRegistrationOptionsEndpoint() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            try {
                HttpResponse response = client.postJson(
                    "_plugins/_security/passkey/registration/options",
                    "{\"username\": \"test-user\"}"
                );

                response.assertStatusCode(SC_OK);
                JsonNode body = response.getBodyAs(JsonNode.class);
                assertThat(body.get("challengeId"), notNullValue());
                assertThat(body.get("challenge"), notNullValue());
                assertThat(body.get("rp"), notNullValue());
                assertThat(body.get("user").get("name").asText(), equalTo("test-user"));
            } catch (Exception e) {
                // Log the actual error for debugging
                System.err.println("Test failed with error: " + e.getMessage());
                e.printStackTrace();
                throw e;
            }
        }
    }

    @Test
    public void testAuthenticationOptionsForUnregisteredUser() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.postJson(
                "_plugins/_security/passkey/authentication/options",
                "{\"username\": \"unregistered-user\"}"
            );

            response.assertStatusCode(SC_NOT_FOUND);
            JsonNode body = response.getBodyAs(JsonNode.class);
            assertThat(body.get("error").asText(), containsString("No passkeys registered"));
        }
    }

    @Test
    public void testCredentialListingForNewUser() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.postJson(
                "_plugins/_security/passkey/credentials/list",
                "{\"username\": \"new-user\"}"
            );

            response.assertStatusCode(SC_OK);
            JsonNode body = response.getBodyAs(JsonNode.class);
            assertThat(body.get("credentials").size(), equalTo(0));
        }
    }

    @Test
    public void testDeleteNonExistentCredential() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse response = client.delete("_plugins/_security/passkey/credentials/fake-id");

            response.assertStatusCode(SC_NOT_FOUND);
            JsonNode body = response.getBodyAs(JsonNode.class);
            assertThat(body.get("error").asText(), containsString("Credential not found"));
        }
    }

    @Test
    public void testChallengeUniqueness() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            HttpResponse r1 = client.postJson("_plugins/_security/passkey/registration/options", 
                "{\"username\": \"user1\"}");
            HttpResponse r2 = client.postJson("_plugins/_security/passkey/registration/options", 
                "{\"username\": \"user1\"}");
            
            r1.assertStatusCode(SC_OK);
            r2.assertStatusCode(SC_OK);
            
            String c1 = r1.getBodyAs(JsonNode.class).get("challenge").asText();
            String c2 = r2.getBodyAs(JsonNode.class).get("challenge").asText();
            
            assertThat("Challenges should be unique", c1.equals(c2), equalTo(false));
        }
    }

    @Test
    public void testEndpointsRequireAuthentication() {
        try (TestRestClient client = cluster.createGenericClientRestClient(new org.opensearch.test.framework.cluster.TestRestClientConfiguration())) {
            HttpResponse response = client.postJson(
                "_plugins/_security/passkey/registration/options",
                "{\"username\": \"test\"}"
            );

            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }
}
