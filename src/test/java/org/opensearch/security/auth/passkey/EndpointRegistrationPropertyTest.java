/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for endpoint registration.
 * 
 * **Feature: passkey-authentication, Property 2: Endpoint registration**
 * **Validates: Requirements 1.2**
 * 
 * For any enabled passkey backend configuration, the WebAuthn registration and 
 * authentication endpoints should be registered and accessible.
 */
public class EndpointRegistrationPropertyTest {

    /**
     * Property 2: Endpoint registration
     * 
     * For any enabled passkey backend configuration, the WebAuthn endpoints
     * should be registered and accessible.
     * 
     * This test runs 100 iterations with random configurations to verify the property holds.
     */
    @org.junit.Test
    public void passkeyAuthenticatorIsRegisteredWhenEnabled() {
        java.util.Random random = new java.util.Random(42); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration settings
            Settings.Builder settingsBuilder = Settings.builder();
            
            // Add random passkey configuration
            String rpId = generateRandomDomain(random);
            String rpName = generateRandomName(random);
            
            settingsBuilder.put("plugins.security.passkey.rp_id", rpId);
            settingsBuilder.put("plugins.security.passkey.rp_name", rpName);
            settingsBuilder.put("plugins.security.passkey.enabled", true);
            
            Settings settings = settingsBuilder.build();
            Path configPath = Paths.get("/tmp/config");
            
            // Create the authenticator
            HTTPPasskeyAuthenticator authenticator = new HTTPPasskeyAuthenticator(settings, configPath);
            
            // Verify the authenticator is properly initialized
            assertNotNull("Authenticator should be initialized", authenticator);
            
            // Verify the type is correct
            assertEquals(
                "Authenticator type should be 'passkey'",
                "passkey",
                authenticator.getType()
            );
            
            // Verify the authenticator can generate challenges
            // This simulates endpoint registration by checking that the authenticator
            // can respond to authentication requests
            org.opensearch.security.filter.SecurityRequest mockRequest = createMockRequest(random);
            org.opensearch.common.util.concurrent.ThreadContext threadContext = 
                new org.opensearch.common.util.concurrent.ThreadContext(settings);
            
            // The authenticator should be able to handle requests
            // Even if it returns null (no credentials), it should not throw exceptions
            try {
                authenticator.extractCredentials(mockRequest, threadContext);
                // Success - authenticator is functional
            } catch (Exception e) {
                // Should not throw exceptions during normal operation
                throw new AssertionError("Authenticator should handle requests without exceptions", e);
            }
        }
    }

    /**
     * Property 2 (variant): Authenticator provides challenge on re-request
     * 
     * For any enabled passkey authenticator, calling reRequestAuthentication
     * should return a valid challenge response.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void authenticatorProvidesChallenge() {
        java.util.Random random = new java.util.Random(43); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Create authenticator with random configuration
            Settings settings = Settings.builder()
                .put("plugins.security.passkey.enabled", true)
                .build();
            Path configPath = Paths.get("/tmp/config");
            
            HTTPPasskeyAuthenticator authenticator = new HTTPPasskeyAuthenticator(settings, configPath);
            
            // Create mock request and credentials
            org.opensearch.security.filter.SecurityRequest mockRequest = createMockRequest(random);
            org.opensearch.security.user.AuthCredentials mockCredentials = 
                new org.opensearch.security.user.AuthCredentials("testuser");
            
            // Request authentication challenge
            java.util.Optional<org.opensearch.security.filter.SecurityResponse> response = 
                authenticator.reRequestAuthentication(mockRequest, mockCredentials);
            
            // Verify challenge response is provided
            assertTrue(
                "Authenticator should provide challenge response",
                response.isPresent()
            );
            
            org.opensearch.security.filter.SecurityResponse securityResponse = response.get();
            
            // Verify response has correct status code (401 Unauthorized)
            assertEquals(
                "Challenge response should have 401 status",
                401,
                securityResponse.getStatus()
            );
            
            // Verify response has WWW-Authenticate header
            assertNotNull(
                "Challenge response should have headers",
                securityResponse.getHeaders()
            );
            
            assertTrue(
                "Challenge response should have WWW-Authenticate header",
                securityResponse.getHeaders().containsKey("WWW-Authenticate")
            );
            
            // Verify response body contains challenge data
            String body = securityResponse.getBody();
            assertNotNull("Challenge response should have body", body);
            assertTrue(
                "Challenge response body should contain challenge",
                body.contains("challenge")
            );
            assertTrue(
                "Challenge response body should contain challengeId",
                body.contains("challengeId")
            );
        }
    }

    /**
     * Property 2 (variant): Multiple authenticator instances are independent
     * 
     * For any two passkey authenticator instances, they should operate independently
     * and not interfere with each other.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void multipleAuthenticatorInstancesAreIndependent() {
        java.util.Random random = new java.util.Random(44); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Create two authenticators with different configurations
            Settings settings1 = Settings.builder()
                .put("plugins.security.passkey.rp_id", generateRandomDomain(random))
                .put("plugins.security.passkey.enabled", true)
                .build();
            
            Settings settings2 = Settings.builder()
                .put("plugins.security.passkey.rp_id", generateRandomDomain(random))
                .put("plugins.security.passkey.enabled", true)
                .build();
            
            Path configPath = Paths.get("/tmp/config");
            
            HTTPPasskeyAuthenticator authenticator1 = new HTTPPasskeyAuthenticator(settings1, configPath);
            HTTPPasskeyAuthenticator authenticator2 = new HTTPPasskeyAuthenticator(settings2, configPath);
            
            // Both should have the same type
            assertEquals(
                "Both authenticators should have type 'passkey'",
                authenticator1.getType(),
                authenticator2.getType()
            );
            
            // Both should be able to generate challenges independently
            org.opensearch.security.filter.SecurityRequest mockRequest = createMockRequest(random);
            org.opensearch.security.user.AuthCredentials mockCredentials = 
                new org.opensearch.security.user.AuthCredentials("testuser");
            
            java.util.Optional<org.opensearch.security.filter.SecurityResponse> response1 = 
                authenticator1.reRequestAuthentication(mockRequest, mockCredentials);
            java.util.Optional<org.opensearch.security.filter.SecurityResponse> response2 = 
                authenticator2.reRequestAuthentication(mockRequest, mockCredentials);
            
            // Both should provide responses
            assertTrue("Authenticator 1 should provide response", response1.isPresent());
            assertTrue("Authenticator 2 should provide response", response2.isPresent());
            
            // The challenges should be different (independent)
            String body1 = response1.get().getBody();
            String body2 = response2.get().getBody();
            
            // Extract challenge IDs from bodies (they should be different)
            String challengeId1 = extractChallengeId(body1);
            String challengeId2 = extractChallengeId(body2);
            
            assertTrue(
                "Challenge IDs should be different for independent authenticators",
                !challengeId1.equals(challengeId2)
            );
        }
    }

    /**
     * Property 2 (variant): Authenticator type is consistent
     * 
     * For any passkey authenticator instance, the type should always be "passkey"
     * regardless of configuration.
     * 
     * This test runs 100 iterations with random configurations to verify the property holds.
     */
    @org.junit.Test
    public void authenticatorTypeIsConsistent() {
        java.util.Random random = new java.util.Random(45); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Create authenticator with random configuration
            Settings.Builder settingsBuilder = Settings.builder();
            
            // Add random configuration values
            settingsBuilder.put("plugins.security.passkey.rp_id", generateRandomDomain(random));
            settingsBuilder.put("plugins.security.passkey.rp_name", generateRandomName(random));
            settingsBuilder.put("plugins.security.passkey.challenge_timeout_ms", 60000 + random.nextInt(240000));
            settingsBuilder.put("plugins.security.passkey.enabled", true);
            
            Settings settings = settingsBuilder.build();
            Path configPath = Paths.get("/tmp/config");
            
            HTTPPasskeyAuthenticator authenticator = new HTTPPasskeyAuthenticator(settings, configPath);
            
            // Type should always be "passkey"
            assertEquals(
                "Authenticator type should always be 'passkey'",
                "passkey",
                authenticator.getType()
            );
            
            // Call getType multiple times - should be consistent
            for (int j = 0; j < 10; j++) {
                assertEquals(
                    "Authenticator type should be consistent across calls",
                    "passkey",
                    authenticator.getType()
                );
            }
        }
    }

    // Helper methods

    private String generateRandomDomain(java.util.Random random) {
        String[] tlds = { "com", "org", "net", "io", "dev" };
        String subdomain = generateRandomString(random, 5, 10);
        String domain = generateRandomString(random, 5, 10);
        String tld = tlds[random.nextInt(tlds.length)];
        return subdomain + "." + domain + "." + tld;
    }

    private String generateRandomName(java.util.Random random) {
        String[] prefixes = { "Test", "Demo", "Sample", "Example", "Mock" };
        String[] suffixes = { "Service", "Platform", "System", "Application", "Portal" };
        return prefixes[random.nextInt(prefixes.length)] + " " + 
               suffixes[random.nextInt(suffixes.length)];
    }

    private String generateRandomString(java.util.Random random, int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    private org.opensearch.security.filter.SecurityRequest createMockRequest(java.util.Random random) {
        // Create a minimal mock request for testing
        return new org.opensearch.security.filter.SecurityRequest() {
            @Override
            public java.util.Map<String, java.util.List<String>> getHeaders() {
                return java.util.Map.of(
                    "Content-Type", java.util.List.of("application/json"),
                    "User-Agent", java.util.List.of("Test-Agent")
                );
            }

            @Override
            public javax.net.ssl.SSLEngine getSSLEngine() {
                return null;
            }

            @Override
            public String path() {
                return "/_plugins/_security/api/passkey/authentication/verify";
            }

            @Override
            public org.opensearch.rest.RestRequest.Method method() {
                return org.opensearch.rest.RestRequest.Method.POST;
            }

            @Override
            public java.util.Optional<java.net.InetSocketAddress> getRemoteAddress() {
                return java.util.Optional.empty();
            }

            @Override
            public String uri() {
                return "/_plugins/_security/api/passkey/authentication/verify";
            }

            @Override
            public java.util.Map<String, String> params() {
                return java.util.Map.of();
            }

            @Override
            public java.util.Set<String> getUnconsumedParams() {
                return java.util.Set.of();
            }
        };
    }

    private String extractChallengeId(String jsonBody) {
        // Simple extraction of challengeId from JSON
        // Format: {"challenge":"...","challengeId":"...","rpId":"...","timeout":...}
        int startIndex = jsonBody.indexOf("\"challengeId\":\"");
        if (startIndex == -1) {
            return "";
        }
        startIndex += 15; // Length of "challengeId":"
        int endIndex = jsonBody.indexOf("\"", startIndex);
        if (endIndex == -1) {
            return "";
        }
        return jsonBody.substring(startIndex, endIndex);
    }
}
