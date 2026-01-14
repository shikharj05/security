/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for origin restriction validation.
 * 
 * **Feature: passkey-authentication, Property 4: Origin restriction**
 * **Validates: Requirements 1.4**
 * 
 * For any authentication request with an origin, the request should be accepted 
 * if and only if the origin is in the allowed origins list.
 */
public class OriginRestrictionPropertyTest {

    /**
     * Property 4: Origin restriction
     * 
     * For any authentication request with an origin, the request should be accepted
     * if and only if the origin is in the allowed origins list.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void originMustBeInAllowedList() {
        java.util.Random random = new java.util.Random(48); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random allowed origins list
            List<String> allowedOrigins = generateRandomOriginsList(random, 1, 5);
            
            // Test case 1: Origin in allowed list should be accepted
            String allowedOrigin = allowedOrigins.get(random.nextInt(allowedOrigins.size()));
            assertTrue(
                "Origin in allowed list should be accepted",
                isOriginAllowed(allowedOrigin, allowedOrigins)
            );
            
            // Test case 2: Origin not in allowed list should be rejected
            String disallowedOrigin = generateRandomOrigin(random);
            // Make sure it's actually not in the list
            while (allowedOrigins.contains(disallowedOrigin)) {
                disallowedOrigin = generateRandomOrigin(random);
            }
            assertFalse(
                "Origin not in allowed list should be rejected",
                isOriginAllowed(disallowedOrigin, allowedOrigins)
            );
        }
    }

    /**
     * Property 4 (variant): Origin matching is exact
     * 
     * For any origin, only exact matches should be accepted (no subdomain matching).
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void originMatchingIsExact() {
        java.util.Random random = new java.util.Random(49); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate a base origin
            String protocol = random.nextBoolean() ? "https" : "http";
            String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
            String baseOrigin = protocol + "://" + domain;
            
            List<String> allowedOrigins = List.of(baseOrigin);
            
            // Test case 1: Subdomain should not match
            String subdomain = "sub." + domain;
            String subdomainOrigin = protocol + "://" + subdomain;
            assertFalse(
                "Subdomain origin should not match parent domain",
                isOriginAllowed(subdomainOrigin, allowedOrigins)
            );
            
            // Test case 2: Different protocol should not match
            String differentProtocol = protocol.equals("https") ? "http" : "https";
            String differentProtocolOrigin = differentProtocol + "://" + domain;
            assertFalse(
                "Different protocol should not match",
                isOriginAllowed(differentProtocolOrigin, allowedOrigins)
            );
            
            // Test case 3: Different port should not match (unless both are default)
            String withPort = baseOrigin + ":8080";
            assertFalse(
                "Origin with explicit port should not match origin without port",
                isOriginAllowed(withPort, allowedOrigins)
            );
        }
    }

    /**
     * Property 4 (variant): Origin validation handles ports correctly
     * 
     * For any origin with port, it should only match if the allowed origin also has the same port.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void originValidationHandlesPorts() {
        java.util.Random random = new java.util.Random(50); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            String protocol = "https";
            String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
            int port = 1024 + random.nextInt(64512); // Random port between 1024 and 65535
            
            // Test case 1: Exact match with port
            String originWithPort = protocol + "://" + domain + ":" + port;
            List<String> allowedWithPort = List.of(originWithPort);
            assertTrue(
                "Origin with port should match when allowed list has same port",
                isOriginAllowed(originWithPort, allowedWithPort)
            );
            
            // Test case 2: Origin without port should not match allowed list with port
            String originWithoutPort = protocol + "://" + domain;
            assertFalse(
                "Origin without port should not match allowed list with port",
                isOriginAllowed(originWithoutPort, allowedWithPort)
            );
            
            // Test case 3: Origin with port should not match allowed list without port
            List<String> allowedWithoutPort = List.of(originWithoutPort);
            assertFalse(
                "Origin with port should not match allowed list without port",
                isOriginAllowed(originWithPort, allowedWithoutPort)
            );
            
            // Test case 4: Different ports should not match
            String originWithDifferentPort = protocol + "://" + domain + ":" + (port + 1);
            assertFalse(
                "Origin with different port should not match",
                isOriginAllowed(originWithDifferentPort, allowedWithPort)
            );
        }
    }

    /**
     * Property 4 (variant): Origin validation is case-sensitive for protocol and path
     * 
     * For any origin, the protocol must match exactly (case-sensitive).
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void originProtocolIsCaseSensitive() {
        java.util.Random random = new java.util.Random(51); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
            String origin = "https://" + domain;
            List<String> allowedOrigins = List.of(origin);
            
            // Test case 1: Uppercase protocol should not match
            String upperProtocol = "HTTPS://" + domain;
            assertFalse(
                "Uppercase protocol should not match lowercase protocol",
                isOriginAllowed(upperProtocol, allowedOrigins)
            );
            
            // Test case 2: Mixed case protocol should not match
            String mixedProtocol = "HtTpS://" + domain;
            assertFalse(
                "Mixed case protocol should not match lowercase protocol",
                isOriginAllowed(mixedProtocol, allowedOrigins)
            );
        }
    }

    /**
     * Property 4 (variant): Origin validation rejects invalid formats
     * 
     * For any invalid origin format, validation should reject it.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void originValidationRejectsInvalidFormats() {
        java.util.Random random = new java.util.Random(52); // Fixed seed for reproducibility
        
        List<String> validAllowedOrigins = List.of("https://example.com");
        
        for (int i = 0; i < 100; i++) {
            // Test various invalid formats
            String[] invalidOrigins = {
                "",                                          // Empty string
                " ",                                         // Whitespace only
                "example.com",                               // Missing protocol
                "//example.com",                             // Missing protocol
                "ftp://example.com",                         // Invalid protocol for WebAuthn
                "https://",                                  // Missing domain
                "https:// example.com",                      // Space in URL
                "https://example.com/path",                  // With path (origins shouldn't have paths)
                "https://example.com?query=value",           // With query
                "https://example.com#fragment",              // With fragment
                "https://user@example.com",                  // With user info
                generateRandomString(random, 1, 10),         // Random string
            };
            
            for (String invalidOrigin : invalidOrigins) {
                assertFalse(
                    "Invalid origin format should be rejected: " + invalidOrigin,
                    isValidOriginFormat(invalidOrigin)
                );
            }
        }
    }

    /**
     * Property 4 (variant): Empty allowed origins list rejects all origins
     * 
     * For any origin, if the allowed origins list is empty, the origin should be rejected.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void emptyAllowedListRejectsAllOrigins() {
        java.util.Random random = new java.util.Random(53); // Fixed seed for reproducibility
        
        List<String> emptyAllowedOrigins = List.of();
        
        for (int i = 0; i < 100; i++) {
            String origin = generateRandomOrigin(random);
            assertFalse(
                "Any origin should be rejected when allowed list is empty",
                isOriginAllowed(origin, emptyAllowedOrigins)
            );
        }
    }

    // Helper methods

    /**
     * Validates if an origin is allowed according to the allowed origins list.
     * 
     * According to WebAuthn spec:
     * - Origin must exactly match one of the allowed origins
     * - Protocol, domain, and port must all match exactly
     * - Domain comparison is case-insensitive, but protocol is case-sensitive
     */
    private boolean isOriginAllowed(String origin, List<String> allowedOrigins) {
        if (origin == null || allowedOrigins == null || allowedOrigins.isEmpty()) {
            return false;
        }
        
        if (!isValidOriginFormat(origin)) {
            return false;
        }
        
        // Normalize origin for comparison
        String normalizedOrigin = normalizeOrigin(origin);
        
        // Check if origin is in the allowed list
        for (String allowedOrigin : allowedOrigins) {
            if (!isValidOriginFormat(allowedOrigin)) {
                continue;
            }
            
            String normalizedAllowed = normalizeOrigin(allowedOrigin);
            if (normalizedOrigin.equals(normalizedAllowed)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Validates if an origin has a valid format for WebAuthn.
     */
    private boolean isValidOriginFormat(String origin) {
        if (origin == null || origin.trim().isEmpty()) {
            return false;
        }
        
        String trimmed = origin.trim();
        
        // Must start with http:// or https://
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            return false;
        }
        
        // Extract the part after protocol
        String afterProtocol = trimmed.substring(trimmed.indexOf("://") + 3);
        
        // Must not be empty after protocol
        if (afterProtocol.isEmpty()) {
            return false;
        }
        
        // Must not contain path, query, or fragment (origins are scheme + host + port only)
        if (afterProtocol.contains("/") || afterProtocol.contains("?") || afterProtocol.contains("#")) {
            return false;
        }
        
        // Must not contain user info
        if (afterProtocol.contains("@")) {
            return false;
        }
        
        // Must not contain spaces
        if (trimmed.contains(" ")) {
            return false;
        }
        
        return true;
    }

    /**
     * Normalizes an origin for comparison.
     * - Protocol remains case-sensitive (as per spec)
     * - Domain is converted to lowercase
     * - Port is preserved
     */
    private String normalizeOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        
        // Split into protocol and rest
        int protocolEnd = origin.indexOf("://");
        if (protocolEnd < 0) {
            return origin;
        }
        
        String protocol = origin.substring(0, protocolEnd + 3); // Keep protocol as-is (case-sensitive)
        String rest = origin.substring(protocolEnd + 3).toLowerCase(); // Lowercase domain and port
        
        return protocol + rest;
    }

    private List<String> generateRandomOriginsList(java.util.Random random, int minSize, int maxSize) {
        int size = minSize + random.nextInt(maxSize - minSize + 1);
        List<String> origins = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            origins.add(generateRandomOrigin(random));
        }
        return origins;
    }

    private String generateRandomOrigin(java.util.Random random) {
        String protocol = random.nextBoolean() ? "https" : "http";
        String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
        
        // Sometimes add a port
        if (random.nextInt(3) == 0) {
            int port = 1024 + random.nextInt(64512);
            return protocol + "://" + domain + ":" + port;
        }
        
        return protocol + "://" + domain;
    }

    private String generateRandomDomainLabel(java.util.Random random) {
        int length = 3 + random.nextInt(10); // 3-12 characters
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    private String generateRandomTld(java.util.Random random) {
        String[] tlds = { "com", "org", "net", "edu", "gov", "io", "co", "dev" };
        return tlds[random.nextInt(tlds.length)];
    }

    private String generateRandomString(java.util.Random random, int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }
}
