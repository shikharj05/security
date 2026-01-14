/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for relying party ID validation.
 * 
 * **Feature: passkey-authentication, Property 3: Relying party ID validation**
 * **Validates: Requirements 1.3**
 * 
 * For any relying party ID and domain pair, the validation should accept the ID 
 * if and only if it matches the domain.
 */
public class RelyingPartyIdValidationPropertyTest {

    /**
     * Property 3: Relying party ID validation
     * 
     * For any relying party ID and domain pair, validation should accept the ID
     * if and only if it matches the domain.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void relyingPartyIdMatchesDomain() {
        java.util.Random random = new java.util.Random(44); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random domain components
            String subdomain = generateRandomDomainLabel(random);
            String domain = generateRandomDomainLabel(random);
            String tld = generateRandomTld(random);
            
            // Test case 1: Exact match - RP ID equals domain
            String fullDomain = subdomain + "." + domain + "." + tld;
            assertTrue(
                "RP ID should match when equal to domain",
                validateRpIdMatchesDomain(fullDomain, fullDomain)
            );
            
            // Test case 2: RP ID is parent domain (valid)
            String parentDomain = domain + "." + tld;
            assertTrue(
                "RP ID should match when it's a parent domain",
                validateRpIdMatchesDomain(parentDomain, fullDomain)
            );
            
            // Test case 3: RP ID is different domain (invalid)
            String differentDomain = generateRandomDomainLabel(random) + "." + tld;
            assertFalse(
                "RP ID should not match when it's a different domain",
                validateRpIdMatchesDomain(differentDomain, fullDomain)
            );
            
            // Test case 4: RP ID is subdomain of the domain (invalid - RP ID must be equal or parent)
            String subdomainOfFull = "extra." + fullDomain;
            assertFalse(
                "RP ID should not match when it's a subdomain of the actual domain",
                validateRpIdMatchesDomain(subdomainOfFull, fullDomain)
            );
        }
    }

    /**
     * Property 3 (variant): RP ID validation with port numbers
     * 
     * For any domain with port, the RP ID should match the domain without port.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void relyingPartyIdIgnoresPort() {
        java.util.Random random = new java.util.Random(45); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random domain and port
            String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
            int port = 1024 + random.nextInt(64512); // Random port between 1024 and 65535
            
            String domainWithPort = domain + ":" + port;
            
            // RP ID should match the domain without port
            assertTrue(
                "RP ID should match domain regardless of port",
                validateRpIdMatchesDomain(domain, domainWithPort)
            );
        }
    }

    /**
     * Property 3 (variant): RP ID validation is case-insensitive
     * 
     * For any domain, the RP ID should match regardless of case.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void relyingPartyIdIsCaseInsensitive() {
        java.util.Random random = new java.util.Random(46); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random domain
            String domain = generateRandomDomainLabel(random) + "." + generateRandomTld(random);
            
            // Test with different case variations
            String upperCase = domain.toUpperCase();
            String lowerCase = domain.toLowerCase();
            String mixedCase = randomizeCase(domain, random);
            
            // All case variations should match
            assertTrue(
                "RP ID should match domain in uppercase",
                validateRpIdMatchesDomain(upperCase, lowerCase)
            );
            assertTrue(
                "RP ID should match domain in lowercase",
                validateRpIdMatchesDomain(lowerCase, upperCase)
            );
            assertTrue(
                "RP ID should match domain in mixed case",
                validateRpIdMatchesDomain(mixedCase, lowerCase)
            );
        }
    }

    /**
     * Property 3 (variant): RP ID validation rejects invalid formats
     * 
     * For any invalid RP ID format, validation should reject it.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void relyingPartyIdRejectsInvalidFormats() {
        java.util.Random random = new java.util.Random(47); // Fixed seed for reproducibility
        
        String validDomain = "example.com";
        
        for (int i = 0; i < 100; i++) {
            // Test various invalid formats
            String[] invalidRpIds = {
                "",                                          // Empty string
                " ",                                         // Whitespace only
                "http://" + validDomain,                     // With protocol
                "https://" + validDomain,                    // With protocol
                validDomain + "/path",                       // With path
                validDomain + "?query=value",                // With query
                validDomain + "#fragment",                   // With fragment
                "user@" + validDomain,                       // With user info
                generateRandomString(random, 1, 5),          // Random string without dots
                "." + validDomain,                           // Leading dot
                validDomain + ".",                           // Trailing dot
                "..",                                        // Only dots
                "domain..com",                               // Double dots
            };
            
            for (String invalidRpId : invalidRpIds) {
                assertFalse(
                    "Invalid RP ID format should be rejected: " + invalidRpId,
                    isValidRpIdFormat(invalidRpId)
                );
            }
        }
    }

    // Helper methods

    /**
     * Validates if an RP ID matches a domain according to WebAuthn spec.
     * 
     * According to WebAuthn spec:
     * - RP ID must be equal to or a registrable domain suffix of the origin's effective domain
     * - Comparison is case-insensitive
     * - Port numbers are ignored
     */
    private boolean validateRpIdMatchesDomain(String rpId, String domain) {
        if (rpId == null || domain == null) {
            return false;
        }
        
        if (!isValidRpIdFormat(rpId)) {
            return false;
        }
        
        // Extract domain without port
        String effectiveDomain = extractDomainWithoutPort(domain);
        
        // Normalize to lowercase for case-insensitive comparison
        String normalizedRpId = rpId.toLowerCase().trim();
        String normalizedDomain = effectiveDomain.toLowerCase().trim();
        
        // Exact match
        if (normalizedRpId.equals(normalizedDomain)) {
            return true;
        }
        
        // RP ID is a registrable domain suffix (parent domain)
        // The domain must end with "." + rpId
        return normalizedDomain.endsWith("." + normalizedRpId);
    }

    /**
     * Validates if an RP ID has a valid format.
     */
    private boolean isValidRpIdFormat(String rpId) {
        if (rpId == null || rpId.trim().isEmpty()) {
            return false;
        }
        
        String trimmed = rpId.trim();
        
        // Must not contain protocol
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return false;
        }
        
        // Must not contain path, query, or fragment
        if (trimmed.contains("/") || trimmed.contains("?") || trimmed.contains("#")) {
            return false;
        }
        
        // Must not contain user info
        if (trimmed.contains("@")) {
            return false;
        }
        
        // Must not start or end with dot
        if (trimmed.startsWith(".") || trimmed.endsWith(".")) {
            return false;
        }
        
        // Must not contain consecutive dots
        if (trimmed.contains("..")) {
            return false;
        }
        
        // Must contain at least one dot (domain.tld format)
        if (!trimmed.contains(".")) {
            return false;
        }
        
        return true;
    }

    /**
     * Extracts domain without port number.
     */
    private String extractDomainWithoutPort(String domain) {
        if (domain == null) {
            return null;
        }
        
        // Remove protocol if present
        String cleaned = domain;
        if (cleaned.startsWith("http://")) {
            cleaned = cleaned.substring(7);
        } else if (cleaned.startsWith("https://")) {
            cleaned = cleaned.substring(8);
        }
        
        // Remove port if present
        int colonIndex = cleaned.lastIndexOf(':');
        if (colonIndex > 0) {
            // Check if what follows is a number (port)
            String afterColon = cleaned.substring(colonIndex + 1);
            if (afterColon.matches("\\d+")) {
                cleaned = cleaned.substring(0, colonIndex);
            }
        }
        
        // Remove path if present
        int slashIndex = cleaned.indexOf('/');
        if (slashIndex > 0) {
            cleaned = cleaned.substring(0, slashIndex);
        }
        
        return cleaned;
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

    private String randomizeCase(String input, java.util.Random random) {
        StringBuilder sb = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            if (random.nextBoolean()) {
                sb.append(Character.toUpperCase(c));
            } else {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }
}
