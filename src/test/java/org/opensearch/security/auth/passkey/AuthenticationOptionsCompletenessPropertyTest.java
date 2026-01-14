/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based test for authentication options completeness.
 * 
 * **Feature: passkey-authentication, Property 11: Authentication options completeness**
 * **Validates: Requirements 3.2**
 * 
 * For any authentication request, the returned options should include the challenge,
 * relying party ID, and optionally allowed credential IDs.
 */
public class AuthenticationOptionsCompletenessPropertyTest {

    /**
     * Property 11: Authentication options completeness
     * 
     * For any authentication request, the returned options should include the challenge,
     * relying party ID, and optionally allowed credential IDs.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void authenticationOptionsCompleteness() {
        java.util.Random random = new java.util.Random(110); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random allowed credentials list (sometimes null for usernameless auth)
            List<String> allowCredentials = null;
            if (random.nextBoolean()) {
                allowCredentials = new ArrayList<>();
                int numAllowed = random.nextInt(5) + 1; // 1-5 credentials
                for (int j = 0; j < numAllowed; j++) {
                    // Generate random base64url-encoded credential ID
                    byte[] credId = new byte[16];
                    random.nextBytes(credId);
                    allowCredentials.add(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credId));
                }
            }
            
            // Create configuration
            Settings settings = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example RP")
                .putList("config.allowed_origins", List.of("https://example.com"))
                .build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Create WebAuthnManager
            WebAuthnManager manager = new WebAuthnManager(rpConfig);
            
            // Generate authentication options
            PublicKeyCredentialRequestOptions options = manager.generateAuthenticationOptions(allowCredentials);
            
            // Assert: Options should be complete
            assertNotNull("Authentication options should not be null", options);
            
            // Check challenge
            assertNotNull("Challenge should not be null", options.getChallenge());
            assertTrue("Challenge should have sufficient entropy (at least 16 bytes)", 
                options.getChallenge().getValue().length >= 16);
            
            // Check relying party ID
            assertNotNull("RP ID should not be null", options.getRpId());
            assertEquals("RP ID should match", "example.com", options.getRpId());
            
            // Check allowed credentials
            if (allowCredentials != null && !allowCredentials.isEmpty()) {
                assertNotNull("Allowed credentials should not be null when provided", 
                    options.getAllowCredentials());
                assertEquals("Number of allowed credentials should match", 
                    allowCredentials.size(), 
                    options.getAllowCredentials().size());
            } else {
                // For usernameless authentication, allowed credentials can be null or empty
                if (options.getAllowCredentials() != null) {
                    assertTrue("Allowed credentials should be empty for usernameless auth",
                        options.getAllowCredentials().isEmpty());
                }
            }
            
            // Check timeout
            assertNotNull("Timeout should not be null", options.getTimeout());
            assertTrue("Timeout should be positive", options.getTimeout() > 0);
            
            // Check user verification
            assertNotNull("User verification should not be null", options.getUserVerification());
        }
    }
}
