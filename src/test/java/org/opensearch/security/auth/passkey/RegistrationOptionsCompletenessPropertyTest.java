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
import java.util.UUID;

import com.webauthn4j.data.PublicKeyCredentialCreationOptions;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based test for registration options completeness.
 * 
 * **Feature: passkey-authentication, Property 6: Registration options completeness**
 * **Validates: Requirements 2.2**
 * 
 * For any registration request, the returned options should include user identifier,
 * relying party information, and supported credential algorithms.
 */
public class RegistrationOptionsCompletenessPropertyTest {

    /**
     * Property 6: Registration options completeness
     * 
     * For any registration request, the returned options should include user identifier,
     * relying party information, and supported credential algorithms.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void registrationOptionsCompleteness() {
        java.util.Random random = new java.util.Random(60); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random username and userId
            String username = "user" + random.nextInt(10000);
            String userId = UUID.randomUUID().toString();
            
            // Generate random exclude credentials list
            List<String> excludeCredentials = new ArrayList<>();
            int numExclude = random.nextInt(5); // 0-4 credentials to exclude
            for (int j = 0; j < numExclude; j++) {
                // Generate random base64url-encoded credential ID
                byte[] credId = new byte[16];
                random.nextBytes(credId);
                excludeCredentials.add(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credId));
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
            
            // Generate registration options
            PublicKeyCredentialCreationOptions options = manager.generateRegistrationOptions(
                username,
                userId,
                excludeCredentials
            );
            
            // Assert: Options should be complete
            assertNotNull("Registration options should not be null", options);
            
            // Check user entity
            assertNotNull("User entity should not be null", options.getUser());
            assertEquals("Username should match", username, options.getUser().getName());
            assertEquals("User display name should match", username, options.getUser().getDisplayName());
            assertNotNull("User ID should not be null", options.getUser().getId());
            
            // Check relying party entity
            assertNotNull("RP entity should not be null", options.getRp());
            assertEquals("RP ID should match", "example.com", options.getRp().getId());
            assertEquals("RP name should match", "Example RP", options.getRp().getName());
            
            // Check supported algorithms
            assertNotNull("Supported algorithms should not be null", options.getPubKeyCredParams());
            assertTrue("Should have at least one supported algorithm", options.getPubKeyCredParams().size() > 0);
            
            // Check challenge
            assertNotNull("Challenge should not be null", options.getChallenge());
            assertTrue("Challenge should have sufficient entropy (at least 16 bytes)", 
                options.getChallenge().getValue().length >= 16);
            
            // Check exclude credentials
            if (!excludeCredentials.isEmpty()) {
                assertNotNull("Exclude credentials should not be null when provided", 
                    options.getExcludeCredentials());
                assertEquals("Number of excluded credentials should match", 
                    excludeCredentials.size(), 
                    options.getExcludeCredentials().size());
            }
            
            // Check timeout
            assertNotNull("Timeout should not be null", options.getTimeout());
            assertTrue("Timeout should be positive", options.getTimeout() > 0);
            
            // Check attestation
            assertNotNull("Attestation preference should not be null", options.getAttestation());
            
            // Check authenticator selection
            assertNotNull("Authenticator selection should not be null", options.getAuthenticatorSelection());
            assertNotNull("User verification should not be null", 
                options.getAuthenticatorSelection().getUserVerification());
            assertNotNull("Resident key requirement should not be null", 
                options.getAuthenticatorSelection().getResidentKey());
        }
    }
}
