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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.Test;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.*;

/**
 * Property-based tests for passkey configuration loading.
 * 
 * **Feature: passkey-authentication, Property 1: Configuration loading completeness**
 * **Validates: Requirements 1.1**
 * 
 * For any valid passkey configuration in config.yml, loading the configuration should result 
 * in an initialized passkey authentication module with all required components available.
 */
public class ConfigurationLoadingPropertyTest {

    private static final Random random = new Random();

    /**
     * Property 1: Configuration loading completeness
     * 
     * For any valid passkey configuration, loading the configuration should result in 
     * an initialized passkey authentication module with all required components available.
     * 
     * This test runs 100 iterations with randomly generated valid configurations.
     */
    @Test
    public void configurationLoadingCompleteness() {
        for (int i = 0; i < 100; i++) {
            // Generate random valid configuration
            PasskeyConfigData configData = generateValidConfig();
            
            // Create Settings from the config data
            Settings.Builder settingsBuilder = Settings.builder();
            
            // Add passkey configuration with the correct prefix
            settingsBuilder.put("config.rp_id", configData.rpId);
            settingsBuilder.put("config.rp_name", configData.rpName);
            settingsBuilder.putList("config.allowed_origins", configData.allowedOrigins);
            settingsBuilder.put("config.challenge_timeout_ms", configData.challengeTimeoutMs);
            settingsBuilder.put("config.user_verification", configData.userVerification);
            settingsBuilder.put("config.attestation", configData.attestation);
            
            if (configData.authenticatorAttachment != null) {
                settingsBuilder.put("config.authenticator_attachment", configData.authenticatorAttachment);
            }
            
            settingsBuilder.put("config.resident_key", configData.residentKey);
            settingsBuilder.putList("config.algorithms", configData.algorithms);
            
            Settings settings = settingsBuilder.build();
            Path configPath = Paths.get("config");
            
            // Load the configuration
            PasskeyAuthenticationConfig passkeyConfig = new PasskeyAuthenticationConfig(settings, configPath);
            
            // Parse the configuration
            RelyingPartyConfig rpConfig = passkeyConfig.parse();
            
            // Verify all required components are present
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            assertNotNull("RP ID should not be null", rpConfig.getRpId());
            assertNotNull("RP name should not be null", rpConfig.getRpName());
            assertNotNull("Allowed origins should not be null", rpConfig.getAllowedOrigins());
            assertFalse("Allowed origins should not be empty", rpConfig.getAllowedOrigins().isEmpty());
            assertTrue("Challenge timeout should be positive", rpConfig.getChallengeTimeoutMs() > 0);
            assertNotNull("User verification requirement should not be null", rpConfig.getUserVerification());
            assertNotNull("Attestation preference should not be null", rpConfig.getAttestation());
            assertNotNull("Resident key requirement should not be null", rpConfig.getResidentKey());
            assertNotNull("Supported algorithms should not be null", rpConfig.getPubKeyCredParams());
            assertFalse("Supported algorithms should not be empty", rpConfig.getPubKeyCredParams().isEmpty());
            
            // Verify the configuration values match what was provided
            assertEquals("RP ID should match", configData.rpId, rpConfig.getRpId());
            assertEquals("RP name should match", configData.rpName, rpConfig.getRpName());
            assertEquals("Allowed origins should match", configData.allowedOrigins, rpConfig.getAllowedOrigins());
            assertEquals("Challenge timeout should match", configData.challengeTimeoutMs, rpConfig.getChallengeTimeoutMs());
            
            // Verify WebAuthnManager can be initialized with the config
            WebAuthnManager webAuthnManager = new WebAuthnManager(rpConfig);
            assertNotNull("WebAuthnManager should be initialized", webAuthnManager);
        }
    }

    /**
     * Generates a valid passkey configuration with random values.
     */
    private PasskeyConfigData generateValidConfig() {
        String rpId = generateRandomString(5, 20).toLowerCase() + ".example.com";
        String rpName = "OpenSearch " + generateRandomString(5, 20);
        
        int originCount = random.nextInt(4) + 1; // 1-5 origins
        List<String> allowedOrigins = new ArrayList<>();
        for (int i = 0; i < originCount; i++) {
            allowedOrigins.add("https://" + generateRandomString(5, 15).toLowerCase() + ".example.com");
        }
        
        long challengeTimeoutMs = 60000L + random.nextInt(540000); // 1-10 minutes
        
        String[] userVerificationOptions = {"required", "preferred", "discouraged"};
        String userVerification = userVerificationOptions[random.nextInt(userVerificationOptions.length)];
        
        String[] attestationOptions = {"none", "indirect", "direct"};
        String attestation = attestationOptions[random.nextInt(attestationOptions.length)];
        
        String[] attachmentOptions = {"platform", "cross-platform", null};
        String authenticatorAttachment = attachmentOptions[random.nextInt(attachmentOptions.length)];
        
        String[] residentKeyOptions = {"required", "preferred", "discouraged"};
        String residentKey = residentKeyOptions[random.nextInt(residentKeyOptions.length)];
        
        List<List<String>> algorithmOptions = Arrays.asList(
            Arrays.asList("ES256", "RS256", "EdDSA"),
            Arrays.asList("ES256", "RS256"),
            Arrays.asList("ES256", "EdDSA"),
            Arrays.asList("ES256")
        );
        List<String> algorithms = algorithmOptions.get(random.nextInt(algorithmOptions.size()));
        
        return new PasskeyConfigData(
            rpId,
            rpName,
            allowedOrigins,
            challengeTimeoutMs,
            userVerification,
            attestation,
            authenticatorAttachment,
            residentKey,
            algorithms
        );
    }

    /**
     * Generates a random alphanumeric string of the specified length range.
     */
    private String generateRandomString(int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder sb = new StringBuilder(length);
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Data class to hold passkey configuration for testing.
     */
    private static class PasskeyConfigData {
        final String rpId;
        final String rpName;
        final List<String> allowedOrigins;
        final long challengeTimeoutMs;
        final String userVerification;
        final String attestation;
        final String authenticatorAttachment;
        final String residentKey;
        final List<String> algorithms;

        PasskeyConfigData(
            String rpId,
            String rpName,
            List<String> allowedOrigins,
            long challengeTimeoutMs,
            String userVerification,
            String attestation,
            String authenticatorAttachment,
            String residentKey,
            List<String> algorithms
        ) {
            this.rpId = rpId;
            this.rpName = rpName;
            this.allowedOrigins = allowedOrigins;
            this.challengeTimeoutMs = challengeTimeoutMs;
            this.userVerification = userVerification;
            this.attestation = attestation;
            this.authenticatorAttachment = authenticatorAttachment;
            this.residentKey = residentKey;
            this.algorithms = algorithms;
        }
    }
}
