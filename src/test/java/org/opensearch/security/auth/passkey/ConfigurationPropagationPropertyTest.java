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

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;

import org.opensearch.common.settings.Settings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Property-based tests for configuration propagation.
 * 
 * **Feature: passkey-authentication, Property 37-41: Configuration propagation**
 * **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5**
 * 
 * For any configuration values, they should be correctly propagated to the 
 * RelyingPartyConfig object.
 */
public class ConfigurationPropagationPropertyTest {

    /**
     * Property 37: User verification requirement propagation
     * 
     * For any configuration with user verification set to "required", 
     * authentication options should have user verification set to "required".
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void userVerificationRequirementPropagation() {
        java.util.Random random = new java.util.Random(54); // Fixed seed for reproducibility
        
        String[] userVerificationValues = { "required", "preferred", "discouraged" };
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration
            String userVerification = userVerificationValues[random.nextInt(userVerificationValues.length)];
            
            Settings settings = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example")
                .putList("config.allowed_origins", List.of("https://example.com"))
                .put("config.user_verification", userVerification)
                .build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: User verification should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            UserVerificationRequirement expected = UserVerificationRequirement.create(userVerification);
            assertEquals(
                "User verification requirement should be propagated",
                expected,
                rpConfig.getUserVerification()
            );
        }
    }

    /**
     * Property 38: Attestation preference propagation
     * 
     * For any configuration with attestation requirements, registration options 
     * should include the configured attestation conveyance preference.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void attestationPreferencePropagation() {
        java.util.Random random = new java.util.Random(55); // Fixed seed for reproducibility
        
        String[] attestationValues = { "none", "indirect", "direct", "enterprise" };
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration
            String attestation = attestationValues[random.nextInt(attestationValues.length)];
            
            Settings settings = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example")
                .putList("config.allowed_origins", List.of("https://example.com"))
                .put("config.attestation", attestation)
                .build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: Attestation preference should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            AttestationConveyancePreference expected = AttestationConveyancePreference.create(attestation);
            assertEquals(
                "Attestation preference should be propagated",
                expected,
                rpConfig.getAttestation()
            );
        }
    }

    /**
     * Property 39: Authenticator attachment propagation
     * 
     * For any configuration with authenticator type restrictions, registration 
     * options should include the configured authenticator attachment preference.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void authenticatorAttachmentPropagation() {
        java.util.Random random = new java.util.Random(56); // Fixed seed for reproducibility
        
        String[] attachmentValues = { "platform", "cross-platform", null };
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration
            String attachment = attachmentValues[random.nextInt(attachmentValues.length)];
            
            Settings.Builder settingsBuilder = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example")
                .putList("config.allowed_origins", List.of("https://example.com"));
            
            if (attachment != null) {
                settingsBuilder.put("config.authenticator_attachment", attachment);
            }
            
            Settings settings = settingsBuilder.build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: Authenticator attachment should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            if (attachment == null) {
                assertNull(
                    "Authenticator attachment should be null when not configured",
                    rpConfig.getAuthenticatorAttachment()
                );
            } else {
                AuthenticatorAttachment expected = AuthenticatorAttachment.create(attachment);
                assertEquals(
                    "Authenticator attachment should be propagated",
                    expected,
                    rpConfig.getAuthenticatorAttachment()
                );
            }
        }
    }

    /**
     * Property 40: Timeout propagation
     * 
     * For any configuration with timeout values, generated options should include 
     * the configured timeout in milliseconds.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void timeoutPropagation() {
        java.util.Random random = new java.util.Random(57); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random timeout value (between 30 seconds and 10 minutes)
            long timeout = 30000L + random.nextInt(570000); // 30s to 600s
            
            Settings settings = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example")
                .putList("config.allowed_origins", List.of("https://example.com"))
                .put("config.challenge_timeout_ms", timeout)
                .build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: Timeout should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            assertEquals(
                "Challenge timeout should be propagated",
                timeout,
                rpConfig.getChallengeTimeoutMs()
            );
        }
    }

    /**
     * Property 41: Resident key requirement propagation
     * 
     * For any configuration with resident key requirements, registration options 
     * should include the configured resident key requirement.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void residentKeyRequirementPropagation() {
        java.util.Random random = new java.util.Random(58); // Fixed seed for reproducibility
        
        String[] residentKeyValues = { "required", "preferred", "discouraged" };
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration
            String residentKey = residentKeyValues[random.nextInt(residentKeyValues.length)];
            
            Settings settings = Settings.builder()
                .put("config.rp_id", "example.com")
                .put("config.rp_name", "Example")
                .putList("config.allowed_origins", List.of("https://example.com"))
                .put("config.resident_key", residentKey)
                .build();
            
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: Resident key requirement should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            ResidentKeyRequirement expected = ResidentKeyRequirement.create(residentKey);
            assertEquals(
                "Resident key requirement should be propagated",
                expected,
                rpConfig.getResidentKey()
            );
        }
    }

    /**
     * Property 37-41 (combined): All configuration values propagate correctly
     * 
     * For any complete configuration, all values should be propagated correctly 
     * to the RelyingPartyConfig object.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void allConfigurationValuesPropagateCorrectly() {
        java.util.Random random = new java.util.Random(59); // Fixed seed for reproducibility
        
        String[] userVerificationValues = { "required", "preferred", "discouraged" };
        String[] attestationValues = { "none", "indirect", "direct", "enterprise" };
        String[] attachmentValues = { "platform", "cross-platform" };
        String[] residentKeyValues = { "required", "preferred", "discouraged" };
        String[] algorithmSets = {
            "ES256,RS256",
            "ES256,ES384,RS256",
            "ES256,RS256,EdDSA",
            "ES384,RS384"
        };
        
        for (int i = 0; i < 100; i++) {
            // Generate random configuration values
            String rpId = generateRandomDomain(random);
            String rpName = generateRandomString(random, 5, 20);
            List<String> allowedOrigins = generateRandomOriginsList(random, 1, 3);
            long timeout = 30000L + random.nextInt(570000);
            String userVerification = userVerificationValues[random.nextInt(userVerificationValues.length)];
            String attestation = attestationValues[random.nextInt(attestationValues.length)];
            String attachment = random.nextBoolean() ? attachmentValues[random.nextInt(attachmentValues.length)] : null;
            String residentKey = residentKeyValues[random.nextInt(residentKeyValues.length)];
            String algorithms = algorithmSets[random.nextInt(algorithmSets.length)];
            
            // Build settings
            Settings.Builder settingsBuilder = Settings.builder()
                .put("config.rp_id", rpId)
                .put("config.rp_name", rpName)
                .putList("config.allowed_origins", allowedOrigins)
                .put("config.challenge_timeout_ms", timeout)
                .put("config.user_verification", userVerification)
                .put("config.attestation", attestation)
                .put("config.resident_key", residentKey)
                .putList("config.algorithms", List.of(algorithms.split(",")));
            
            if (attachment != null) {
                settingsBuilder.put("config.authenticator_attachment", attachment);
            }
            
            Settings settings = settingsBuilder.build();
            
            // Parse configuration
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: All values should be propagated correctly
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            assertEquals("RP ID should be propagated", rpId, rpConfig.getRpId());
            assertEquals("RP name should be propagated", rpName, rpConfig.getRpName());
            assertEquals("Allowed origins should be propagated", allowedOrigins, rpConfig.getAllowedOrigins());
            assertEquals("Challenge timeout should be propagated", timeout, rpConfig.getChallengeTimeoutMs());
            assertEquals(
                "User verification should be propagated",
                UserVerificationRequirement.create(userVerification),
                rpConfig.getUserVerification()
            );
            assertEquals(
                "Attestation should be propagated",
                AttestationConveyancePreference.create(attestation),
                rpConfig.getAttestation()
            );
            if (attachment != null) {
                assertEquals(
                    "Authenticator attachment should be propagated",
                    AuthenticatorAttachment.create(attachment),
                    rpConfig.getAuthenticatorAttachment()
                );
            } else {
                assertNull("Authenticator attachment should be null", rpConfig.getAuthenticatorAttachment());
            }
            assertEquals(
                "Resident key should be propagated",
                ResidentKeyRequirement.create(residentKey),
                rpConfig.getResidentKey()
            );
            assertNotNull("Algorithms should be propagated", rpConfig.getPubKeyCredParams());
            assertEquals(
                "Number of algorithms should match",
                algorithms.split(",").length,
                rpConfig.getPubKeyCredParams().size()
            );
        }
    }

    /**
     * Property 37-41 (variant): Default values are used when not configured
     * 
     * For any configuration with missing optional values, default values should be used.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void defaultValuesAreUsedWhenNotConfigured() {
        java.util.Random random = new java.util.Random(60); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Build minimal configuration (only required fields)
            String rpId = generateRandomDomain(random);
            String rpName = generateRandomString(random, 5, 20);
            List<String> allowedOrigins = generateRandomOriginsList(random, 1, 3);
            
            Settings settings = Settings.builder()
                .put("config.rp_id", rpId)
                .put("config.rp_name", rpName)
                .putList("config.allowed_origins", allowedOrigins)
                .build();
            
            // Parse configuration
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, Paths.get("/tmp"));
            RelyingPartyConfig rpConfig = config.parse();
            
            // Assert: Default values should be used
            assertNotNull("RelyingPartyConfig should not be null", rpConfig);
            assertEquals("Default timeout should be 300000ms", 300000L, rpConfig.getChallengeTimeoutMs());
            assertEquals(
                "Default user verification should be PREFERRED",
                UserVerificationRequirement.PREFERRED,
                rpConfig.getUserVerification()
            );
            assertEquals(
                "Default attestation should be NONE",
                AttestationConveyancePreference.NONE,
                rpConfig.getAttestation()
            );
            assertNull(
                "Default authenticator attachment should be null",
                rpConfig.getAuthenticatorAttachment()
            );
            assertEquals(
                "Default resident key should be PREFERRED",
                ResidentKeyRequirement.PREFERRED,
                rpConfig.getResidentKey()
            );
            assertNotNull("Default algorithms should be set", rpConfig.getPubKeyCredParams());
            assertEquals("Default should have 3 algorithms", 3, rpConfig.getPubKeyCredParams().size());
        }
    }

    // Helper methods

    private String generateRandomDomain(java.util.Random random) {
        String label = generateRandomDomainLabel(random);
        String tld = generateRandomTld(random);
        return label + "." + tld;
    }

    private String generateRandomDomainLabel(java.util.Random random) {
        int length = 3 + random.nextInt(10);
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
            char c = random.nextBoolean() ? (char) ('a' + random.nextInt(26)) : (char) ('A' + random.nextInt(26));
            sb.append(c);
        }
        return sb.toString();
    }

    private List<String> generateRandomOriginsList(java.util.Random random, int minSize, int maxSize) {
        int size = minSize + random.nextInt(maxSize - minSize + 1);
        List<String> origins = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            String protocol = random.nextBoolean() ? "https" : "http";
            String domain = generateRandomDomain(random);
            origins.add(protocol + "://" + domain);
        }
        return origins;
    }
}
