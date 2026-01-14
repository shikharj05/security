/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

import org.opensearch.common.settings.Settings;

/**
 * Configuration parser for passkey authentication.
 * Parses settings from config.yml and creates a RelyingPartyConfig instance.
 */
public class PasskeyAuthenticationConfig {

    private static final String CONFIG_PREFIX = "config.";
    
    // Configuration keys
    private static final String RP_ID_KEY = CONFIG_PREFIX + "rp_id";
    private static final String RP_NAME_KEY = CONFIG_PREFIX + "rp_name";
    private static final String ALLOWED_ORIGINS_KEY = CONFIG_PREFIX + "allowed_origins";
    private static final String CHALLENGE_TIMEOUT_MS_KEY = CONFIG_PREFIX + "challenge_timeout_ms";
    private static final String USER_VERIFICATION_KEY = CONFIG_PREFIX + "user_verification";
    private static final String ATTESTATION_KEY = CONFIG_PREFIX + "attestation";
    private static final String AUTHENTICATOR_ATTACHMENT_KEY = CONFIG_PREFIX + "authenticator_attachment";
    private static final String RESIDENT_KEY_KEY = CONFIG_PREFIX + "resident_key";
    private static final String ALGORITHMS_KEY = CONFIG_PREFIX + "algorithms";
    
    // Default values
    private static final long DEFAULT_CHALLENGE_TIMEOUT_MS = 300000L; // 5 minutes
    private static final String DEFAULT_USER_VERIFICATION = "preferred";
    private static final String DEFAULT_ATTESTATION = "none";
    private static final String DEFAULT_RESIDENT_KEY = "preferred";
    private static final List<String> DEFAULT_ALGORITHMS = List.of("ES256", "RS256", "EdDSA");

    private final Settings settings;
    private final Path configPath;

    public PasskeyAuthenticationConfig(Settings settings, Path configPath) {
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.configPath = Objects.requireNonNull(configPath, "configPath must not be null");
    }

    /**
     * Parse the configuration and create a RelyingPartyConfig instance.
     * 
     * @return RelyingPartyConfig with parsed settings
     * @throws IllegalArgumentException if required configuration is missing or invalid
     */
    public RelyingPartyConfig parse() {
        // Parse required fields
        String rpId = settings.get(RP_ID_KEY);
        if (rpId == null || rpId.trim().isEmpty()) {
            throw new IllegalArgumentException("Relying party ID (rp_id) is required");
        }

        String rpName = settings.get(RP_NAME_KEY);
        if (rpName == null || rpName.trim().isEmpty()) {
            throw new IllegalArgumentException("Relying party name (rp_name) is required");
        }

        List<String> allowedOrigins = settings.getAsList(ALLOWED_ORIGINS_KEY);
        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            throw new IllegalArgumentException("At least one allowed origin is required");
        }

        // Parse optional fields with defaults
        long challengeTimeoutMs = settings.getAsLong(CHALLENGE_TIMEOUT_MS_KEY, DEFAULT_CHALLENGE_TIMEOUT_MS);
        if (challengeTimeoutMs <= 0) {
            throw new IllegalArgumentException("Challenge timeout must be positive");
        }

        UserVerificationRequirement userVerification = parseUserVerification(
            settings.get(USER_VERIFICATION_KEY, DEFAULT_USER_VERIFICATION)
        );

        AttestationConveyancePreference attestation = parseAttestation(
            settings.get(ATTESTATION_KEY, DEFAULT_ATTESTATION)
        );

        AuthenticatorAttachment authenticatorAttachment = parseAuthenticatorAttachment(
            settings.get(AUTHENTICATOR_ATTACHMENT_KEY)
        );

        ResidentKeyRequirement residentKey = parseResidentKey(
            settings.get(RESIDENT_KEY_KEY, DEFAULT_RESIDENT_KEY)
        );

        List<PublicKeyCredentialParameters> pubKeyCredParams = parseAlgorithms(
            settings.getAsList(ALGORITHMS_KEY, DEFAULT_ALGORITHMS)
        );

        return new RelyingPartyConfig(
            rpId,
            rpName,
            allowedOrigins,
            challengeTimeoutMs,
            userVerification,
            attestation,
            authenticatorAttachment,
            residentKey,
            pubKeyCredParams
        );
    }

    /**
     * Parse user verification requirement from string.
     */
    private UserVerificationRequirement parseUserVerification(String value) {
        if (value == null) {
            return UserVerificationRequirement.PREFERRED;
        }
        
        try {
            return UserVerificationRequirement.create(value.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid user_verification value: " + value + ". Must be one of: required, preferred, discouraged"
            );
        }
    }

    /**
     * Parse attestation conveyance preference from string.
     */
    private AttestationConveyancePreference parseAttestation(String value) {
        if (value == null) {
            return AttestationConveyancePreference.NONE;
        }
        
        try {
            return AttestationConveyancePreference.create(value.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid attestation value: " + value + ". Must be one of: none, indirect, direct, enterprise"
            );
        }
    }

    /**
     * Parse authenticator attachment from string.
     * Returns null if not specified (allows both platform and cross-platform).
     */
    private AuthenticatorAttachment parseAuthenticatorAttachment(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        
        try {
            return AuthenticatorAttachment.create(value.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid authenticator_attachment value: " + value + ". Must be one of: platform, cross-platform"
            );
        }
    }

    /**
     * Parse resident key requirement from string.
     */
    private ResidentKeyRequirement parseResidentKey(String value) {
        if (value == null) {
            return ResidentKeyRequirement.PREFERRED;
        }
        
        try {
            return ResidentKeyRequirement.create(value.toLowerCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid resident_key value: " + value + ". Must be one of: required, preferred, discouraged"
            );
        }
    }

    /**
     * Parse supported algorithms from list of algorithm names.
     */
    private List<PublicKeyCredentialParameters> parseAlgorithms(List<String> algorithmNames) {
        if (algorithmNames == null || algorithmNames.isEmpty()) {
            algorithmNames = DEFAULT_ALGORITHMS;
        }

        List<PublicKeyCredentialParameters> params = new ArrayList<>();
        
        for (String algName : algorithmNames) {
            COSEAlgorithmIdentifier algorithm = parseAlgorithmName(algName);
            params.add(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, algorithm));
        }

        return params;
    }

    /**
     * Parse algorithm name to COSE algorithm identifier.
     */
    private COSEAlgorithmIdentifier parseAlgorithmName(String algName) {
        if (algName == null || algName.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm name cannot be empty");
        }

        String normalized = algName.trim().toUpperCase();
        
        switch (normalized) {
            case "ES256":
                return COSEAlgorithmIdentifier.ES256;
            case "ES384":
                return COSEAlgorithmIdentifier.ES384;
            case "ES512":
                return COSEAlgorithmIdentifier.ES512;
            case "RS256":
                return COSEAlgorithmIdentifier.RS256;
            case "RS384":
                return COSEAlgorithmIdentifier.RS384;
            case "RS512":
                return COSEAlgorithmIdentifier.RS512;
            case "EDDSA":
                return COSEAlgorithmIdentifier.EdDSA;
            default:
                throw new IllegalArgumentException(
                    "Unsupported algorithm: " + algName + ". Supported algorithms: ES256, ES384, ES512, RS256, RS384, RS512, EdDSA"
                );
        }
    }

    // Getters for testing
    public Settings getSettings() {
        return settings;
    }

    public Path getConfigPath() {
        return configPath;
    }
}
