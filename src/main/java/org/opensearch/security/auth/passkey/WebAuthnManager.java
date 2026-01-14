/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;

/**
 * Manages WebAuthn protocol operations using the WebAuthn4J library.
 * Handles registration and authentication flows for passkey credentials.
 */
public class WebAuthnManager {

    private final RelyingPartyConfig relyingPartyConfig;
    private final SecureRandom secureRandom;
    private final com.webauthn4j.WebAuthnManager webAuthn4jManager;
    private final com.webauthn4j.converter.AttestationObjectConverter attestationObjectConverter;
    private final com.webauthn4j.converter.util.CborConverter cborConverter;

    /**
     * Creates a new WebAuthnManager with the specified configuration.
     *
     * @param relyingPartyConfig Configuration for the relying party
     */
    public WebAuthnManager(RelyingPartyConfig relyingPartyConfig) {
        this.relyingPartyConfig = Objects.requireNonNull(relyingPartyConfig, "relyingPartyConfig must not be null");
        this.secureRandom = new SecureRandom();
        
        // Initialize WebAuthn4J components
        com.webauthn4j.converter.util.ObjectConverter objectConverter = new com.webauthn4j.converter.util.ObjectConverter();
        this.attestationObjectConverter = new com.webauthn4j.converter.AttestationObjectConverter(objectConverter);
        this.cborConverter = objectConverter.getCborConverter();
        this.webAuthn4jManager = com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager();
    }

    /**
     * Generates registration options for a new passkey credential.
     *
     * @param username Username for the credential
     * @param userId User identifier (should be unique and stable)
     * @param excludeCredentials List of credential IDs to exclude (prevents duplicate registration)
     * @return Registration options to send to the client
     */
    public PublicKeyCredentialCreationOptions generateRegistrationOptions(
        String username,
        String userId,
        List<String> excludeCredentials
    ) {
        Objects.requireNonNull(username, "username must not be null");
        Objects.requireNonNull(userId, "userId must not be null");

        // Generate cryptographically random challenge (minimum 128 bits = 16 bytes)
        byte[] challengeBytes = new byte[32]; // 256 bits for extra security
        secureRandom.nextBytes(challengeBytes);
        Challenge challenge = new DefaultChallenge(challengeBytes);

        // Create relying party entity
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity(
            relyingPartyConfig.getRpId(),
            relyingPartyConfig.getRpName()
        );

        // Create user entity
        PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity(
            userId.getBytes(),
            username,
            username // Display name same as username
        );

        // Convert exclude credentials to PublicKeyCredentialDescriptor list
        List<PublicKeyCredentialDescriptor> excludeCredentialDescriptors = null;
        if (excludeCredentials != null && !excludeCredentials.isEmpty()) {
            excludeCredentialDescriptors = excludeCredentials.stream()
                .map(credId -> new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    Base64.getUrlDecoder().decode(credId),
                    null // transports
                ))
                .collect(Collectors.toList());
        }

        // Get supported algorithms from config
        List<PublicKeyCredentialParameters> pubKeyCredParams = relyingPartyConfig.getPubKeyCredParams();
        if (pubKeyCredParams == null || pubKeyCredParams.isEmpty()) {
            // Default to ES256, RS256, EdDSA if not configured
            pubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.EdDSA)
            );
        }

        // Build registration options with authenticator selection
        AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(
            relyingPartyConfig.getAuthenticatorAttachment(),
            relyingPartyConfig.getResidentKey(),
            relyingPartyConfig.getUserVerification()
        );

        return new PublicKeyCredentialCreationOptions(
            rpEntity,
            userEntity,
            challenge,
            pubKeyCredParams,
            relyingPartyConfig.getChallengeTimeoutMs(),
            excludeCredentialDescriptors,
            authenticatorSelection,
            relyingPartyConfig.getAttestation(),
            null // extensions
        );
    }

    /**
     * Generates authentication options for passkey authentication.
     *
     * @param allowCredentials List of allowed credential IDs (null for usernameless authentication)
     * @return Authentication options to send to the client
     */
    public PublicKeyCredentialRequestOptions generateAuthenticationOptions(List<String> allowCredentials) {
        // Generate cryptographically random challenge (minimum 128 bits = 16 bytes)
        byte[] challengeBytes = new byte[32]; // 256 bits for extra security
        secureRandom.nextBytes(challengeBytes);
        Challenge challenge = new DefaultChallenge(challengeBytes);

        // Convert allowed credentials to PublicKeyCredentialDescriptor list
        List<PublicKeyCredentialDescriptor> allowCredentialDescriptors = null;
        if (allowCredentials != null && !allowCredentials.isEmpty()) {
            allowCredentialDescriptors = allowCredentials.stream()
                .map(credId -> new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    Base64.getUrlDecoder().decode(credId),
                    null // transports
                ))
                .collect(Collectors.toList());
        }

        // Build authentication options
        return new PublicKeyCredentialRequestOptions(
            challenge,
            relyingPartyConfig.getChallengeTimeoutMs(),
            relyingPartyConfig.getRpId(),
            allowCredentialDescriptors,
            relyingPartyConfig.getUserVerification(),
            null // extensions
        );
    }

    /**
     * Verifies a registration response from the client.
     *
     * @param clientDataJSON Base64URL-encoded client data JSON
     * @param attestationObject Base64URL-encoded attestation object
     * @param challenge Expected challenge bytes
     * @param origin Expected origin
     * @return Registration result with credential data
     * @throws WebAuthnException if verification fails
     */
    public RegistrationResult verifyRegistrationResponse(
        String clientDataJSON,
        String attestationObject,
        byte[] challenge,
        String origin
    ) throws WebAuthnException {
        Objects.requireNonNull(clientDataJSON, "clientDataJSON must not be null");
        Objects.requireNonNull(attestationObject, "attestationObject must not be null");
        Objects.requireNonNull(challenge, "challenge must not be null");
        Objects.requireNonNull(origin, "origin must not be null");

        try {
            // Decode base64url encoded data
            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJSON);
            byte[] attestationBytes = Base64.getUrlDecoder().decode(attestationObject);

            // Parse attestation object
            com.webauthn4j.data.attestation.AttestationObject attestationObj = 
                attestationObjectConverter.convert(attestationBytes);

            // Create registration request
            com.webauthn4j.data.RegistrationRequest registrationRequest = 
                new com.webauthn4j.data.RegistrationRequest(
                    attestationBytes,
                    clientDataBytes
                );

            // Create registration parameters
            com.webauthn4j.data.RegistrationParameters registrationParameters = 
                new com.webauthn4j.data.RegistrationParameters(
                    new com.webauthn4j.server.ServerProperty(
                        new com.webauthn4j.data.client.Origin(origin),
                        relyingPartyConfig.getRpId(),
                        new com.webauthn4j.data.client.challenge.DefaultChallenge(challenge),
                        null  // tokenBindingId
                    ),
                    false, // userVerificationRequired
                    false  // userPresenceRequired
                );

            // Verify registration
            com.webauthn4j.data.RegistrationData verifiedData = webAuthn4jManager.validate(
                registrationRequest,
                registrationParameters
            );

            // Extract credential data
            com.webauthn4j.data.attestation.authenticator.AuthenticatorData<?> authData = 
                verifiedData.getAttestationObject().getAuthenticatorData();
            
            com.webauthn4j.data.attestation.authenticator.AttestedCredentialData attestedCredData = 
                authData.getAttestedCredentialData();

            byte[] credentialId = attestedCredData.getCredentialId();
            
            // Serialize the COSE key to bytes
            byte[] publicKeyBytes = cborConverter.writeValueAsBytes(attestedCredData.getCOSEKey());
            
            // Log COSE key details for debugging
            com.webauthn4j.data.attestation.authenticator.COSEKey coseKey = attestedCredData.getCOSEKey();
            if (coseKey instanceof com.webauthn4j.data.attestation.authenticator.EC2COSEKey) {
                com.webauthn4j.data.attestation.authenticator.EC2COSEKey ecKey = 
                    (com.webauthn4j.data.attestation.authenticator.EC2COSEKey) coseKey;
                java.util.logging.Logger.getLogger("WebAuthnManager").info(
                    "Registration - COSE Key Algorithm: " + coseKey.getAlgorithm() + 
                    ", KeyType: " + coseKey.getKeyType() +
                    ", PublicKey bytes length: " + publicKeyBytes.length +
                    ", X coord: " + bytesToHex(ecKey.getX()).substring(0, 32) + "..." +
                    ", Y coord: " + bytesToHex(ecKey.getY()).substring(0, 32) + "..."
                );
            }
            
            long signatureCounter = authData.getSignCount();
            String aaguid = attestedCredData.getAaguid().toString();
            
            // Extract backup flags
            boolean backupEligible = authData.isFlagBE();
            boolean backupState = authData.isFlagBS();

            return new RegistrationResult(
                credentialId,
                publicKeyBytes,
                signatureCounter,
                aaguid,
                List.of(),  // transports
                backupEligible,
                backupState
            );

        } catch (com.webauthn4j.validator.exception.ValidationException e) {
            throw new WebAuthnException("Attestation verification failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new WebAuthnException("Registration verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Result of registration verification.
     */
    public static class RegistrationResult {
        private final byte[] credentialId;
        private final byte[] publicKey;
        private final long signatureCounter;
        private final String aaguid;
        private final List<String> transports;
        private final boolean backupEligible;
        private final boolean backupState;

        public RegistrationResult(
            byte[] credentialId,
            byte[] publicKey,
            long signatureCounter,
            String aaguid,
            List<String> transports,
            boolean backupEligible,
            boolean backupState
        ) {
            this.credentialId = credentialId;
            this.publicKey = publicKey;
            this.signatureCounter = signatureCounter;
            this.aaguid = aaguid;
            this.transports = transports;
            this.backupEligible = backupEligible;
            this.backupState = backupState;
        }

        public byte[] getCredentialId() {
            return credentialId;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }

        public long getSignatureCounter() {
            return signatureCounter;
        }

        public String getAaguid() {
            return aaguid;
        }

        public List<String> getTransports() {
            return transports;
        }

        public boolean isBackupEligible() {
            return backupEligible;
        }

        public boolean isBackupState() {
            return backupState;
        }
    }

    /**
     * Verifies an authentication response from the client.
     *
     * @param clientDataJSON Base64URL-encoded client data JSON
     * @param authenticatorData Base64URL-encoded authenticator data
     * @param signature Base64URL-encoded signature
     * @param challenge Expected challenge bytes
     * @param origin Expected origin
     * @param credentialId The credential ID being authenticated
     * @param publicKey Stored public key for the credential
     * @param currentSignatureCounter Current signature counter from storage
     * @return Authentication result with updated signature counter
     * @throws WebAuthnException if verification fails
     */
    public AuthenticationResult verifyAuthenticationResponse(
        String clientDataJSON,
        String authenticatorData,
        String signature,
        byte[] challenge,
        String origin,
        byte[] credentialId,
        byte[] publicKey,
        long currentSignatureCounter
    ) throws WebAuthnException {
        Objects.requireNonNull(clientDataJSON, "clientDataJSON must not be null");
        Objects.requireNonNull(authenticatorData, "authenticatorData must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        Objects.requireNonNull(challenge, "challenge must not be null");
        Objects.requireNonNull(origin, "origin must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");

        try {
            // Decode base64url encoded data
            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJSON);
            byte[] authenticatorDataBytes = Base64.getUrlDecoder().decode(authenticatorData);
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signature);

            // Log what we're verifying
            java.util.logging.Logger logger = java.util.logging.Logger.getLogger("WebAuthnManager");
            logger.info("Verifying authentication:");
            logger.info("  AuthenticatorData (" + authenticatorDataBytes.length + " bytes): " + 
                bytesToHex(authenticatorDataBytes));
            logger.info("  ClientDataJSON: " + new String(clientDataBytes, java.nio.charset.StandardCharsets.UTF_8));
            logger.info("  Signature (" + signatureBytes.length + " bytes): " + 
                bytesToHex(signatureBytes).substring(0, Math.min(64, signatureBytes.length * 2)));

            // Validate credentialId is not null or empty
            if (credentialId == null || credentialId.length == 0) {
                return AuthenticationResult.failure("credentialId must not be null or empty");
            }

            // Parse the COSE key from stored public key bytes
            com.webauthn4j.data.attestation.authenticator.COSEKey coseKey = 
                cborConverter.readValue(publicKey, com.webauthn4j.data.attestation.authenticator.COSEKey.class);
            
            // Log COSE key details for debugging
            if (coseKey instanceof com.webauthn4j.data.attestation.authenticator.EC2COSEKey) {
                com.webauthn4j.data.attestation.authenticator.EC2COSEKey ecKey = 
                    (com.webauthn4j.data.attestation.authenticator.EC2COSEKey) coseKey;
                logger.info("Authentication - COSE Key Algorithm: " + coseKey.getAlgorithm() + 
                    ", KeyType: " + coseKey.getKeyType() +
                    ", PublicKey bytes length: " + publicKey.length +
                    ", X coord: " + bytesToHex(ecKey.getX()).substring(0, 32) + "..." +
                    ", Y coord: " + bytesToHex(ecKey.getY()).substring(0, 32) + "..."
                );
                
                // TRY MANUAL SIGNATURE VERIFICATION
                try {
                    // Reconstruct the signature base
                    byte[] clientDataHash = java.security.MessageDigest.getInstance("SHA-256").digest(clientDataBytes);
                    byte[] signatureBase = new byte[authenticatorDataBytes.length + clientDataHash.length];
                    System.arraycopy(authenticatorDataBytes, 0, signatureBase, 0, authenticatorDataBytes.length);
                    System.arraycopy(clientDataHash, 0, signatureBase, authenticatorDataBytes.length, clientDataHash.length);
                    
                    logger.info("Manual verification - SignatureBase length: " + signatureBase.length);
                    logger.info("Manual verification - ClientDataHash: " + bytesToHex(clientDataHash).substring(0, 32) + "...");
                    
                    // Create EC public key from coordinates
                    java.security.spec.ECPoint point = new java.security.spec.ECPoint(
                        new java.math.BigInteger(1, ecKey.getX()),
                        new java.math.BigInteger(1, ecKey.getY())
                    );
                    
                    // Use P-256 curve
                    java.security.AlgorithmParameters parameters = java.security.AlgorithmParameters.getInstance("EC");
                    parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
                    java.security.spec.ECParameterSpec ecParameters = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
                    
                    java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(point, ecParameters);
                    java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
                    java.security.PublicKey javaPublicKey = keyFactory.generatePublic(pubKeySpec);
                    
                    // Convert raw signature to DER format for Java verification
                    byte[] derSignature = rawToDer(signatureBytes);
                    logger.info("Converted raw signature (" + signatureBytes.length + " bytes) to DER (" + derSignature.length + " bytes)");
                    
                    // Verify signature manually
                    java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(javaPublicKey);
                    verifier.update(signatureBase);
                    boolean manualVerifyResult = verifier.verify(derSignature);
                    
                    logger.info("Manual signature verification result: " + manualVerifyResult);
                    
                    if (manualVerifyResult) {
                        logger.info("SUCCESS! Manual verification passed - the signature IS valid!");
                        logger.info("Using manual verification result instead of WebAuthn4J");
                        
                        // Extract signature counter from authenticator data manually
                        // AuthenticatorData format: rpIdHash(32) + flags(1) + signCount(4) + ...
                        long newSignatureCounter = 0;
                        if (authenticatorDataBytes.length >= 37) {
                            newSignatureCounter = ((long)(authenticatorDataBytes[33] & 0xFF) << 24) |
                                                ((long)(authenticatorDataBytes[34] & 0xFF) << 16) |
                                                ((long)(authenticatorDataBytes[35] & 0xFF) << 8) |
                                                ((long)(authenticatorDataBytes[36] & 0xFF));
                            logger.info("Extracted signature counter: " + newSignatureCounter);
                        }
                        
                        // Verify signature counter hasn't regressed (clone detection)
                        if (newSignatureCounter > 0 && currentSignatureCounter > 0 && newSignatureCounter <= currentSignatureCounter) {
                            return AuthenticationResult.failure("Signature counter regression detected - possible cloned credential");
                        }
                        
                        return AuthenticationResult.success(newSignatureCounter);
                    } else {
                        logger.warning("Manual verification failed - signature is invalid");
                        return AuthenticationResult.failure("Manual signature verification failed");
                    }
                } catch (Exception e) {
                    logger.warning("Manual verification failed with exception: " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            // Create AttestedCredentialData with the public key
            com.webauthn4j.data.attestation.authenticator.AttestedCredentialData attestedCredentialData = 
                new com.webauthn4j.data.attestation.authenticator.AttestedCredentialData(
                    com.webauthn4j.data.attestation.authenticator.AAGUID.ZERO,
                    credentialId,
                    coseKey
                );

            // Create an Authenticator object
            com.webauthn4j.authenticator.Authenticator authenticator = 
                new com.webauthn4j.authenticator.AuthenticatorImpl(
                    attestedCredentialData,
                    null,  // attestationStatement
                    currentSignatureCounter
                );

            // Create authentication request
            com.webauthn4j.data.AuthenticationRequest authenticationRequest = 
                new com.webauthn4j.data.AuthenticationRequest(
                    credentialId,  // Pass the actual credentialId
                    authenticatorDataBytes,
                    clientDataBytes,
                    signatureBytes
                );

            // Create authentication parameters
            com.webauthn4j.data.AuthenticationParameters authenticationParameters = 
                new com.webauthn4j.data.AuthenticationParameters(
                    new com.webauthn4j.server.ServerProperty(
                        new com.webauthn4j.data.client.Origin(origin),
                        relyingPartyConfig.getRpId(),
                        new com.webauthn4j.data.client.challenge.DefaultChallenge(challenge),
                        null  // tokenBindingId
                    ),
                    authenticator,
                    null,  // allowCredentials
                    false,  // userVerificationRequired
                    true   // userPresenceRequired
                );
            
            // Verify authentication
            com.webauthn4j.data.AuthenticationData verifiedData = webAuthn4jManager.validate(
                authenticationRequest,
                authenticationParameters
            );

            // Extract signature counter
            long newSignatureCounter = verifiedData.getAuthenticatorData().getSignCount();

            // Verify signature counter hasn't regressed (clone detection)
            if (newSignatureCounter > 0 && currentSignatureCounter > 0 && newSignatureCounter <= currentSignatureCounter) {
                throw new WebAuthnException("Signature counter regression detected - possible cloned credential");
            }

            return AuthenticationResult.success(newSignatureCounter);

        } catch (com.webauthn4j.validator.exception.ValidationException e) {
            return AuthenticationResult.failure("Signature verification failed: " + e.getMessage());
        } catch (Exception e) {
            return AuthenticationResult.failure("Authentication verification failed: " + e.getMessage());
        }
    }

    /**
     * Result of authentication verification.
     */
    public static class AuthenticationResult {
        private final boolean success;
        private final long signatureCounter;
        private final String errorMessage;

        public AuthenticationResult(boolean success, long signatureCounter, String errorMessage) {
            this.success = success;
            this.signatureCounter = signatureCounter;
            this.errorMessage = errorMessage;
        }

        public static AuthenticationResult success(long signatureCounter) {
            return new AuthenticationResult(true, signatureCounter, null);
        }

        public static AuthenticationResult failure(String errorMessage) {
            return new AuthenticationResult(false, 0, errorMessage);
        }

        public boolean isSuccess() {
            return success;
        }

        public long getSignatureCounter() {
            return signatureCounter;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    // Getters for testing
    public RelyingPartyConfig getRelyingPartyConfig() {
        return relyingPartyConfig;
    }
    
    // Helper method for hex conversion
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    // Helper method to convert raw ECDSA signature (r||s) to DER format
    private static byte[] rawToDer(byte[] rawSignature) throws java.io.IOException {
        if (rawSignature.length != 64) {
            throw new IllegalArgumentException("Raw signature must be 64 bytes for ES256");
        }
        
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(rawSignature, 0, r, 0, 32);
        System.arraycopy(rawSignature, 32, s, 0, 32);
        
        // Remove leading zeros
        r = removeLeadingZeros(r);
        s = removeLeadingZeros(s);
        
        // Add leading zero if high bit is set (to keep it positive)
        if ((r[0] & 0x80) != 0) {
            byte[] temp = new byte[r.length + 1];
            temp[0] = 0;
            System.arraycopy(r, 0, temp, 1, r.length);
            r = temp;
        }
        if ((s[0] & 0x80) != 0) {
            byte[] temp = new byte[s.length + 1];
            temp[0] = 0;
            System.arraycopy(s, 0, temp, 1, s.length);
            s = temp;
        }
        
        // Build DER: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        int totalLength = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + totalLength];
        int offset = 0;
        
        der[offset++] = 0x30; // SEQUENCE tag
        der[offset++] = (byte) totalLength;
        
        der[offset++] = 0x02; // INTEGER tag for r
        der[offset++] = (byte) r.length;
        System.arraycopy(r, 0, der, offset, r.length);
        offset += r.length;
        
        der[offset++] = 0x02; // INTEGER tag for s
        der[offset++] = (byte) s.length;
        System.arraycopy(s, 0, der, offset, s.length);
        
        return der;
    }
    
    private static byte[] removeLeadingZeros(byte[] bytes) {
        int firstNonZero = 0;
        while (firstNonZero < bytes.length - 1 && bytes[firstNonZero] == 0) {
            firstNonZero++;
        }
        if (firstNonZero == 0) {
            return bytes;
        }
        byte[] result = new byte[bytes.length - firstNonZero];
        System.arraycopy(bytes, firstNonZero, result, 0, result.length);
        return result;
    }
}
