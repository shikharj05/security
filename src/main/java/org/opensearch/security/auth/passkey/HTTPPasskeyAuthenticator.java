/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

/**
 * HTTP authenticator for WebAuthn/FIDO2 passkey authentication.
 * Extracts WebAuthn assertions from HTTP requests and validates them.
 */
public class HTTPPasskeyAuthenticator implements HTTPAuthenticator {

    private static final Logger log = LogManager.getLogger(HTTPPasskeyAuthenticator.class);
    private static final String PASSKEY_TYPE = "passkey";
    
    private final ChallengeStore challengeStore;

    /**
     * Constructor required by OpenSearch Security plugin framework.
     * 
     * @param settings OpenSearch settings
     * @param configPath Path to configuration directory
     */
    public HTTPPasskeyAuthenticator(final Settings settings, final Path configPath) {
        // For now, use in-memory challenge store
        // In production, this should be injected or configured
        this.challengeStore = new InMemoryChallengeStore();
        log.info("HTTPPasskeyAuthenticator initialized");
    }

    /**
     * Constructor for testing with injectable dependencies.
     * 
     * @param challengeStore The challenge store to use
     */
    public HTTPPasskeyAuthenticator(ChallengeStore challengeStore) {
        this.challengeStore = challengeStore;
    }

    @Override
    public String getType() {
        return PASSKEY_TYPE;
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context) 
            throws OpenSearchSecurityException {
        
        try {
            // Check if this is a passkey authentication request
            // WebAuthn assertions are typically sent in the request body as JSON
            String contentType = request.header("Content-Type");
            
            if (contentType == null || !contentType.contains("application/json")) {
                log.debug("Request does not contain JSON content type, skipping passkey authentication");
                return null;
            }

            // Parse the request body to extract WebAuthn assertion
            // The assertion should contain:
            // - credentialId: The credential ID being used
            // - clientDataJSON: Base64URL encoded client data
            // - authenticatorData: Base64URL encoded authenticator data
            // - signature: Base64URL encoded signature
            // - challengeId: The challenge ID to validate against
            
            Map<String, Object> requestBody = parseRequestBody(request);
            
            if (requestBody == null || !requestBody.containsKey("credentialId")) {
                log.debug("Request body does not contain passkey assertion data");
                return null;
            }

            // Extract assertion components
            String credentialId = (String) requestBody.get("credentialId");
            String clientDataJSON = (String) requestBody.get("clientDataJSON");
            String authenticatorData = (String) requestBody.get("authenticatorData");
            String signature = (String) requestBody.get("signature");
            String challengeId = (String) requestBody.get("challengeId");
            String userHandle = (String) requestBody.get("userHandle"); // Optional

            if (credentialId == null || clientDataJSON == null || 
                authenticatorData == null || signature == null || challengeId == null) {
                log.debug("Incomplete passkey assertion data in request");
                return null;
            }

            // Create AuthCredentials with the assertion data as native credentials
            // The backend will validate the assertion
            PasskeyAssertion assertion = new PasskeyAssertion(
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature,
                challengeId,
                userHandle
            );

            // Use credential ID as username placeholder - the backend will resolve the actual username
            AuthCredentials credentials = new AuthCredentials(credentialId, assertion);
            
            // Mark as complete since we have all the data needed for validation
            credentials.markComplete();
            
            log.debug("Successfully extracted passkey assertion for credential: {}", credentialId);
            return credentials;

        } catch (Exception e) {
            log.error("Error extracting passkey credentials", e);
            throw new OpenSearchSecurityException("Failed to extract passkey credentials: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest request, AuthCredentials credentials) {
        // Return a challenge response for WebAuthn authentication
        // This is called when credentials are incomplete or authentication needs another roundtrip
        
        try {
            // Generate a new challenge for authentication
            String challengeId = java.util.UUID.randomUUID().toString();
            byte[] challengeBytes = generateChallenge();
            
            Challenge challenge = new Challenge(
                challengeId,
                challengeBytes,
                null, // username is optional for authentication
                Challenge.ChallengeType.AUTHENTICATION,
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(300), // 5 minute expiry
                null // session ID
            );
            
            challengeStore.storeChallenge(challengeId, challenge);
            
            // Return challenge in response body
            String responseBody = String.format(
                "{\"challenge\":\"%s\",\"challengeId\":\"%s\",\"rpId\":\"opensearch\",\"timeout\":300000}",
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
                challengeId
            );
            
            return Optional.of(
                new SecurityResponse(
                    HttpStatus.SC_UNAUTHORIZED,
                    Map.of("WWW-Authenticate", "Passkey realm=\"OpenSearch Security\""),
                    responseBody,
                    "application/json"
                )
            );
            
        } catch (Exception e) {
            log.error("Error generating passkey challenge", e);
            return Optional.of(
                new SecurityResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    Map.of(),
                    "{\"error\":\"Failed to generate authentication challenge\"}",
                    "application/json"
                )
            );
        }
    }

    /**
     * Parse the request body as JSON.
     * 
     * @param request The security request
     * @return Map of request body fields, or null if parsing fails
     */
    private Map<String, Object> parseRequestBody(SecurityRequest request) {
        // Note: In a real implementation, we would need access to the request body
        // This is a placeholder that shows the expected structure
        // The actual implementation will depend on how SecurityRequest provides access to the body
        
        // For now, return null to indicate we need to implement body parsing
        // This will be completed when we integrate with the REST API endpoints
        return null;
    }

    /**
     * Generate a cryptographically random challenge.
     * 
     * @return Random challenge bytes (32 bytes = 256 bits)
     */
    private byte[] generateChallenge() {
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        return challenge;
    }

    /**
     * Inner class representing a WebAuthn assertion.
     * This is used as native credentials in AuthCredentials.
     */
    public static class PasskeyAssertion {
        private final String credentialId;
        private final String clientDataJSON;
        private final String authenticatorData;
        private final String signature;
        private final String challengeId;
        private final String userHandle;

        public PasskeyAssertion(
            String credentialId,
            String clientDataJSON,
            String authenticatorData,
            String signature,
            String challengeId,
            String userHandle
        ) {
            this.credentialId = credentialId;
            this.clientDataJSON = clientDataJSON;
            this.authenticatorData = authenticatorData;
            this.signature = signature;
            this.challengeId = challengeId;
            this.userHandle = userHandle;
        }

        public String getCredentialId() {
            return credentialId;
        }

        public String getClientDataJSON() {
            return clientDataJSON;
        }

        public String getAuthenticatorData() {
            return authenticatorData;
        }

        public String getSignature() {
            return signature;
        }

        public String getChallengeId() {
            return challengeId;
        }

        public String getUserHandle() {
            return userHandle;
        }
    }
}
