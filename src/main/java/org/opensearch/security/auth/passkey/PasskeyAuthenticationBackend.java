/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

/**
 * Authentication backend for WebAuthn/FIDO2 passkey authentication.
 * Validates passkey assertions and returns authenticated users.
 */
public class PasskeyAuthenticationBackend implements AuthenticationBackend {

    private static final Logger log = LogManager.getLogger(PasskeyAuthenticationBackend.class);

    private final WebAuthnManager webAuthnManager;
    private final PasskeyCredentialRepository credentialRepository;
    private final ChallengeStore challengeStore;
    private final PasskeyAuditLogger auditLogger;

    /**
     * Creates a new PasskeyAuthenticationBackend with explicit dependencies.
     * Used when instantiated directly by the plugin.
     * 
     * @param settings OpenSearch settings
     * @param configPath Path to configuration directory
     * @param webAuthnManager WebAuthn protocol manager
     * @param credentialRepository Repository for passkey credentials
     * @param challengeStore Store for temporary challenges
     * @param auditLog Audit log for logging authentication events
     */
    public PasskeyAuthenticationBackend(
        Settings settings,
        Path configPath,
        WebAuthnManager webAuthnManager,
        PasskeyCredentialRepository credentialRepository,
        ChallengeStore challengeStore,
        AuditLog auditLog
    ) {
        this.webAuthnManager = webAuthnManager;
        this.credentialRepository = credentialRepository;
        this.challengeStore = challengeStore;
        this.auditLogger = new PasskeyAuditLogger(auditLog);
    }

    /**
     * Creates a new PasskeyAuthenticationBackend for reflection-based instantiation.
     * This constructor is used when the backend is loaded through config.yml.
     * 
     * Note: This creates a minimal backend that won't be fully functional until
     * the shared components are injected. For production use, the plugin should
     * instantiate this backend directly with all dependencies.
     * 
     * @param settings OpenSearch settings
     * @param configPath Path to configuration directory
     */
    public PasskeyAuthenticationBackend(Settings settings, Path configPath) {
        // Initialize with default configuration
        // This is used when loaded via reflection from config.yml
        log.warn("PasskeyAuthenticationBackend instantiated via reflection - limited functionality");
        log.warn("For full functionality, the plugin should instantiate this backend directly");
        
        // Create minimal components for basic functionality
        try {
            PasskeyAuthenticationConfig config = new PasskeyAuthenticationConfig(settings, configPath);
            RelyingPartyConfig rpConfig = config.parse();
            this.webAuthnManager = new WebAuthnManager(rpConfig);
            this.challengeStore = new InMemoryChallengeStore();
            
            // Note: CredentialRepository requires Client and ClusterService which aren't available here
            // This is a limitation of reflection-based instantiation
            this.credentialRepository = null;
            this.auditLogger = null;
            
            log.info("PasskeyAuthenticationBackend initialized with minimal configuration");
            log.warn("Credential repository not available - backend will have limited functionality");
        } catch (Exception e) {
            log.error("Failed to initialize PasskeyAuthenticationBackend via reflection", e);
            throw new RuntimeException("Failed to initialize PasskeyAuthenticationBackend", e);
        }
    }

    @Override
    public String getType() {
        return "passkey";
    }

    @Override
    public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
        // Check if backend was properly initialized
        if (credentialRepository == null) {
            log.error("PasskeyAuthenticationBackend not properly initialized - credential repository is null");
            log.error("This backend was likely instantiated via reflection without proper dependency injection");
            log.error("For production use, ensure the plugin instantiates this backend directly");
            throw new OpenSearchSecurityException("Passkey authentication backend not properly configured");
        }
        
        AuthCredentials credentials = context.getCredentials();
        String username = null;
        String credentialId = null;
        
        // Extract the passkey assertion from native credentials
        Object nativeCredentials = credentials.getNativeCredentials();
        if (!(nativeCredentials instanceof HTTPPasskeyAuthenticator.PasskeyAssertion)) {
            throw new OpenSearchSecurityException("Invalid credentials type for passkey authentication");
        }
        
        HTTPPasskeyAuthenticator.PasskeyAssertion assertion = 
            (HTTPPasskeyAuthenticator.PasskeyAssertion) nativeCredentials;
        
        try {
            // 1. Consume and validate challenge from ChallengeStore
            String challengeId = assertion.getChallengeId();
            Optional<Challenge> challengeOpt = challengeStore.consumeChallenge(challengeId);
            
            if (!challengeOpt.isPresent()) {
                log.warn("Challenge not found or already used: {}", challengeId);
                // Note: Cannot log to audit log here as we don't have SecurityRequest in this context
                throw new OpenSearchSecurityException("Invalid or expired challenge");
            }
            
            Challenge challenge = challengeOpt.get();
            
            // Check if challenge has expired
            if (challenge.getExpiresAt().isBefore(Instant.now())) {
                log.warn("Challenge has expired: {}", challengeId);
                throw new OpenSearchSecurityException("Challenge has expired");
            }
            
            // 2. Retrieve stored credential by credential ID
            credentialId = assertion.getCredentialId();
            Optional<PasskeyCredential> credentialOpt = credentialRepository.findByCredentialId(credentialId);
            
            if (!credentialOpt.isPresent()) {
                log.warn("Credential not found: {}", credentialId);
                throw new OpenSearchSecurityException("Unknown credential");
            }
            
            PasskeyCredential credential = credentialOpt.get();
            username = credential.getUsername();
            
            // 3. Verify assertion using WebAuthnManager
            String origin = webAuthnManager.getRelyingPartyConfig().getAllowedOrigins().get(0); // TODO: Get actual origin from request
            
            // Decode credentialId from base64url to bytes
            byte[] credentialIdBytes = Base64.getUrlDecoder().decode(credentialId);
            log.info("Decoded credentialId: {} bytes from string: {}", credentialIdBytes.length, credentialId);
            
            WebAuthnManager.AuthenticationResult result = webAuthnManager.verifyAuthenticationResponse(
                assertion.getClientDataJSON(),
                assertion.getAuthenticatorData(),
                assertion.getSignature(),
                challenge.getChallengeBytes(),
                origin,
                credentialIdBytes,
                credential.getPublicKey(),
                credential.getSignatureCounter()
            );
            
            if (!result.isSuccess()) {
                log.warn("Authentication verification failed for credential {}: {}", credentialId, result.getErrorMessage());
                throw new OpenSearchSecurityException("Authentication verification failed: " + result.getErrorMessage());
            }
            
            // 4. Check signature counter for clone detection (if supported)
            if (result.getSignatureCounter() > 0) {
                if (result.getSignatureCounter() <= credential.getSignatureCounter()) {
                    log.error("Signature counter regression detected for credential {}: stored={}, received={}", 
                        credentialId, credential.getSignatureCounter(), result.getSignatureCounter());
                    throw new OpenSearchSecurityException("Possible credential cloning detected");
                }
                
                // Update signature counter
                credentialRepository.updateSignatureCounter(credentialId, result.getSignatureCounter());
            }
            
            // 5. Update credential last used timestamp
            credentialRepository.updateLastUsed(credentialId);
            
            // 6. Create and return User principal with roles
            // Note: Audit logging for authentication happens in the REST layer where SecurityRequest is available
            // Backend roles come from the credentials (if set by role mapping)
            // Security roles will be mapped by the authorization backend
            ImmutableSet<String> backendRoles = credentials.getBackendRoles().isEmpty() 
                ? ImmutableSet.of() 
                : ImmutableSet.copyOf(credentials.getBackendRoles());
            
            ImmutableSet<String> securityRoles = credentials.getSecurityRoles().isEmpty()
                ? ImmutableSet.of()
                : ImmutableSet.copyOf(credentials.getSecurityRoles());
            
            ImmutableMap<String, String> attributes = credentials.getAttributes().isEmpty()
                ? ImmutableMap.of()
                : ImmutableMap.copyOf(credentials.getAttributes());
            
            User user = new User(
                username,
                backendRoles,
                securityRoles,
                null, // requested tenant
                attributes,
                false // not injected
            );
            
            log.info("Successfully authenticated user {} with passkey credential {}", username, credentialId);
            return user;
            
        } catch (WebAuthnException e) {
            log.error("WebAuthn verification error", e);
            throw new OpenSearchSecurityException("Authentication failed: " + e.getMessage(), e);
        } catch (OpenSearchSecurityException e) {
            // Already logged, just rethrow
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during passkey authentication", e);
            throw new OpenSearchSecurityException("Authentication failed: " + e.getMessage(), e);
        }
    }
}
