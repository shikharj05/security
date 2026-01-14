/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.filter.SecurityRequest;

/**
 * Audit logger for passkey authentication events.
 * Integrates with OpenSearch Security audit log framework to log
 * passkey-specific events including registration, authentication,
 * and credential management operations.
 */
public class PasskeyAuditLogger {
    
    private static final Logger log = LogManager.getLogger(PasskeyAuditLogger.class);
    
    private final AuditLog auditLog;
    
    /**
     * Passkey-specific event types for audit logging
     */
    public enum PasskeyEventType {
        REGISTRATION_SUCCESS,
        REGISTRATION_FAILURE,
        AUTHENTICATION_SUCCESS,
        AUTHENTICATION_FAILURE,
        CREDENTIAL_DELETED,
        CREDENTIAL_UPDATED
    }
    
    public PasskeyAuditLogger(AuditLog auditLog) {
        this.auditLog = auditLog;
    }
    
    /**
     * Log a successful passkey registration
     * 
     * @param username The username that registered the passkey
     * @param credentialId The credential ID (base64url encoded)
     * @param request The security request context
     */
    public void logRegistrationSuccess(
        String username,
        String credentialId,
        SecurityRequest request
    ) {
        // Use the standard authenticated event for successful registration
        auditLog.logSucceededLogin(username, false, username, request);
        
        log.info("Passkey registration successful for user: {}, credential: {}", username, credentialId);
    }
    
    /**
     * Log a failed passkey registration
     * 
     * @param username The username attempting registration (may be null)
     * @param failureReason The reason for failure
     * @param request The security request context
     */
    public void logRegistrationFailure(
        String username,
        String failureReason,
        SecurityRequest request
    ) {
        // Use the standard failed login event for failed registration
        String effectiveUser = username != null ? username : "unknown";
        auditLog.logFailedLogin(effectiveUser, false, effectiveUser, request);
        
        log.warn("Passkey registration failed for user: {}, reason: {}", username, sanitizeFailureReason(failureReason));
    }
    
    /**
     * Log a successful passkey authentication
     * 
     * @param username The authenticated username
     * @param credentialId The credential ID used
     * @param request The security request context
     */
    public void logAuthenticationSuccess(
        String username,
        String credentialId,
        SecurityRequest request
    ) {
        // Use the standard authenticated event for successful authentication
        auditLog.logSucceededLogin(username, false, username, request);
        
        log.info("Passkey authentication successful for user: {}, credential: {}", username, credentialId);
    }
    
    /**
     * Log a failed passkey authentication
     * 
     * @param username The username attempting authentication (may be null)
     * @param credentialId The credential ID attempted (may be null)
     * @param failureReason The reason for failure
     * @param request The security request context
     */
    public void logAuthenticationFailure(
        String username,
        String credentialId,
        String failureReason,
        SecurityRequest request
    ) {
        // Use the standard failed login event for failed authentication
        String effectiveUser = username != null ? username : "unknown";
        auditLog.logFailedLogin(effectiveUser, false, effectiveUser, request);
        
        log.warn("Passkey authentication failed for user: {}, credential: {}, reason: {}", 
            username, credentialId, sanitizeFailureReason(failureReason));
    }
    
    /**
     * Log a credential deletion event
     * 
     * @param username The user who owns the credential
     * @param credentialId The credential ID being deleted
     * @param request The security request context
     */
    public void logCredentialDeleted(
        String username,
        String credentialId,
        SecurityRequest request
    ) {
        // Log as a granted privileges event (user successfully performed an action)
        auditLog.logGrantedPrivileges(username, request);
        
        log.info("Passkey credential deleted for user: {}, credential: {}", username, credentialId);
    }
    
    /**
     * Log a credential update event
     * 
     * @param username The user who owns the credential
     * @param credentialId The credential ID being updated
     * @param request The security request context
     */
    public void logCredentialUpdated(
        String username,
        String credentialId,
        SecurityRequest request
    ) {
        // Log as a granted privileges event (user successfully performed an action)
        auditLog.logGrantedPrivileges(username, request);
        
        log.info("Passkey credential updated for user: {}, credential: {}", username, credentialId);
    }
    
    /**
     * Sanitize failure reasons to ensure no sensitive cryptographic material is logged
     */
    private String sanitizeFailureReason(String reason) {
        if (reason == null) {
            return "Unknown error";
        }
        
        // Remove any potential sensitive data patterns
        String sanitized = reason;
        
        // Remove base64-encoded data that might be challenges or keys
        sanitized = sanitized.replaceAll("[A-Za-z0-9+/]{40,}={0,2}", "[REDACTED_DATA]");
        
        // Remove hex-encoded data
        sanitized = sanitized.replaceAll("0x[0-9a-fA-F]{32,}", "[REDACTED_HEX]");
        
        // Keep the error message but sanitize potential sensitive content
        return sanitized;
    }
}
