/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.rest.BytesRestResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * Property-based tests for error messaging and HTTP status code correctness.
 * 
 * **Feature: passkey-authentication, Property 42: Attestation failure error messaging**
 * **Feature: passkey-authentication, Property 43: Signature failure error messaging**
 * **Feature: passkey-authentication, Property 44: Expired challenge error messaging**
 * **Feature: passkey-authentication, Property 45: Unknown credential error messaging**
 * **Feature: passkey-authentication, Property 46: HTTP status code correctness**
 * **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
 * 
 * For any passkey operation failure, the error response should include appropriate
 * error messaging and HTTP status codes.
 */
public class ErrorMessagingPropertyTest {

    /**
     * Property 42: Attestation failure error messaging
     * 
     * For any registration failure due to invalid attestation, the error response 
     * should indicate attestation verification failure.
     * 
     * This test runs 100 iterations with different attestation failure messages.
     */
    @org.junit.Test
    public void attestationFailureErrorMessaging() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Generate random attestation failure message
            String failureReason = "Attestation verification failed: " + generateRandomReason(i);
            
            // Create attestation verification exception
            PasskeyRegistrationException exception = PasskeyRegistrationException.attestationVerificationFailed(failureReason);
            
            // Create error response
            PasskeyErrorResponse errorResponse = PasskeyErrorResponse.fromException(exception);
            
            // Assert: Error type should be ATTESTATION_VERIFICATION_FAILED
            assertEquals(
                "Error type should be ATTESTATION_VERIFICATION_FAILED",
                PasskeyException.PasskeyErrorType.ATTESTATION_VERIFICATION_FAILED,
                errorResponse.getErrorType()
            );
            
            // Assert: HTTP status should be BAD_REQUEST (400)
            assertEquals(
                "HTTP status should be BAD_REQUEST for attestation failure",
                RestStatus.BAD_REQUEST,
                errorResponse.getHttpStatus()
            );
            
            // Assert: Error message should contain the failure reason
            assertTrue(
                "Error message should contain failure information",
                errorResponse.getReason().contains("Attestation verification failed")
            );
            
            // Assert: Error response should be serializable
            XContentBuilder builder = XContentFactory.jsonBuilder();
            BytesRestResponse restResponse = errorResponse.toRestResponse(builder);
            assertNotNull("REST response should not be null", restResponse);
            assertEquals("REST response status should match", RestStatus.BAD_REQUEST, restResponse.status());
        }
    }

    /**
     * Property 43: Signature failure error messaging
     * 
     * For any authentication failure due to invalid signature, the error response 
     * should indicate signature verification failure.
     * 
     * This test runs 100 iterations with different signature failure messages.
     */
    @org.junit.Test
    public void signatureFailureErrorMessaging() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Generate random signature failure message
            String failureReason = "Signature verification failed: " + generateRandomReason(i);
            
            // Create signature verification exception
            PasskeyAuthenticationException exception = PasskeyAuthenticationException.signatureVerificationFailed(failureReason);
            
            // Create error response
            PasskeyErrorResponse errorResponse = PasskeyErrorResponse.fromException(exception);
            
            // Assert: Error type should be SIGNATURE_VERIFICATION_FAILED
            assertEquals(
                "Error type should be SIGNATURE_VERIFICATION_FAILED",
                PasskeyException.PasskeyErrorType.SIGNATURE_VERIFICATION_FAILED,
                errorResponse.getErrorType()
            );
            
            // Assert: HTTP status should be UNAUTHORIZED (401)
            assertEquals(
                "HTTP status should be UNAUTHORIZED for signature failure",
                RestStatus.UNAUTHORIZED,
                errorResponse.getHttpStatus()
            );
            
            // Assert: Error message should contain the failure reason
            assertTrue(
                "Error message should contain failure information",
                errorResponse.getReason().contains("Signature verification failed")
            );
            
            // Assert: Error response should be serializable
            XContentBuilder builder = XContentFactory.jsonBuilder();
            BytesRestResponse restResponse = errorResponse.toRestResponse(builder);
            assertNotNull("REST response should not be null", restResponse);
            assertEquals("REST response status should match", RestStatus.UNAUTHORIZED, restResponse.status());
        }
    }

    /**
     * Property 44: Expired challenge error messaging
     * 
     * For any authentication failure due to expired challenge, the error response 
     * should indicate the challenge has expired.
     * 
     * This test runs 100 iterations with different expired challenge messages.
     */
    @org.junit.Test
    public void expiredChallengeErrorMessaging() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Generate random expired challenge message
            String failureReason = "Challenge has expired: " + generateRandomReason(i);
            
            // Create expired challenge exception
            PasskeyAuthenticationException exception = PasskeyAuthenticationException.challengeExpired(failureReason);
            
            // Create error response
            PasskeyErrorResponse errorResponse = PasskeyErrorResponse.fromException(exception);
            
            // Assert: Error type should be CHALLENGE_EXPIRED
            assertEquals(
                "Error type should be CHALLENGE_EXPIRED",
                PasskeyException.PasskeyErrorType.CHALLENGE_EXPIRED,
                errorResponse.getErrorType()
            );
            
            // Assert: HTTP status should be BAD_REQUEST (400)
            assertEquals(
                "HTTP status should be BAD_REQUEST for expired challenge",
                RestStatus.BAD_REQUEST,
                errorResponse.getHttpStatus()
            );
            
            // Assert: Error message should contain the expiration information
            assertTrue(
                "Error message should contain expiration information",
                errorResponse.getReason().contains("expired")
            );
            
            // Assert: Error response should be serializable
            XContentBuilder builder = XContentFactory.jsonBuilder();
            BytesRestResponse restResponse = errorResponse.toRestResponse(builder);
            assertNotNull("REST response should not be null", restResponse);
            assertEquals("REST response status should match", RestStatus.BAD_REQUEST, restResponse.status());
        }
    }

    /**
     * Property 45: Unknown credential error messaging
     * 
     * For any authentication failure due to unknown credential, the error response 
     * should indicate the credential is not registered.
     * 
     * This test runs 100 iterations with different unknown credential messages.
     */
    @org.junit.Test
    public void unknownCredentialErrorMessaging() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Generate random unknown credential message
            String failureReason = "Credential not registered: " + generateRandomCredentialId(i);
            
            // Create unknown credential exception
            PasskeyAuthenticationException exception = PasskeyAuthenticationException.unknownCredential(failureReason);
            
            // Create error response
            PasskeyErrorResponse errorResponse = PasskeyErrorResponse.fromException(exception);
            
            // Assert: Error type should be UNKNOWN_CREDENTIAL
            assertEquals(
                "Error type should be UNKNOWN_CREDENTIAL",
                PasskeyException.PasskeyErrorType.UNKNOWN_CREDENTIAL,
                errorResponse.getErrorType()
            );
            
            // Assert: HTTP status should be UNAUTHORIZED (401)
            assertEquals(
                "HTTP status should be UNAUTHORIZED for unknown credential",
                RestStatus.UNAUTHORIZED,
                errorResponse.getHttpStatus()
            );
            
            // Assert: Error message should contain credential information
            assertTrue(
                "Error message should contain credential information",
                errorResponse.getReason().contains("Credential")
            );
            
            // Assert: Error response should be serializable
            XContentBuilder builder = XContentFactory.jsonBuilder();
            BytesRestResponse restResponse = errorResponse.toRestResponse(builder);
            assertNotNull("REST response should not be null", restResponse);
            assertEquals("REST response status should match", RestStatus.UNAUTHORIZED, restResponse.status());
        }
    }

    /**
     * Property 46: HTTP status code correctness
     * 
     * For any passkey operation failure, the HTTP status code should be appropriate 
     * to the failure type (400 for client errors, 401 for authentication failures, 
     * 403 for authorization failures, 500 for server errors).
     * 
     * This test runs 100 iterations testing all error types.
     */
    @org.junit.Test
    public void httpStatusCodeCorrectness() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Test each error type and verify correct HTTP status
            
            // Configuration errors -> 500 INTERNAL_SERVER_ERROR
            PasskeyConfigurationException configException = new PasskeyConfigurationException("Config error " + i);
            PasskeyErrorResponse configResponse = PasskeyErrorResponse.fromException(configException);
            assertEquals(
                "Configuration errors should return INTERNAL_SERVER_ERROR",
                RestStatus.INTERNAL_SERVER_ERROR,
                configResponse.getHttpStatus()
            );
            
            // Registration errors -> 400 BAD_REQUEST
            PasskeyRegistrationException regException = PasskeyRegistrationException.invalidRequest("Invalid request " + i);
            PasskeyErrorResponse regResponse = PasskeyErrorResponse.fromException(regException);
            assertEquals(
                "Registration errors should return BAD_REQUEST",
                RestStatus.BAD_REQUEST,
                regResponse.getHttpStatus()
            );
            
            // Attestation verification failures -> 400 BAD_REQUEST
            PasskeyRegistrationException attestException = PasskeyRegistrationException.attestationVerificationFailed("Attestation failed " + i);
            PasskeyErrorResponse attestResponse = PasskeyErrorResponse.fromException(attestException);
            assertEquals(
                "Attestation failures should return BAD_REQUEST",
                RestStatus.BAD_REQUEST,
                attestResponse.getHttpStatus()
            );
            
            // Signature verification failures -> 401 UNAUTHORIZED
            PasskeyAuthenticationException sigException = PasskeyAuthenticationException.signatureVerificationFailed("Signature failed " + i);
            PasskeyErrorResponse sigResponse = PasskeyErrorResponse.fromException(sigException);
            assertEquals(
                "Signature failures should return UNAUTHORIZED",
                RestStatus.UNAUTHORIZED,
                sigResponse.getHttpStatus()
            );
            
            // Unknown credential -> 401 UNAUTHORIZED
            PasskeyAuthenticationException unknownException = PasskeyAuthenticationException.unknownCredential("Unknown credential " + i);
            PasskeyErrorResponse unknownResponse = PasskeyErrorResponse.fromException(unknownException);
            assertEquals(
                "Unknown credential should return UNAUTHORIZED",
                RestStatus.UNAUTHORIZED,
                unknownResponse.getHttpStatus()
            );
            
            // Expired challenge -> 400 BAD_REQUEST
            PasskeyAuthenticationException expiredException = PasskeyAuthenticationException.challengeExpired("Challenge expired " + i);
            PasskeyErrorResponse expiredResponse = PasskeyErrorResponse.fromException(expiredException);
            assertEquals(
                "Expired challenge should return BAD_REQUEST",
                RestStatus.BAD_REQUEST,
                expiredResponse.getHttpStatus()
            );
            
            // Unauthorized access -> 403 FORBIDDEN
            PasskeyAuthenticationException unauthorizedException = PasskeyAuthenticationException.unauthorized("Unauthorized " + i);
            PasskeyErrorResponse unauthorizedResponse = PasskeyErrorResponse.fromException(unauthorizedException);
            assertEquals(
                "Unauthorized access should return FORBIDDEN",
                RestStatus.FORBIDDEN,
                unauthorizedResponse.getHttpStatus()
            );
            
            // Storage errors -> 500 INTERNAL_SERVER_ERROR
            PasskeyStorageException storageException = new PasskeyStorageException("Storage error " + i);
            PasskeyErrorResponse storageResponse = PasskeyErrorResponse.fromException(storageException);
            assertEquals(
                "Storage errors should return INTERNAL_SERVER_ERROR",
                RestStatus.INTERNAL_SERVER_ERROR,
                storageResponse.getHttpStatus()
            );
        }
    }

    /**
     * Additional property: Error messages should not contain sensitive data
     * 
     * For any error response, sensitive cryptographic material should be redacted.
     * 
     * This test runs 100 iterations with messages containing potential sensitive data.
     */
    @org.junit.Test
    public void errorMessagesShouldNotContainSensitiveData() throws Exception {
        for (int i = 0; i < 100; i++) {
            // Create messages with potential sensitive data
            String sensitiveData = generateBase64Data(i);
            String messageWithSensitiveData = "Operation failed with data: " + sensitiveData;
            
            // Create exception with sensitive data
            Exception genericException = new Exception(messageWithSensitiveData);
            PasskeyErrorResponse errorResponse = PasskeyErrorResponse.fromGenericException(genericException);
            
            // Assert: Sensitive data should be redacted
            String reason = errorResponse.getReason();
            assertFalse(
                "Error message should not contain base64-encoded sensitive data",
                reason.contains(sensitiveData)
            );
            
            // Assert: Redaction marker should be present if data was redacted
            if (sensitiveData.length() >= 32) {
                assertTrue(
                    "Long base64 strings should be redacted",
                    reason.contains("[REDACTED]") || !reason.contains(sensitiveData)
                );
            }
        }
    }

    // Helper methods

    /**
     * Generate a random failure reason for testing.
     */
    private String generateRandomReason(int iteration) {
        String[] reasons = {
            "invalid format",
            "verification failed",
            "timeout occurred",
            "invalid signature",
            "malformed data",
            "unsupported algorithm",
            "invalid encoding",
            "parse error"
        };
        return reasons[iteration % reasons.length] + " (iteration " + iteration + ")";
    }

    /**
     * Generate a random credential ID for testing.
     */
    private String generateRandomCredentialId(int iteration) {
        return "cred_" + iteration + "_" + System.currentTimeMillis();
    }

    /**
     * Generate base64-like data for testing sensitive data redaction.
     */
    private String generateBase64Data(int iteration) {
        // Generate strings of varying lengths to test redaction threshold
        int length = 32 + (iteration % 64);
        StringBuilder sb = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt((iteration + i) % chars.length()));
        }
        return sb.toString();
    }
}
