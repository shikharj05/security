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
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;
import java.time.Instant;

/**
 * Standardized error response structure for passkey operations.
 * Provides consistent error formatting and HTTP status code mapping.
 */
public class PasskeyErrorResponse {

    private final String status = "error";
    private final String reason;
    private final PasskeyException.PasskeyErrorType errorType;
    private final String timestamp;
    private final RestStatus httpStatus;

    private PasskeyErrorResponse(String reason, PasskeyException.PasskeyErrorType errorType, RestStatus httpStatus) {
        this.reason = reason;
        this.errorType = errorType;
        this.httpStatus = httpStatus;
        this.timestamp = Instant.now().toString();
    }

    /**
     * Creates an error response from a PasskeyException.
     */
    public static PasskeyErrorResponse fromException(PasskeyException exception) {
        RestStatus status = mapErrorTypeToHttpStatus(exception.getErrorType());
        return new PasskeyErrorResponse(exception.getMessage(), exception.getErrorType(), status);
    }

    /**
     * Creates an error response from a generic exception.
     */
    public static PasskeyErrorResponse fromGenericException(Exception exception) {
        return new PasskeyErrorResponse(
            sanitizeErrorMessage(exception.getMessage()),
            PasskeyException.PasskeyErrorType.AUTHENTICATION_ERROR,
            RestStatus.INTERNAL_SERVER_ERROR
        );
    }

    /**
     * Maps PasskeyErrorType to appropriate HTTP status code.
     */
    private static RestStatus mapErrorTypeToHttpStatus(PasskeyException.PasskeyErrorType errorType) {
        switch (errorType) {
            case CONFIGURATION_ERROR:
                return RestStatus.INTERNAL_SERVER_ERROR;
            case REGISTRATION_ERROR:
            case INVALID_REQUEST:
                return RestStatus.BAD_REQUEST;
            case ATTESTATION_VERIFICATION_FAILED:
                return RestStatus.BAD_REQUEST;
            case AUTHENTICATION_ERROR:
            case SIGNATURE_VERIFICATION_FAILED:
            case UNKNOWN_CREDENTIAL:
                return RestStatus.UNAUTHORIZED;
            case CHALLENGE_EXPIRED:
                return RestStatus.BAD_REQUEST;
            case UNAUTHORIZED:
                return RestStatus.FORBIDDEN;
            case STORAGE_ERROR:
                return RestStatus.INTERNAL_SERVER_ERROR;
            default:
                return RestStatus.INTERNAL_SERVER_ERROR;
        }
    }

    /**
     * Sanitizes error messages to ensure no sensitive data is exposed.
     * Removes potential cryptographic material, keys, or other sensitive information.
     */
    private static String sanitizeErrorMessage(String message) {
        if (message == null) {
            return "An error occurred during passkey operation";
        }
        
        // Remove any potential base64-encoded data (likely cryptographic material)
        String sanitized = message.replaceAll("[A-Za-z0-9+/]{32,}={0,2}", "[REDACTED]");
        
        // Remove hex-encoded data (potential keys or hashes)
        sanitized = sanitized.replaceAll("0x[0-9a-fA-F]{16,}", "[REDACTED]");
        
        // If the message is too long, truncate it
        if (sanitized.length() > 500) {
            sanitized = sanitized.substring(0, 497) + "...";
        }
        
        return sanitized;
    }

    /**
     * Converts this error response to a BytesRestResponse.
     */
    public BytesRestResponse toRestResponse(XContentBuilder builder) throws IOException {
        builder.startObject();
        builder.field("status", status);
        builder.field("reason", reason);
        builder.startObject("details");
        builder.field("error_type", errorType.name());
        builder.field("timestamp", timestamp);
        builder.endObject();
        builder.endObject();
        
        return new BytesRestResponse(httpStatus, builder);
    }

    /**
     * Gets the HTTP status code for this error.
     */
    public RestStatus getHttpStatus() {
        return httpStatus;
    }

    /**
     * Gets the error reason message.
     */
    public String getReason() {
        return reason;
    }

    /**
     * Gets the error type.
     */
    public PasskeyException.PasskeyErrorType getErrorType() {
        return errorType;
    }
}
