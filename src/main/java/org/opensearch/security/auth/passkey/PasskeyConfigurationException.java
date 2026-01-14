/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Exception thrown when passkey configuration is invalid or missing.
 * Examples: invalid relying party ID, missing required configuration, invalid origin configuration.
 */
public class PasskeyConfigurationException extends PasskeyException {

    public PasskeyConfigurationException(String message) {
        super(message, PasskeyErrorType.CONFIGURATION_ERROR);
    }

    public PasskeyConfigurationException(String message, Throwable cause) {
        super(message, cause, PasskeyErrorType.CONFIGURATION_ERROR);
    }
}
