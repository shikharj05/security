/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Exception thrown when WebAuthn operations fail.
 */
public class WebAuthnException extends Exception {

    public WebAuthnException(String message) {
        super(message);
    }

    public WebAuthnException(String message, Throwable cause) {
        super(message, cause);
    }
}
