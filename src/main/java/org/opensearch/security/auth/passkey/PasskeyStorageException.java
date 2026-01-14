/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

/**
 * Exception thrown when passkey storage operations fail.
 * Examples: credential storage failure, credential retrieval failure, challenge storage failure.
 */
public class PasskeyStorageException extends PasskeyException {

    public PasskeyStorageException(String message) {
        super(message, PasskeyErrorType.STORAGE_ERROR);
    }

    public PasskeyStorageException(String message, Throwable cause) {
        super(message, cause, PasskeyErrorType.STORAGE_ERROR);
    }
}
