/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.plugin.config;

import java.util.Collections;
import java.util.List;

/**
 * Exception thrown when plugin configuration validation fails.
 */
public class PluginConfigValidationException extends Exception {

    private final List<String> errors;

    /**
     * Creates a new validation exception with a message and list of errors.
     *
     * @param message The exception message
     * @param errors List of validation error messages
     */
    public PluginConfigValidationException(String message, List<String> errors) {
        super(message + ": " + String.join("; ", errors));
        this.errors = Collections.unmodifiableList(errors);
    }

    /**
     * Gets the list of validation errors.
     *
     * @return Immutable list of error messages
     */
    public List<String> getErrors() {
        return errors;
    }
}
