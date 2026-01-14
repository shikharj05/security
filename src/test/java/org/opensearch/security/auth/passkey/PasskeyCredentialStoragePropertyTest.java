/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.time.Instant;
import java.util.List;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Property-based tests for passkey credential storage.
 * 
 * **Feature: passkey-authentication, Property 8: Credential storage completeness**
 * **Validates: Requirements 2.4**
 * 
 * For any successful attestation verification, the stored credential should include 
 * the public key, credential ID, and user association.
 */
public class PasskeyCredentialStoragePropertyTest {

    /**
     * Property 8: Credential storage completeness
     * 
     * For any credential with valid data, when we create a PasskeyCredential object,
     * it should store all required fields: credential ID, username, public key, 
     * signature counter, and user association.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void credentialStorageCompleteness() {
        java.util.Random random = new java.util.Random(42); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] publicKey = generateRandomBytes(random, 32, 256);
            long signatureCounter = random.nextInt(1000000);
            String friendlyName = generateRandomString(random, 10, 50);
            
            // Arrange: Create metadata and credential
            PasskeyMetadata metadata = new PasskeyMetadata(friendlyName, "platform", "test-agent");
            Instant now = Instant.now();
            
            PasskeyCredential credential = new PasskeyCredential(
                credentialId,
                username,
                publicKey,
                signatureCounter,
                "test-aaguid",
                List.of("usb", "nfc"),
                metadata,
                now,
                now,
                true,
                false
            );

            // Assert: Verify all required fields are stored
            assertNotNull("Credential should not be null", credential);
            assertEquals("Credential ID should be stored", credentialId, credential.getCredentialId());
            assertEquals("Username should be stored", username, credential.getUsername());
            assertArrayEquals("Public key should be stored", publicKey, credential.getPublicKey());
            assertEquals("Signature counter should be stored", signatureCounter, credential.getSignatureCounter());
            assertNotNull("Metadata should be stored", credential.getMetadata());
            assertNotNull("Created timestamp should be stored", credential.getCreatedAt());
        }
    }

    /**
     * Property 8 (variant): Credential serialization round-trip
     * 
     * For any credential, serializing and deserializing should preserve all data.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void credentialSerializationRoundTrip() throws Exception {
        java.util.Random random = new java.util.Random(43); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] publicKey = generateRandomBytes(random, 32, 256);
            long signatureCounter = random.nextInt(1000000);
            
            // Arrange: Create a credential
            PasskeyMetadata metadata = new PasskeyMetadata("test-key", "platform", "test-agent");
            Instant now = Instant.now();
            
            PasskeyCredential original = new PasskeyCredential(
                credentialId,
                username,
                publicKey,
                signatureCounter,
                "test-aaguid",
                List.of("usb"),
                metadata,
                now,
                now,
                true,
                false
            );

            // Act: Serialize to XContent and back
            XContentBuilder builder = XContentFactory.jsonBuilder();
            original.toXContent(builder, ToXContent.EMPTY_PARAMS);
            String json = builder.toString();
            
            XContentParser parser = XContentType.JSON
                .xContent()
                .createParser(
                    NamedXContentRegistry.EMPTY,
                    DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                    json
                );
            parser.nextToken(); // Move to START_OBJECT
            PasskeyCredential deserialized = PasskeyCredential.fromXContent(parser);

            // Assert: All fields should match
            assertEquals("Credential ID should match", original.getCredentialId(), deserialized.getCredentialId());
            assertEquals("Username should match", original.getUsername(), deserialized.getUsername());
            assertArrayEquals("Public key should match", original.getPublicKey(), deserialized.getPublicKey());
            assertEquals(
                "Signature counter should match",
                original.getSignatureCounter(),
                deserialized.getSignatureCounter()
            );
        }
    }

    // Helper methods for generating random test data
    private String generateRandomString(java.util.Random random, int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    private byte[] generateRandomBytes(java.util.Random random, int minSize, int maxSize) {
        int size = minSize + random.nextInt(maxSize - minSize + 1);
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }
}
