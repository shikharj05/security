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
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Property-based tests for passkey public key only storage.
 * 
 * **Feature: passkey-authentication, Property 25: Public key only storage**
 * **Validates: Requirements 6.1**
 * 
 * For any stored credential, the stored data should contain only public key material 
 * and never private key material.
 */
public class PasskeyPublicKeyOnlyStoragePropertyTest {

    /**
     * Property 25: Public key only storage
     * 
     * For any credential, the stored data should only contain public key material.
     * Private keys should never be stored or serialized.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void publicKeyOnlyStorage() throws Exception {
        java.util.Random random = new java.util.Random(44); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] publicKey = generateRandomBytes(random, 32, 256);
            long signatureCounter = random.nextInt(1000000);
            
            // Arrange: Create a credential with only public key
            PasskeyMetadata metadata = new PasskeyMetadata("test-key", "platform", "test-agent");
            Instant now = Instant.now();
            
            PasskeyCredential credential = new PasskeyCredential(
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

            // Assert: Verify only public key is stored
            assertNotNull("Public key should be stored", credential.getPublicKey());
            assertArrayEquals("Public key should match input", publicKey, credential.getPublicKey());
            
            // Serialize to JSON and verify no private key material
            XContentBuilder builder = XContentFactory.jsonBuilder();
            credential.toXContent(builder, ToXContent.EMPTY_PARAMS);
            String json = builder.toString();
            
            // Verify JSON doesn't contain any private key indicators
            assertFalse(
                "Serialized credential should not contain 'private_key' field",
                json.contains("private_key")
            );
            assertFalse(
                "Serialized credential should not contain 'privateKey' field",
                json.contains("privateKey")
            );
            assertFalse(
                "Serialized credential should not contain 'secret' field",
                json.contains("secret")
            );
            
            // Verify JSON contains public key
            assertTrue(
                "Serialized credential should contain 'public_key' field",
                json.contains("public_key")
            );
        }
    }

    /**
     * Property 25 (variant): Public key immutability
     * 
     * For any credential, the public key should be immutable after creation.
     * Modifying the original byte array should not affect the stored public key.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void publicKeyImmutability() {
        java.util.Random random = new java.util.Random(45); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] originalPublicKey = generateRandomBytes(random, 32, 256);
            byte[] publicKeyCopy = originalPublicKey.clone();
            long signatureCounter = random.nextInt(1000000);
            
            // Arrange: Create a credential
            PasskeyMetadata metadata = new PasskeyMetadata("test-key", "platform", "test-agent");
            Instant now = Instant.now();
            
            PasskeyCredential credential = new PasskeyCredential(
                credentialId,
                username,
                originalPublicKey,
                signatureCounter,
                "test-aaguid",
                List.of("usb"),
                metadata,
                now,
                now,
                true,
                false
            );

            // Act: Modify the original public key array
            for (int j = 0; j < originalPublicKey.length; j++) {
                originalPublicKey[j] = (byte) 0xFF;
            }

            // Assert: Stored public key should not be affected by external modification
            assertArrayEquals(
                "Stored public key should not be affected by external modification",
                publicKeyCopy,
                credential.getPublicKey()
            );
        }
    }

    /**
     * Property 25 (variant): Deserialized credential contains only public key
     * 
     * For any credential that is serialized and deserialized, the deserialized
     * credential should only contain public key material.
     * 
     * This test runs 100 iterations with random data to verify the property holds.
     */
    @org.junit.Test
    public void deserializedCredentialContainsOnlyPublicKey() throws Exception {
        java.util.Random random = new java.util.Random(46); // Fixed seed for reproducibility
        
        for (int i = 0; i < 100; i++) {
            // Generate random test data
            String credentialId = generateRandomString(random, 10, 100);
            String username = generateRandomString(random, 3, 64);
            byte[] publicKey = generateRandomBytes(random, 32, 256);
            long signatureCounter = random.nextInt(1000000);
            
            // Arrange: Create and serialize a credential
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

            // Act: Serialize and deserialize
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
            parser.nextToken();
            PasskeyCredential deserialized = PasskeyCredential.fromXContent(parser);

            // Assert: Deserialized credential should only have public key
            assertNotNull("Deserialized public key should not be null", deserialized.getPublicKey());
            assertArrayEquals("Deserialized public key should match original", publicKey, deserialized.getPublicKey());
            
            // Verify the deserialized JSON doesn't contain private key material
            XContentBuilder deserializedBuilder = XContentFactory.jsonBuilder();
            deserialized.toXContent(deserializedBuilder, ToXContent.EMPTY_PARAMS);
            String deserializedJson = deserializedBuilder.toString();
            
            assertFalse(
                "Deserialized credential should not contain 'private_key' field",
                deserializedJson.contains("private_key")
            );
            assertFalse(
                "Deserialized credential should not contain 'privateKey' field",
                deserializedJson.contains("privateKey")
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
