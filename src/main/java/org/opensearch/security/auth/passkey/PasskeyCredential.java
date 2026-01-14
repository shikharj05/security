/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * Represents a stored passkey credential.
 * Contains the public key and metadata for WebAuthn authentication.
 */
public class PasskeyCredential implements Writeable, ToXContentObject {

    private final String credentialId;
    private final String username;
    private final byte[] publicKey;
    private final long signatureCounter;
    private final String aaguid;
    private final List<String> transports;
    private final PasskeyMetadata metadata;
    private final Instant createdAt;
    private final Instant lastUsedAt;
    private final boolean backupEligible;
    private final boolean backupState;

    public PasskeyCredential(
        String credentialId,
        String username,
        byte[] publicKey,
        long signatureCounter,
        String aaguid,
        List<String> transports,
        PasskeyMetadata metadata,
        Instant createdAt,
        Instant lastUsedAt,
        boolean backupEligible,
        boolean backupState
    ) {
        this.credentialId = Objects.requireNonNull(credentialId, "credentialId must not be null");
        this.username = Objects.requireNonNull(username, "username must not be null");
        // Make defensive copy to prevent external modification
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey must not be null").clone();
        this.signatureCounter = signatureCounter;
        this.aaguid = aaguid;
        this.transports = transports;
        this.metadata = Objects.requireNonNull(metadata, "metadata must not be null");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.lastUsedAt = lastUsedAt;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
    }

    public PasskeyCredential(StreamInput in) throws IOException {
        this.credentialId = in.readString();
        this.username = in.readString();
        this.publicKey = in.readByteArray();
        this.signatureCounter = in.readLong();
        this.aaguid = in.readOptionalString();
        this.transports = in.readOptionalStringList();
        this.metadata = new PasskeyMetadata(in);
        this.createdAt = in.readInstant();
        this.lastUsedAt = in.readOptionalInstant();
        this.backupEligible = in.readBoolean();
        this.backupState = in.readBoolean();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(credentialId);
        out.writeString(username);
        out.writeByteArray(publicKey);
        out.writeLong(signatureCounter);
        out.writeOptionalString(aaguid);
        out.writeOptionalStringCollection(transports);
        metadata.writeTo(out);
        out.writeInstant(createdAt);
        out.writeOptionalInstant(lastUsedAt);
        out.writeBoolean(backupEligible);
        out.writeBoolean(backupState);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("credential_id", credentialId);
        builder.field("username", username);
        builder.field("public_key", publicKey);
        builder.field("signature_counter", signatureCounter);
        if (aaguid != null) {
            builder.field("aaguid", aaguid);
        }
        if (transports != null && !transports.isEmpty()) {
            builder.field("transports", transports);
        }
        builder.field("metadata", metadata);
        builder.field("created_at", createdAt.toString());
        if (lastUsedAt != null) {
            builder.field("last_used_at", lastUsedAt.toString());
        }
        builder.field("backup_eligible", backupEligible);
        builder.field("backup_state", backupState);
        builder.endObject();
        return builder;
    }

    public static PasskeyCredential fromXContent(XContentParser parser) throws IOException {
        String credentialId = null;
        String username = null;
        byte[] publicKey = null;
        long signatureCounter = 0;
        String aaguid = null;
        List<String> transports = null;
        PasskeyMetadata metadata = null;
        Instant createdAt = null;
        Instant lastUsedAt = null;
        boolean backupEligible = false;
        boolean backupState = false;

        XContentParser.Token token;
        String currentFieldName = null;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                switch (currentFieldName) {
                    case "credential_id":
                        credentialId = parser.text();
                        break;
                    case "username":
                        username = parser.text();
                        break;
                    case "public_key":
                        publicKey = parser.binaryValue();
                        break;
                    case "signature_counter":
                        signatureCounter = parser.longValue();
                        break;
                    case "aaguid":
                        aaguid = parser.text();
                        break;
                    case "created_at":
                        createdAt = Instant.parse(parser.text());
                        break;
                    case "last_used_at":
                        lastUsedAt = Instant.parse(parser.text());
                        break;
                    case "backup_eligible":
                        backupEligible = parser.booleanValue();
                        break;
                    case "backup_state":
                        backupState = parser.booleanValue();
                        break;
                }
            } else if (token == XContentParser.Token.START_ARRAY && "transports".equals(currentFieldName)) {
                transports = new java.util.ArrayList<>();
                while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
                    transports.add(parser.text());
                }
            } else if (token == XContentParser.Token.START_OBJECT && "metadata".equals(currentFieldName)) {
                metadata = PasskeyMetadata.fromXContent(parser);
            }
        }

        return new PasskeyCredential(
            credentialId,
            username,
            publicKey,
            signatureCounter,
            aaguid,
            transports,
            metadata,
            createdAt,
            lastUsedAt,
            backupEligible,
            backupState
        );
    }

    // Getters
    public String getCredentialId() {
        return credentialId;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getPublicKey() {
        // Return defensive copy to prevent external modification
        return publicKey.clone();
    }

    public long getSignatureCounter() {
        return signatureCounter;
    }

    public String getAaguid() {
        return aaguid;
    }

    public List<String> getTransports() {
        return transports;
    }

    public PasskeyMetadata getMetadata() {
        return metadata;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public boolean isBackupEligible() {
        return backupEligible;
    }

    public boolean isBackupState() {
        return backupState;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasskeyCredential that = (PasskeyCredential) o;
        return Objects.equals(credentialId, that.credentialId) && Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialId, username);
    }
}
