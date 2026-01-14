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
import java.util.Objects;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * Represents a temporary challenge for authentication or registration.
 * Challenges are single-use and have a time-to-live.
 */
public class Challenge implements Writeable, ToXContentObject {

    private final String challengeId;
    private final byte[] challengeBytes;
    private final String username;
    private final ChallengeType type;
    private final Instant createdAt;
    private final Instant expiresAt;
    private final String sessionId;

    public Challenge(
        String challengeId,
        byte[] challengeBytes,
        String username,
        ChallengeType type,
        Instant createdAt,
        Instant expiresAt,
        String sessionId
    ) {
        this.challengeId = Objects.requireNonNull(challengeId, "challengeId must not be null");
        this.challengeBytes = Objects.requireNonNull(challengeBytes, "challengeBytes must not be null");
        this.username = username; // Can be null for usernameless authentication
        this.type = Objects.requireNonNull(type, "type must not be null");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt must not be null");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        this.sessionId = sessionId;
    }

    public Challenge(StreamInput in) throws IOException {
        this.challengeId = in.readString();
        this.challengeBytes = in.readByteArray();
        this.username = in.readOptionalString();
        this.type = ChallengeType.valueOf(in.readString());
        this.createdAt = in.readInstant();
        this.expiresAt = in.readInstant();
        this.sessionId = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(challengeId);
        out.writeByteArray(challengeBytes);
        out.writeOptionalString(username);
        out.writeString(type.name());
        out.writeInstant(createdAt);
        out.writeInstant(expiresAt);
        out.writeOptionalString(sessionId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("challenge_id", challengeId);
        builder.field("challenge_bytes", challengeBytes);
        if (username != null) {
            builder.field("username", username);
        }
        builder.field("type", type.name());
        builder.field("created_at", createdAt.toString());
        builder.field("expires_at", expiresAt.toString());
        if (sessionId != null) {
            builder.field("session_id", sessionId);
        }
        builder.endObject();
        return builder;
    }

    public static Challenge fromXContent(XContentParser parser) throws IOException {
        String challengeId = null;
        byte[] challengeBytes = null;
        String username = null;
        ChallengeType type = null;
        Instant createdAt = null;
        Instant expiresAt = null;
        String sessionId = null;

        XContentParser.Token token;
        String currentFieldName = null;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                switch (currentFieldName) {
                    case "challenge_id":
                        challengeId = parser.text();
                        break;
                    case "challenge_bytes":
                        challengeBytes = parser.binaryValue();
                        break;
                    case "username":
                        username = parser.text();
                        break;
                    case "type":
                        type = ChallengeType.valueOf(parser.text());
                        break;
                    case "created_at":
                        createdAt = Instant.parse(parser.text());
                        break;
                    case "expires_at":
                        expiresAt = Instant.parse(parser.text());
                        break;
                    case "session_id":
                        sessionId = parser.text();
                        break;
                }
            }
        }

        return new Challenge(challengeId, challengeBytes, username, type, createdAt, expiresAt, sessionId);
    }

    /**
     * Check if this challenge has expired.
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    // Getters
    public String getChallengeId() {
        return challengeId;
    }

    public byte[] getChallengeBytes() {
        return challengeBytes;
    }

    public String getUsername() {
        return username;
    }

    public ChallengeType getType() {
        return type;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getSessionId() {
        return sessionId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Challenge challenge = (Challenge) o;
        return Objects.equals(challengeId, challenge.challengeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(challengeId);
    }

    /**
     * Type of challenge: REGISTRATION or AUTHENTICATION
     */
    public enum ChallengeType {
        REGISTRATION,
        AUTHENTICATION
    }
}
