/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Configuration for the WebAuthn relying party.
 * Contains settings that control passkey authentication behavior.
 */
public class RelyingPartyConfig implements Writeable, ToXContentObject {

    private final String rpId;
    private final String rpName;
    private final List<String> allowedOrigins;
    private final long challengeTimeoutMs;
    private final UserVerificationRequirement userVerification;
    private final AttestationConveyancePreference attestation;
    private final AuthenticatorAttachment authenticatorAttachment;
    private final ResidentKeyRequirement residentKey;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;

    public RelyingPartyConfig(
        String rpId,
        String rpName,
        List<String> allowedOrigins,
        long challengeTimeoutMs,
        UserVerificationRequirement userVerification,
        AttestationConveyancePreference attestation,
        AuthenticatorAttachment authenticatorAttachment,
        ResidentKeyRequirement residentKey,
        List<PublicKeyCredentialParameters> pubKeyCredParams
    ) {
        this.rpId = Objects.requireNonNull(rpId, "rpId must not be null");
        this.rpName = Objects.requireNonNull(rpName, "rpName must not be null");
        this.allowedOrigins = Objects.requireNonNull(allowedOrigins, "allowedOrigins must not be null");
        this.challengeTimeoutMs = challengeTimeoutMs;
        this.userVerification = Objects.requireNonNull(userVerification, "userVerification must not be null");
        this.attestation = Objects.requireNonNull(attestation, "attestation must not be null");
        this.authenticatorAttachment = authenticatorAttachment; // Can be null
        this.residentKey = Objects.requireNonNull(residentKey, "residentKey must not be null");
        this.pubKeyCredParams = Objects.requireNonNull(pubKeyCredParams, "pubKeyCredParams must not be null");
    }

    public RelyingPartyConfig(StreamInput in) throws IOException {
        this.rpId = in.readString();
        this.rpName = in.readString();
        this.allowedOrigins = in.readStringList();
        this.challengeTimeoutMs = in.readLong();
        this.userVerification = UserVerificationRequirement.create(in.readString());
        this.attestation = AttestationConveyancePreference.create(in.readString());
        String attachmentStr = in.readOptionalString();
        this.authenticatorAttachment = attachmentStr != null ? AuthenticatorAttachment.create(attachmentStr) : null;
        this.residentKey = ResidentKeyRequirement.create(in.readString());
        // Note: PublicKeyCredentialParameters serialization would need custom handling
        // For now, we'll skip it in the stream serialization
        this.pubKeyCredParams = List.of();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(rpId);
        out.writeString(rpName);
        out.writeStringCollection(allowedOrigins);
        out.writeLong(challengeTimeoutMs);
        out.writeString(userVerification.getValue());
        out.writeString(attestation.getValue());
        out.writeOptionalString(authenticatorAttachment != null ? authenticatorAttachment.getValue() : null);
        out.writeString(residentKey.getValue());
        // Skip pubKeyCredParams for now
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("rp_id", rpId);
        builder.field("rp_name", rpName);
        builder.field("allowed_origins", allowedOrigins);
        builder.field("challenge_timeout_ms", challengeTimeoutMs);
        builder.field("user_verification", userVerification.getValue());
        builder.field("attestation", attestation.getValue());
        if (authenticatorAttachment != null) {
            builder.field("authenticator_attachment", authenticatorAttachment.getValue());
        }
        builder.field("resident_key", residentKey.getValue());
        builder.endObject();
        return builder;
    }

    // Getters
    public String getRpId() {
        return rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public List<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    public long getChallengeTimeoutMs() {
        return challengeTimeoutMs;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public ResidentKeyRequirement getResidentKey() {
        return residentKey;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RelyingPartyConfig that = (RelyingPartyConfig) o;
        return Objects.equals(rpId, that.rpId) && Objects.equals(rpName, that.rpName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rpId, rpName);
    }
}
