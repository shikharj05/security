/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.util.Objects;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * User-facing metadata for a passkey credential.
 */
public class PasskeyMetadata implements Writeable, ToXContentObject {

    private final String friendlyName;
    private final String deviceType;
    private final String userAgent;

    public PasskeyMetadata(String friendlyName, String deviceType, String userAgent) {
        this.friendlyName = friendlyName;
        this.deviceType = deviceType;
        this.userAgent = userAgent;
    }

    public PasskeyMetadata(StreamInput in) throws IOException {
        this.friendlyName = in.readOptionalString();
        this.deviceType = in.readOptionalString();
        this.userAgent = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(friendlyName);
        out.writeOptionalString(deviceType);
        out.writeOptionalString(userAgent);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (friendlyName != null) {
            builder.field("friendly_name", friendlyName);
        }
        if (deviceType != null) {
            builder.field("device_type", deviceType);
        }
        if (userAgent != null) {
            builder.field("user_agent", userAgent);
        }
        builder.endObject();
        return builder;
    }

    public static PasskeyMetadata fromXContent(XContentParser parser) throws IOException {
        String friendlyName = null;
        String deviceType = null;
        String userAgent = null;

        XContentParser.Token token;
        String currentFieldName = null;

        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                switch (currentFieldName) {
                    case "friendly_name":
                        friendlyName = parser.text();
                        break;
                    case "device_type":
                        deviceType = parser.text();
                        break;
                    case "user_agent":
                        userAgent = parser.text();
                        break;
                }
            }
        }

        return new PasskeyMetadata(friendlyName, deviceType, userAgent);
    }

    // Getters
    public String getFriendlyName() {
        return friendlyName;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public String getUserAgent() {
        return userAgent;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasskeyMetadata that = (PasskeyMetadata) o;
        return Objects.equals(friendlyName, that.friendlyName)
            && Objects.equals(deviceType, that.deviceType)
            && Objects.equals(userAgent, that.userAgent);
    }

    @Override
    public int hashCode() {
        return Objects.hash(friendlyName, deviceType, userAgent);
    }
}
