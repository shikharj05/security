/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

/**
 * Document structure for storing all passkey credentials in the security index.
 * Similar to how internal users are stored.
 */
public class PasskeyCredentialsDocument implements ToXContent {
    
    private static final String META_TYPE = "passkey_credentials";
    private static final int CONFIG_VERSION = 1;
    
    private final Map<String, PasskeyCredential> credentials;
    
    public PasskeyCredentialsDocument() {
        this.credentials = new HashMap<>();
    }
    
    public PasskeyCredentialsDocument(Map<String, PasskeyCredential> credentials) {
        this.credentials = new HashMap<>(credentials);
    }
    
    public Map<String, PasskeyCredential> getCredentials() {
        return new HashMap<>(credentials);
    }
    
    public void putCredential(PasskeyCredential credential) {
        credentials.put(credential.getCredentialId(), credential);
    }
    
    public void removeCredential(String credentialId) {
        credentials.remove(credentialId);
    }
    
    public PasskeyCredential getCredential(String credentialId) {
        return credentials.get(credentialId);
    }
    
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        
        // Add metadata
        builder.startObject("_meta");
        builder.field("type", META_TYPE);
        builder.field("config_version", CONFIG_VERSION);
        builder.endObject();
        
        // Serialize credentials to JSON and store as base64 string (like internal users)
        // This avoids hitting the field limit in the security index
        XContentBuilder credBuilder = XContentBuilder.builder(XContentType.JSON.xContent());
        credBuilder.startObject();
        for (Map.Entry<String, PasskeyCredential> entry : credentials.entrySet()) {
            credBuilder.field(entry.getKey());
            entry.getValue().toXContent(credBuilder, params);
        }
        credBuilder.endObject();
        credBuilder.close();
        
        // Convert to base64 string
        String credentialsJson = credBuilder.toString();
        String credentialsBase64 = java.util.Base64.getEncoder().encodeToString(
            credentialsJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        
        builder.field("passkeycreds", credentialsBase64);
        
        builder.endObject();
        return builder;
    }

    
    public static PasskeyCredentialsDocument fromXContent(XContentParser parser) throws IOException {
        Map<String, PasskeyCredential> credentials = new HashMap<>();
        
        XContentParser.Token token;
        String currentFieldName = null;
        
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token == XContentParser.Token.VALUE_STRING && "passkeycreds".equals(currentFieldName)) {
                // Decode base64 string
                String credentialsBase64 = parser.text();
                String credentialsJson = new String(
                    java.util.Base64.getDecoder().decode(credentialsBase64),
                    java.nio.charset.StandardCharsets.UTF_8
                );
                
                // Parse the JSON
                try (XContentParser credParser = XContentType.JSON.xContent().createParser(
                    null, null, credentialsJson)) {
                    
                    credParser.nextToken(); // START_OBJECT
                    while ((token = credParser.nextToken()) != XContentParser.Token.END_OBJECT) {
                        if (token == XContentParser.Token.FIELD_NAME) {
                            String credentialId = credParser.currentName();
                            credParser.nextToken(); // Move to START_OBJECT
                            PasskeyCredential credential = PasskeyCredential.fromXContent(credParser);
                            credentials.put(credentialId, credential);
                        }
                    }
                }
            } else if (token == XContentParser.Token.START_OBJECT && "_meta".equals(currentFieldName)) {
                // Skip metadata
                parser.skipChildren();
            }
        }
        
        return new PasskeyCredentialsDocument(credentials);
    }
}
