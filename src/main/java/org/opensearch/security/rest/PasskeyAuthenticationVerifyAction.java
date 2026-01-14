/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.passkey.HTTPPasskeyAuthenticator;
import org.opensearch.security.auth.passkey.PasskeyAuthenticationBackend;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST action to verify passkey authentication response.
 * Handles POST /_plugins/_security/api/passkey/authentication/verify
 */
public class PasskeyAuthenticationVerifyAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(PasskeyAuthenticationVerifyAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/passkey/authentication/verify")),
        PLUGIN_ROUTE_PREFIX
    );

    private final PasskeyAuthenticationBackend authenticationBackend;

    public PasskeyAuthenticationVerifyAction(
        final Settings settings,
        final RestController controller,
        final PasskeyAuthenticationBackend authenticationBackend,
        final ThreadPool threadPool
    ) {
        super();
        this.authenticationBackend = authenticationBackend;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
                    // Parse request body
                    Map<String, Object> requestBody = request.contentParser().map();
                    
                    String challengeId = (String) requestBody.get("challengeId");
                    String username = (String) requestBody.get("username");
                    
                    // Parse assertion from request body (WebAuthn format)
                    @SuppressWarnings("unchecked")
                    Map<String, Object> assertionMap = (Map<String, Object>) requestBody.get("assertion");
                    if (assertionMap == null) {
                        builder.startObject();
                        builder.field("error", "Missing assertion object");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }
                    
                    String credentialId = (String) assertionMap.get("id");
                    @SuppressWarnings("unchecked")
                    Map<String, Object> assertionResponse = (Map<String, Object>) assertionMap.get("response");
                    
                    if (assertionResponse == null) {
                        builder.startObject();
                        builder.field("error", "Missing assertion.response");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }
                    
                    String clientDataJSON = (String) assertionResponse.get("clientDataJSON");
                    String authenticatorData = (String) assertionResponse.get("authenticatorData");
                    String signature = (String) assertionResponse.get("signature");

                    if (challengeId == null || credentialId == null || clientDataJSON == null || 
                        authenticatorData == null || signature == null) {
                        builder.startObject();
                        builder.field("error", "Missing required fields");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }
                    
                    // Get origin from request
                    String origin = request.header("Origin");
                    if (origin == null) {
                        builder.startObject();
                        builder.field("error", "Origin header required");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Create PasskeyAssertion
                    HTTPPasskeyAuthenticator.PasskeyAssertion assertion = 
                        new HTTPPasskeyAuthenticator.PasskeyAssertion(
                            credentialId,
                            clientDataJSON,
                            authenticatorData,
                            signature,
                            challengeId,
                            null // userHandle
                        );

                    // Create AuthCredentials with the assertion
                    // Use username from request if provided, otherwise use a placeholder
                    // The backend will get the actual username from the credential
                    String authUsername = username != null ? username : "passkey-user";
                    AuthCredentials credentials = new AuthCredentials(authUsername, assertion);

                    // Create authentication context
                    AuthenticationContext context = new AuthenticationContext(credentials);

                    // Delegate to PasskeyAuthenticationBackend for verification
                    User user;
                    try {
                        user = authenticationBackend.authenticate(context);
                    } catch (OpenSearchSecurityException e) {
                        log.warn("Authentication failed: {}", e.getMessage());
                        builder.startObject();
                        builder.field("error", e.getMessage());
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.UNAUTHORIZED, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Log authentication event
                    log.info("Passkey authentication successful for user: {}, credentialId: {}", 
                        user.getName(), credentialId);

                    // Build success response
                    // Note: In a real implementation, this would create a session token or JWT
                    builder.startObject();
                    builder.field("success", true);
                    builder.field("username", user.getName());
                    builder.field("message", "Authentication successful");
                    // TODO: Generate and return authentication token/session
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error verifying authentication", e);
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e.getMessage());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if (builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "Passkey Authentication Verify Action";
    }
}
