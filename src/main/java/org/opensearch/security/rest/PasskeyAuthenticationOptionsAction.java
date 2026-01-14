/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.rest;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.passkey.Challenge;
import org.opensearch.security.auth.passkey.ChallengeStore;
import org.opensearch.security.auth.passkey.PasskeyCredential;
import org.opensearch.security.auth.passkey.PasskeyCredentialRepository;
import org.opensearch.security.auth.passkey.WebAuthnManager;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST action to generate passkey authentication options.
 * Handles POST /_plugins/_security/api/passkey/authentication/options
 */
public class PasskeyAuthenticationOptionsAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(PasskeyAuthenticationOptionsAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/passkey/authentication/options")),
        PLUGIN_ROUTE_PREFIX
    );

    private final WebAuthnManager webAuthnManager;
    private final ChallengeStore challengeStore;
    private final PasskeyCredentialRepository credentialRepository;

    public PasskeyAuthenticationOptionsAction(
        final Settings settings,
        final RestController controller,
        final WebAuthnManager webAuthnManager,
        final ChallengeStore challengeStore,
        final PasskeyCredentialRepository credentialRepository,
        final ThreadPool threadPool
    ) {
        super();
        this.webAuthnManager = webAuthnManager;
        this.challengeStore = challengeStore;
        this.credentialRepository = credentialRepository;
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
                    // Parse request body (username is optional for usernameless authentication)
                    Map<String, Object> requestBody = request.contentParser().map();
                    String username = (String) requestBody.get("username");

                    // Get allowed credentials if username is provided
                    List<String> allowCredentials = null;
                    if (username != null && !username.isEmpty()) {
                        List<PasskeyCredential> credentials = credentialRepository.findByUsername(username);
                        allowCredentials = credentials.stream()
                            .map(PasskeyCredential::getCredentialId)
                            .collect(Collectors.toList());

                        if (allowCredentials.isEmpty()) {
                            builder.startObject();
                            builder.field("error", "No passkeys registered for user: " + username);
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.NOT_FOUND, builder);
                            channel.sendResponse(response);
                            return;
                        }
                    }

                    // Generate authentication options
                    PublicKeyCredentialRequestOptions options = webAuthnManager.generateAuthenticationOptions(allowCredentials);

                    // Store challenge
                    String challengeId = UUID.randomUUID().toString();
                    byte[] challengeBytes = options.getChallenge().getValue();
                    Instant now = Instant.now();
                    Challenge challenge = new Challenge(
                        challengeId,
                        challengeBytes,
                        username, // may be null for usernameless auth
                        Challenge.ChallengeType.AUTHENTICATION,
                        now,
                        now.plusSeconds(300), // 5 minute expiry
                        null // sessionId - could be extracted from request if needed
                    );
                    challengeStore.storeChallenge(challengeId, challenge);

                    // Build response
                    builder.startObject();
                    builder.field("challengeId", challengeId);
                    builder.field("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes));
                    
                    if (options.getTimeout() != null) {
                        builder.field("timeout", options.getTimeout());
                    }
                    
                    if (options.getRpId() != null) {
                        builder.field("rpId", options.getRpId());
                    }
                    
                    if (options.getAllowCredentials() != null && !options.getAllowCredentials().isEmpty()) {
                        builder.startArray("allowCredentials");
                        final XContentBuilder finalBuilder = builder;
                        options.getAllowCredentials().forEach(cred -> {
                            try {
                                finalBuilder.startObject();
                                finalBuilder.field("type", cred.getType().getValue());
                                finalBuilder.field("id", Base64.getUrlEncoder().withoutPadding().encodeToString(cred.getId()));
                                finalBuilder.endObject();
                            } catch (IOException e) {
                                log.error("Error writing allowCredentials", e);
                            }
                        });
                        builder.endArray();
                    }
                    
                    if (options.getUserVerification() != null) {
                        builder.field("userVerification", options.getUserVerification().getValue());
                    }
                    
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error generating authentication options", e);
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
        return "Passkey Authentication Options Action";
    }
}
