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
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
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
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST action to generate passkey registration options.
 * Handles POST /_plugins/_security/api/passkey/registration/options
 */
public class PasskeyRegistrationOptionsAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(PasskeyRegistrationOptionsAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/passkey/registration/options")),
        PLUGIN_ROUTE_PREFIX
    );

    private final WebAuthnManager webAuthnManager;
    private final ChallengeStore challengeStore;
    private final PasskeyCredentialRepository credentialRepository;
    private final ThreadContext threadContext;

    public PasskeyRegistrationOptionsAction(
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
        this.threadContext = threadPool.getThreadContext();
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
                    // Extract username from request body or authenticated user
                    String requestedUsername = null;
                    if (request.hasContent()) {
                        Map<String, Object> body = XContentHelper.convertToMap(request.content(), false, XContentType.JSON).v2();
                        requestedUsername = (String) body.get("username");
                    }
                    
                    // Get authenticated user
                    final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    if (user == null) {
                        builder.startObject();
                        builder.field("error", "User not authenticated");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.UNAUTHORIZED, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Use requested username if provided and user is admin, otherwise use authenticated user
                    String username = user.getName();
                    if (requestedUsername != null && !requestedUsername.isEmpty()) {
                        // Only allow admin to register for other users
                        if (user.getRoles().contains("all_access") || user.getName().equals("admin")) {
                            username = requestedUsername;
                        }
                    }
                    
                    String userId = username; // Use username as userId for simplicity

                    // Get existing credentials to exclude from registration
                    List<PasskeyCredential> existingCredentials = credentialRepository.findByUsername(username);
                    List<String> excludeCredentials = existingCredentials.stream()
                        .map(PasskeyCredential::getCredentialId)
                        .collect(Collectors.toList());

                    // Generate registration options
                    PublicKeyCredentialCreationOptions options = webAuthnManager.generateRegistrationOptions(
                        username,
                        userId,
                        excludeCredentials
                    );

                    // Store challenge
                    String challengeId = UUID.randomUUID().toString();
                    byte[] challengeBytes = options.getChallenge().getValue();
                    Instant now = Instant.now();
                    Challenge challenge = new Challenge(
                        challengeId,
                        challengeBytes,
                        username,
                        Challenge.ChallengeType.REGISTRATION,
                        now,
                        now.plusSeconds(300), // 5 minute expiry
                        null // sessionId - could be extracted from request if needed
                    );
                    challengeStore.storeChallenge(challengeId, challenge);

                    // Build response
                    builder.startObject();
                    builder.field("challengeId", challengeId);
                    builder.field("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes));
                    
                    builder.startObject("rp");
                    builder.field("id", options.getRp().getId());
                    builder.field("name", options.getRp().getName());
                    builder.endObject();
                    
                    builder.startObject("user");
                    builder.field("id", Base64.getUrlEncoder().withoutPadding().encodeToString(options.getUser().getId()));
                    builder.field("name", options.getUser().getName());
                    builder.field("displayName", options.getUser().getDisplayName());
                    builder.endObject();
                    
                    builder.startArray("pubKeyCredParams");
                    final XContentBuilder finalBuilder = builder;
                    options.getPubKeyCredParams().forEach(param -> {
                        try {
                            finalBuilder.startObject();
                            finalBuilder.field("type", param.getType().getValue());
                            finalBuilder.field("alg", param.getAlg().getValue());
                            finalBuilder.endObject();
                        } catch (IOException e) {
                            log.error("Error writing pubKeyCredParams", e);
                        }
                    });
                    builder.endArray();
                    
                    if (options.getTimeout() != null) {
                        builder.field("timeout", options.getTimeout());
                    }
                    
                    if (options.getExcludeCredentials() != null && !options.getExcludeCredentials().isEmpty()) {
                        builder.startArray("excludeCredentials");
                        final XContentBuilder finalBuilder2 = builder;
                        options.getExcludeCredentials().forEach(cred -> {
                            try {
                                finalBuilder2.startObject();
                                finalBuilder2.field("type", cred.getType().getValue());
                                finalBuilder2.field("id", Base64.getUrlEncoder().withoutPadding().encodeToString(cred.getId()));
                                finalBuilder2.endObject();
                            } catch (IOException e) {
                                log.error("Error writing excludeCredentials", e);
                            }
                        });
                        builder.endArray();
                    }
                    
                    if (options.getAuthenticatorSelection() != null) {
                        builder.startObject("authenticatorSelection");
                        if (options.getAuthenticatorSelection().getAuthenticatorAttachment() != null) {
                            builder.field("authenticatorAttachment", options.getAuthenticatorSelection().getAuthenticatorAttachment().getValue());
                        }
                        if (options.getAuthenticatorSelection().getResidentKey() != null) {
                            builder.field("residentKey", options.getAuthenticatorSelection().getResidentKey().getValue());
                        }
                        if (options.getAuthenticatorSelection().getUserVerification() != null) {
                            builder.field("userVerification", options.getAuthenticatorSelection().getUserVerification().getValue());
                        }
                        builder.endObject();
                    }
                    
                    if (options.getAttestation() != null) {
                        builder.field("attestation", options.getAttestation().getValue());
                    }
                    
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error generating registration options", e);
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
        return "Passkey Registration Options Action";
    }
}
