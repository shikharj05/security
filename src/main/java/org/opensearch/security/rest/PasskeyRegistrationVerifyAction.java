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
import java.util.Optional;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auth.passkey.Challenge;
import org.opensearch.security.auth.passkey.ChallengeStore;
import org.opensearch.security.auth.passkey.PasskeyAuditLogger;
import org.opensearch.security.auth.passkey.PasskeyCredential;
import org.opensearch.security.auth.passkey.PasskeyCredentialRepository;
import org.opensearch.security.auth.passkey.PasskeyMetadata;
import org.opensearch.security.auth.passkey.WebAuthnException;
import org.opensearch.security.auth.passkey.WebAuthnManager;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST action to verify passkey registration response.
 * Handles POST /_plugins/_security/api/passkey/registration/verify
 */
public class PasskeyRegistrationVerifyAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(PasskeyRegistrationVerifyAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new Route(POST, "/passkey/registration/verify")),
        PLUGIN_ROUTE_PREFIX
    );

    private final WebAuthnManager webAuthnManager;
    private final ChallengeStore challengeStore;
    private final PasskeyCredentialRepository credentialRepository;
    private final ThreadContext threadContext;
    private final PasskeyAuditLogger auditLogger;

    public PasskeyRegistrationVerifyAction(
        final Settings settings,
        final RestController controller,
        final WebAuthnManager webAuthnManager,
        final ChallengeStore challengeStore,
        final PasskeyCredentialRepository credentialRepository,
        final ThreadPool threadPool,
        final AuditLog auditLog
    ) {
        super();
        this.webAuthnManager = webAuthnManager;
        this.challengeStore = challengeStore;
        this.credentialRepository = credentialRepository;
        this.threadContext = threadPool.getThreadContext();
        this.auditLogger = new PasskeyAuditLogger(auditLog);
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
                    // Extract authenticated user
                    final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    if (user == null) {
                        builder.startObject();
                        builder.field("error", "User not authenticated");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.UNAUTHORIZED, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    String username = user.getName();
                    
                    // Create SecurityRequest for audit logging
                    SecurityRequest securityRequest = SecurityRequestFactory.from(request);

                    // Parse request body
                    Map<String, Object> requestBody = request.contentParser().map();
                    
                    // Extract username if provided (for admin to register for others)
                    String requestedUsername = (String) requestBody.get("username");
                    if (requestedUsername != null && !requestedUsername.isEmpty()) {
                        // Only allow admin to register for other users
                        if (user.getRoles().contains("all_access") || user.getName().equals("admin")) {
                            username = requestedUsername;
                        }
                    }
                    
                    String challengeId = (String) requestBody.get("challengeId");
                    String friendlyName = (String) requestBody.get("friendlyName");
                    
                    // Parse credential from request body (WebAuthn format)
                    @SuppressWarnings("unchecked")
                    Map<String, Object> credentialMap = (Map<String, Object>) requestBody.get("credential");
                    if (credentialMap == null) {
                        builder.startObject();
                        builder.field("error", "Missing credential object");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> credentialResponse = (Map<String, Object>) credentialMap.get("response");
                    if (credentialResponse == null) {
                        builder.startObject();
                        builder.field("error", "Missing credential.response");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }
                    
                    String clientDataJSON = (String) credentialResponse.get("clientDataJSON");
                    String attestationObject = (String) credentialResponse.get("attestationObject");
                    
                    if (challengeId == null || clientDataJSON == null || attestationObject == null) {
                        builder.startObject();
                        builder.field("error", "Missing required fields: challengeId, clientDataJSON, attestationObject");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Consume challenge (single-use)
                    Optional<Challenge> challengeOpt = challengeStore.consumeChallenge(challengeId);
                    if (!challengeOpt.isPresent()) {
                        auditLogger.logRegistrationFailure(username, "Invalid or expired challenge", securityRequest);
                        builder.startObject();
                        builder.field("error", "Invalid or expired challenge");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    Challenge challenge = challengeOpt.get();

                    // Verify the challenge belongs to this user
                    if (!username.equals(challenge.getUsername())) {
                        builder.startObject();
                        builder.field("error", "Challenge does not belong to authenticated user");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Get origin from request
                    String origin = request.header("Origin");
                    if (origin == null) {
                        origin = request.header("Referer");
                        if (origin != null) {
                            // Extract origin from referer
                            int idx = origin.indexOf("://");
                            if (idx > 0) {
                                int endIdx = origin.indexOf("/", idx + 3);
                                if (endIdx > 0) {
                                    origin = origin.substring(0, endIdx);
                                }
                            }
                        }
                    }

                    if (origin == null) {
                        builder.startObject();
                        builder.field("error", "Origin header required");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Verify attestation
                    WebAuthnManager.RegistrationResult result;
                    try {
                        result = webAuthnManager.verifyRegistrationResponse(
                            clientDataJSON,
                            attestationObject,
                            challenge.getChallengeBytes(),
                            origin
                        );
                    } catch (WebAuthnException e) {
                        log.error("Attestation verification failed", e);
                        auditLogger.logRegistrationFailure(username, "Attestation verification failed: " + e.getMessage(), securityRequest);
                        builder.startObject();
                        builder.field("error", "Attestation verification failed: " + e.getMessage());
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Create credential metadata
                    PasskeyMetadata metadata = new PasskeyMetadata(
                        friendlyName != null ? friendlyName : "Passkey",
                        "unknown", // deviceType - could be extracted from attestation
                        request.header("User-Agent")
                    );

                    // Store credential
                    String credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(result.getCredentialId());
                    PasskeyCredential credential = new PasskeyCredential(
                        credentialId,
                        username,
                        result.getPublicKey(),
                        result.getSignatureCounter(),
                        result.getAaguid(),
                        result.getTransports(),
                        metadata,
                        Instant.now(),
                        null, // lastUsedAt
                        result.isBackupEligible(),
                        result.isBackupState()
                    );

                    credentialRepository.storeCredential(credential);

                    // Log successful registration
                    auditLogger.logRegistrationSuccess(username, credentialId, securityRequest);
                    log.info("Passkey registered successfully for user: {}, credentialId: {}", username, credentialId);

                    // Build success response
                    builder.startObject();
                    builder.field("success", true);
                    builder.field("credentialId", credentialId);
                    builder.field("message", "Passkey registered successfully");
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error verifying registration", e);
                    
                    // Log registration failure
                    try {
                        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                        String username = user != null ? user.getName() : null;
                        SecurityRequest securityRequest = SecurityRequestFactory.from(request);
                        auditLogger.logRegistrationFailure(username, e.getMessage(), securityRequest);
                    } catch (Exception auditEx) {
                        log.error("Failed to log audit event", auditEx);
                    }
                    
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
        return "Passkey Registration Verify Action";
    }
}
