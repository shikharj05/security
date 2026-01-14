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
import org.opensearch.security.auth.passkey.PasskeyAuditLogger;
import org.opensearch.security.auth.passkey.PasskeyCredential;
import org.opensearch.security.auth.passkey.PasskeyCredentialRepository;
import org.opensearch.security.auth.passkey.PasskeyMetadata;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.DELETE;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * REST action for passkey credential management.
 * Handles:
 * - POST /_plugins/_security/api/passkey/credentials/list (list)
 * - DELETE /_plugins/_security/api/passkey/credentials/{id} (delete)
 * - PUT /_plugins/_security/api/passkey/credentials/{id} (update)
 */
public class PasskeyCredentialManagementAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(PasskeyCredentialManagementAction.class);

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(
            new Route(POST, "/passkey/credentials/list"),
            new Route(DELETE, "/passkey/credentials/{credentialId}"),
            new Route(PUT, "/passkey/credentials/{credentialId}")
        ),
        PLUGIN_ROUTE_PREFIX
    );

    private final PasskeyCredentialRepository credentialRepository;
    private final ThreadContext threadContext;
    private final PasskeyAuditLogger auditLogger;

    public PasskeyCredentialManagementAction(
        final Settings settings,
        final RestController controller,
        final PasskeyCredentialRepository credentialRepository,
        final ThreadPool threadPool,
        final AuditLog auditLog
    ) {
        super();
        this.credentialRepository = credentialRepository;
        this.threadContext = threadPool.getThreadContext();
        this.auditLogger = new PasskeyAuditLogger(auditLog);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    public String getName() {
        return "Passkey Credential Management Action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        final RestRequest.Method method = request.method();
        
        if (method == POST) {
            return handleList(request);
        } else if (method == DELETE) {
            return handleDelete(request);
        } else if (method == PUT) {
            return handleUpdate(request);
        } else {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }
    }

    private RestChannelConsumer handleList(RestRequest request) {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
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

                    String username = user.getName();
                    
                    // Allow admin to query by username in request body
                    if (request.hasContent()) {
                        Map<String, Object> requestBody = request.contentParser().map();
                        String requestedUsername = (String) requestBody.get("username");
                        if (requestedUsername != null && !requestedUsername.isEmpty()) {
                            // Only allow admin to query other users
                            if (user.getRoles().contains("all_access") || user.getName().equals("admin")) {
                                username = requestedUsername;
                            }
                        }
                    }

                    // Get all credentials for the user
                    List<PasskeyCredential> credentials = credentialRepository.findByUsername(username);

                    // Build response with credential metadata
                    builder.startObject();
                    builder.field("username", username);
                    builder.startArray("credentials");
                    
                    for (PasskeyCredential credential : credentials) {
                        builder.startObject();
                        builder.field("credentialId", credential.getCredentialId());
                        builder.field("username", credential.getUsername());  // Add username field
                        builder.field("friendlyName", credential.getMetadata().getFriendlyName());
                        builder.field("deviceType", credential.getMetadata().getDeviceType());
                        builder.field("createdAt", credential.getCreatedAt().toString());
                        if (credential.getLastUsedAt() != null) {
                            builder.field("lastUsedAt", credential.getLastUsedAt().toString());
                        } else {
                            builder.nullField("lastUsedAt");
                        }
                        if (credential.getTransports() != null && !credential.getTransports().isEmpty()) {
                            builder.field("transports", credential.getTransports());
                        }
                        builder.endObject();
                    }
                    
                    builder.endArray();
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error listing credentials", e);
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

    private RestChannelConsumer handleDelete(RestRequest request) {
        final String credentialId = request.param("credentialId");
        
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
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

                    String username = user.getName();

                    // Verify the credential belongs to the user
                    Optional<PasskeyCredential> credentialOpt = credentialRepository.findByCredentialId(credentialId);
                    if (!credentialOpt.isPresent()) {
                        builder.startObject();
                        builder.field("error", "Credential not found");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.NOT_FOUND, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    PasskeyCredential credential = credentialOpt.get();
                    
                    // Allow admin to delete any credential, otherwise only own credentials
                    boolean isAdmin = user.getRoles().contains("all_access") || user.getName().equals("admin");
                    if (!credential.getUsername().equals(username) && !isAdmin) {
                        builder.startObject();
                        builder.field("error", "Unauthorized: credential belongs to another user");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Delete the credential
                    credentialRepository.deleteCredential(credentialId);

                    // Log credential deletion
                    SecurityRequest securityRequest = SecurityRequestFactory.from(request);
                    auditLogger.logCredentialDeleted(username, credentialId, securityRequest);
                    
                    log.info("Credential deleted: {} for user: {}", credentialId, username);

                    // Build success response
                    builder.startObject();
                    builder.field("success", true);
                    builder.field("message", "Credential deleted successfully");
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error deleting credential", e);
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

    private RestChannelConsumer handleUpdate(RestRequest request) throws IOException {
        final String credentialId = request.param("credentialId");
        
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
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

                    String username = user.getName();

                    // Parse request body
                    Map<String, Object> requestBody = request.contentParser().map();
                    String friendlyName = (String) requestBody.get("friendlyName");

                    if (friendlyName == null || friendlyName.isEmpty()) {
                        builder.startObject();
                        builder.field("error", "Missing required field: friendlyName");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Verify the credential belongs to the user
                    Optional<PasskeyCredential> credentialOpt = credentialRepository.findByCredentialId(credentialId);
                    if (!credentialOpt.isPresent()) {
                        builder.startObject();
                        builder.field("error", "Credential not found");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.NOT_FOUND, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    PasskeyCredential credential = credentialOpt.get();
                    
                    // Allow admin to update any credential, otherwise only own credentials
                    boolean isAdmin = user.getRoles().contains("all_access") || user.getName().equals("admin");
                    if (!credential.getUsername().equals(username) && !isAdmin) {
                        builder.startObject();
                        builder.field("error", "Unauthorized: credential belongs to another user");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                        channel.sendResponse(response);
                        return;
                    }

                    // Update the metadata
                    PasskeyMetadata updatedMetadata = new PasskeyMetadata(
                        friendlyName,
                        credential.getMetadata().getDeviceType(),
                        credential.getMetadata().getUserAgent()
                    );
                    credentialRepository.updateCredentialMetadata(credentialId, updatedMetadata);

                    // Log credential update
                    SecurityRequest securityRequest = SecurityRequestFactory.from(request);
                    auditLogger.logCredentialUpdated(username, credentialId, securityRequest);
                    
                    log.info("Credential metadata updated: {} for user: {}", credentialId, username);

                    // Build success response
                    builder.startObject();
                    builder.field("success", true);
                    builder.field("message", "Credential updated successfully");
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e) {
                    log.error("Error updating credential", e);
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
}
