/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.security.auth.passkey;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.transport.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * OpenSearch-backed implementation of PasskeyCredentialRepository.
 * Stores all passkey credentials in a single document in the main security index,
 * following the same pattern as internal users.
 * 
 * Document ID: "passkey_credentials"
 * Index: .opendistro_security
 */
public class OpenSearchPasskeyCredentialRepository implements PasskeyCredentialRepository {

    private static final Logger log = LogManager.getLogger(OpenSearchPasskeyCredentialRepository.class);

    private static final String DOCUMENT_ID = "passkeycredentials";
    private final Client client;
    private final String securityIndex;
    private final ThreadPool threadPool;

    public OpenSearchPasskeyCredentialRepository(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
        this.securityIndex = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;
    }

    /**
     * Load the passkey credentials document from the security index.
     * Uses privileged context on generic thread pool to bypass security checks.
     */
    private PasskeyCredentialsDocument loadDocument() {
        try {
            return threadPool.generic().submit(() -> {
                try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                    threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                    
                    try {
                        GetRequest getRequest = new GetRequest(securityIndex, DOCUMENT_ID);
                        GetResponse response = client.get(getRequest).actionGet();

                        if (!response.isExists()) {
                            log.debug("Passkey credentials document does not exist, returning empty");
                            return new PasskeyCredentialsDocument();
                        }

                        try (XContentParser parser = XContentType.JSON.xContent().createParser(
                            null, null, response.getSourceAsBytes())) {
                            return PasskeyCredentialsDocument.fromXContent(parser);
                        }
                    } catch (IOException e) {
                        log.error("Failed to load passkey credentials document", e);
                        return new PasskeyCredentialsDocument();
                    }
                }
            }).get(); // Block until complete
        } catch (Exception e) {
            log.error("Failed to submit load operation", e);
            return new PasskeyCredentialsDocument();
        }
    }

    /**
     * Save the passkey credentials document to the security index.
     * Uses privileged context on generic thread pool to bypass security checks.
     */
    private void saveDocument(PasskeyCredentialsDocument document) {
        // Submit to generic thread pool to avoid security filter on REST thread
        try {
            threadPool.generic().submit(() -> {
                try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                    // Set header to bypass security checks
                    threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
                    
                    try {
                        XContentBuilder builder = jsonBuilder();
                        document.toXContent(builder, null);

                        IndexRequest indexRequest = new IndexRequest(securityIndex)
                            .id(DOCUMENT_ID)
                            .source(builder)
                            .setRefreshPolicy("wait_for");

                        IndexResponse response = client.index(indexRequest).actionGet();

                        if (response.status() == RestStatus.CREATED || response.status() == RestStatus.OK) {
                            log.debug("Saved passkey credentials document");
                        } else {
                            log.warn("Unexpected response status when saving document: {}", response.status());
                        }
                    } catch (IOException e) {
                        log.error("Failed to save passkey credentials document", e);
                        throw new RuntimeException("Failed to save passkey credentials", e);
                    }
                }
            }).get(); // Block until complete
        } catch (Exception e) {
            log.error("Failed to submit save operation", e);
            throw new RuntimeException("Failed to save passkey credentials", e);
        }
    }

    @Override
    public void storeCredential(PasskeyCredential credential) {
        synchronized (this) {
            PasskeyCredentialsDocument document = loadDocument();
            document.putCredential(credential);
            saveDocument(document);
            log.debug("Stored passkey credential {} for user {}", 
                credential.getCredentialId(), credential.getUsername());
        }
    }

    @Override
    public Optional<PasskeyCredential> findByCredentialId(String credentialId) {
        PasskeyCredentialsDocument document = loadDocument();
        PasskeyCredential credential = document.getCredential(credentialId);
        
        if (credential != null) {
            log.debug("Found credential {} for user {}", credentialId, credential.getUsername());
        } else {
            log.debug("Credential {} not found", credentialId);
        }
        
        return Optional.ofNullable(credential);
    }

    @Override
    public List<PasskeyCredential> findByUsername(String username) {
        PasskeyCredentialsDocument document = loadDocument();
        List<PasskeyCredential> credentials = document.getCredentials().values().stream()
            .filter(cred -> cred.getUsername().equals(username))
            .collect(Collectors.toList());
        
        log.debug("Found {} credentials for user {}", credentials.size(), username);
        return credentials;
    }

    @Override
    public void deleteCredential(String credentialId) {
        synchronized (this) {
            PasskeyCredentialsDocument document = loadDocument();
            document.removeCredential(credentialId);
            saveDocument(document);
            log.debug("Deleted credential {}", credentialId);
        }
    }

    @Override
    public void updateCredentialMetadata(String credentialId, PasskeyMetadata metadata) {
        synchronized (this) {
            PasskeyCredentialsDocument document = loadDocument();
            PasskeyCredential credential = document.getCredential(credentialId);
            
            if (credential == null) {
                log.warn("Cannot update metadata - credential {} not found", credentialId);
                return;
            }
            
            // Create updated credential with new metadata
            PasskeyCredential updated = new PasskeyCredential(
                credential.getCredentialId(),
                credential.getUsername(),
                credential.getPublicKey(),
                credential.getSignatureCounter(),
                credential.getAaguid(),
                credential.getTransports(),
                metadata,
                credential.getCreatedAt(),
                credential.getLastUsedAt(),
                credential.isBackupEligible(),
                credential.isBackupState()
            );
            
            document.putCredential(updated);
            saveDocument(document);
            log.debug("Updated metadata for credential {}", credentialId);
        }
    }

    @Override
    public void updateSignatureCounter(String credentialId, long counter) {
        synchronized (this) {
            PasskeyCredentialsDocument document = loadDocument();
            PasskeyCredential credential = document.getCredential(credentialId);
            
            if (credential == null) {
                log.warn("Cannot update counter - credential {} not found", credentialId);
                return;
            }
            
            // Create updated credential with new counter
            PasskeyCredential updated = new PasskeyCredential(
                credential.getCredentialId(),
                credential.getUsername(),
                credential.getPublicKey(),
                counter,
                credential.getAaguid(),
                credential.getTransports(),
                credential.getMetadata(),
                credential.getCreatedAt(),
                credential.getLastUsedAt(),
                credential.isBackupEligible(),
                credential.isBackupState()
            );
            
            document.putCredential(updated);
            saveDocument(document);
            log.debug("Updated signature counter for credential {} to {}", credentialId, counter);
        }
    }

    @Override
    public void updateLastUsed(String credentialId) {
        synchronized (this) {
            PasskeyCredentialsDocument document = loadDocument();
            PasskeyCredential credential = document.getCredential(credentialId);
            
            if (credential == null) {
                log.warn("Cannot update last used - credential {} not found", credentialId);
                return;
            }
            
            // Create updated credential with new last used timestamp
            PasskeyCredential updated = new PasskeyCredential(
                credential.getCredentialId(),
                credential.getUsername(),
                credential.getPublicKey(),
                credential.getSignatureCounter(),
                credential.getAaguid(),
                credential.getTransports(),
                credential.getMetadata(),
                credential.getCreatedAt(),
                Instant.now(),
                credential.isBackupEligible(),
                credential.isBackupState()
            );
            
            document.putCredential(updated);
            saveDocument(document);
            log.debug("Updated last used timestamp for credential {}", credentialId);
        }
    }
}
