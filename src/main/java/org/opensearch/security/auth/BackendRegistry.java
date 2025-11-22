/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auth;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Multimap;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.identity.UserSubject;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.blocking.ClientBlockRegistry;
import org.opensearch.security.auth.internal.NoOpAuthenticationBackend;
import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.auth.plugin.adapter.AuthenticationBackendAdapter;
import org.opensearch.security.auth.plugin.adapter.AuthorizationBackendAdapter;
import org.opensearch.security.auth.plugin.config.AuthenticationPluginConfig;
import org.opensearch.security.auth.plugin.config.AuthorizationPluginConfig;
import org.opensearch.security.auth.plugin.config.PluginConfigLoader;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.http.XFFResolver;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.HostAndCidrMatcher;
import org.opensearch.security.support.SecuritySettings;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.threadpool.ThreadPool;

import org.greenrobot.eventbus.Subscribe;

import static org.apache.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE;
import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.opensearch.security.auth.http.saml.HTTPSamlAuthenticator.SAML_TYPE;
import static org.opensearch.security.http.HTTPBasicAuthenticator.BASIC_TYPE;

public class BackendRegistry {

    protected static final Logger log = LogManager.getLogger(BackendRegistry.class);
    private SortedSet<AuthDomain> restAuthDomains;
    private Set<AuthorizationBackend> restAuthorizers;

    // New plugin architecture support
    private final List<AuthenticationPlugin> authenticationPlugins;
    private final List<AuthorizationPlugin> authorizationPlugins;

    private List<AuthFailureListener> ipAuthFailureListeners;
    private Multimap<String, AuthFailureListener> authBackendFailureListeners;
    private List<ClientBlockRegistry<InetAddress>> ipClientBlockRegistries;
    private Multimap<String, ClientBlockRegistry<String>> authBackendClientBlockRegistries;
    private String hostResolverMode;

    private volatile boolean initialized;
    private volatile boolean injectedUserEnabled = false;
    private final AdminDNs adminDns;
    private final XFFResolver xffResolver;
    private volatile boolean anonymousAuthEnabled = false;
    private final Settings opensearchSettings;
    private final AuditLog auditLog;
    private final ThreadPool threadPool;
    private final UserInjector userInjector;
    private final ClusterInfoHolder clusterInfoHolder;
    private int ttlInMin;
    private Cache<AuthCredentials, User> userCache; // rest standard
    private Cache<String, User> restImpersonationCache; // used for rest impersonation
    private Cache<User, Set<String>> restRoleCache; //
    
    // New plugin architecture caches
    private Cache<AuthCredentials, UserPrincipal> userPrincipalCache; // cache for UserPrincipal objects
    private Cache<UserPrincipal, Set<String>> principalRoleCache; // cache for resolved permissions

    private void createCaches() {
        userCache = CacheBuilder.newBuilder()
            .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
            .removalListener(new RemovalListener<AuthCredentials, User>() {
                @Override
                public void onRemoval(RemovalNotification<AuthCredentials, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey().getUsername(), notification.getCause());
                }
            })
            .build();

        restImpersonationCache = CacheBuilder.newBuilder()
            .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
            .removalListener(new RemovalListener<String, User>() {
                @Override
                public void onRemoval(RemovalNotification<String, User> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                }
            })
            .build();

        restRoleCache = CacheBuilder.newBuilder()
            .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
            .removalListener(new RemovalListener<User, Set<String>>() {
                @Override
                public void onRemoval(RemovalNotification<User, Set<String>> notification) {
                    log.debug("Clear user cache for {} due to {}", notification.getKey(), notification.getCause());
                }
            })
            .build();

        // New plugin architecture caches
        userPrincipalCache = CacheBuilder.newBuilder()
            .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
            .removalListener(new RemovalListener<AuthCredentials, UserPrincipal>() {
                @Override
                public void onRemoval(RemovalNotification<AuthCredentials, UserPrincipal> notification) {
                    log.debug(
                        "Clear UserPrincipal cache for {} due to {}",
                        notification.getKey().getUsername(),
                        notification.getCause()
                    );
                }
            })
            .build();

        principalRoleCache = CacheBuilder.newBuilder()
            .expireAfterWrite(ttlInMin, TimeUnit.MINUTES)
            .removalListener(new RemovalListener<UserPrincipal, Set<String>>() {
                @Override
                public void onRemoval(RemovalNotification<UserPrincipal, Set<String>> notification) {
                    log.debug(
                        "Clear principal role cache for {} due to {}",
                        notification.getKey().getName(),
                        notification.getCause()
                    );
                }
            })
            .build();
    }

    public void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(SecuritySettings.CACHE_TTL_SETTING, newTtlInMin -> {
            log.info("Detected change in settings, cluster setting for TTL is {}", newTtlInMin);

            ttlInMin = newTtlInMin;
            createCaches();
        });
    }

    public BackendRegistry(
        final Settings settings,
        final AdminDNs adminDns,
        final XFFResolver xffResolver,
        final AuditLog auditLog,
        final ThreadPool threadPool,
        final ClusterInfoHolder clusterInfoHolder
    ) {
        this.adminDns = adminDns;
        this.opensearchSettings = settings;
        this.xffResolver = xffResolver;
        this.auditLog = auditLog;
        this.threadPool = threadPool;
        this.clusterInfoHolder = clusterInfoHolder;
        this.userInjector = new UserInjector(settings, threadPool, auditLog, xffResolver);
        this.restAuthDomains = Collections.emptySortedSet();
        this.ipAuthFailureListeners = Collections.emptyList();

        // Initialize plugin lists
        this.authenticationPlugins = new ArrayList<>();
        this.authorizationPlugins = new ArrayList<>();

        this.ttlInMin = settings.getAsInt(ConfigConstants.SECURITY_CACHE_TTL_MINUTES, 60);

        // This is going to be defined in the opensearch.yml, so it's best suited to be initialized once.
        this.injectedUserEnabled = opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false);
        initialized = this.injectedUserEnabled;

        createCaches();
    }

    public boolean isInitialized() {
        return initialized;
    }

    public int getTtlInMin() {
        return ttlInMin;
    }

    public void invalidateCache() {
        userCache.invalidateAll();
        restImpersonationCache.invalidateAll();
        restRoleCache.invalidateAll();
        
        // Invalidate new plugin architecture caches
        userPrincipalCache.invalidateAll();
        principalRoleCache.invalidateAll();
    }

    public void invalidateUserCache(String[] usernames) {
        if (usernames == null || usernames.length == 0) {
            log.warn("No usernames given, not invalidating user cache.");
            return;
        }

        Set<String> usernamesAsSet = new HashSet<>(Arrays.asList(usernames));

        // Invalidate entries in the userCache by iterating over the keys and matching the username.
        userCache.asMap()
            .keySet()
            .stream()
            .filter(authCreds -> usernamesAsSet.contains(authCreds.getUsername()))
            .forEach(userCache::invalidate);

        // Invalidate entries in the restImpersonationCache directly since it uses the username as the key.
        restImpersonationCache.invalidateAll(usernamesAsSet);

        // Invalidate entries in the restRoleCache by iterating over the keys and matching the username.
        restRoleCache.asMap().keySet().stream().filter(user -> usernamesAsSet.contains(user.getName())).forEach(restRoleCache::invalidate);

        // Invalidate entries in the new plugin architecture caches
        userPrincipalCache.asMap()
            .keySet()
            .stream()
            .filter(authCreds -> usernamesAsSet.contains(authCreds.getUsername()))
            .forEach(userPrincipalCache::invalidate);

        principalRoleCache.asMap()
            .keySet()
            .stream()
            .filter(principal -> usernamesAsSet.contains(principal.getName()))
            .forEach(principalRoleCache::invalidate);

        // If the user isn't found it still says this, which could be bad
        log.debug("Cache invalidated for all valid users from list: {}", String.join(", ", usernamesAsSet));
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {

        invalidateCache();
        anonymousAuthEnabled = dcm.isAnonymousAuthenticationEnabled()// config.dynamic.http.anonymous_auth_enabled
            && !opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false);

        restAuthDomains = Collections.unmodifiableSortedSet(dcm.getRestAuthDomains());
        restAuthorizers = Collections.unmodifiableSet(dcm.getRestAuthorizers());

        ipAuthFailureListeners = dcm.getIpAuthFailureListeners();
        authBackendFailureListeners = dcm.getAuthBackendFailureListeners();
        ipClientBlockRegistries = dcm.getIpClientBlockRegistries();
        authBackendClientBlockRegistries = dcm.getAuthBackendClientBlockRegistries();
        hostResolverMode = dcm.getHostsResolverMode();

        // OpenSearch Security no default authc
        initialized = !restAuthDomains.isEmpty() || anonymousAuthEnabled || injectedUserEnabled;
    }

    /**
     *
     * @param request
     * @return The authenticated user, null means another roundtrip
     * @throws OpenSearchSecurityException
     */
    public boolean authenticate(final SecurityRequestChannel request) {
        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isBlockedBasedOnAddress = request.getRemoteAddress()
            .map(InetSocketAddress::getAddress)
            .map(this::isBlocked)
            .orElse(false);
        if (isBlockedBasedOnAddress) {
            if (isDebugEnabled) {
                InetSocketAddress ipAddress = request.getRemoteAddress().orElse(null);
                log.debug(
                    "Rejecting REST request because of blocked address: {}",
                    ipAddress != null ? "/" + ipAddress.getAddress().getHostAddress() : null
                );
            }

            request.queueForSending(new SecurityResponse(SC_UNAUTHORIZED, "Authentication finally failed"));
            return false;
        }

        ThreadContext threadContext = this.threadPool.getThreadContext();

        final String sslPrincipal = (String) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);

        if (adminDns.isAdminDN(sslPrincipal)) {
            // PKI authenticated REST call
            User superuser = new User(sslPrincipal);
            UserSubject subject = new UserSubjectImpl(threadPool, superuser);
            threadContext.putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, superuser);
            return true;
        }

        if (userInjector.injectUser(request)) {
            // ThreadContext injected user
            return true;
        }

        if (!isInitialized()) {
            StringBuilder error = new StringBuilder("OpenSearch Security not initialized.");
            if (!clusterInfoHolder.hasClusterManager()) {
                error.append(String.format(" %s", ClusterInfoHolder.CLUSTER_MANAGER_NOT_PRESENT));
            }
            log.error("{} (you may need to run securityadmin)", error.toString());
            request.queueForSending(new SecurityResponse(SC_SERVICE_UNAVAILABLE, error.toString()));
            return false;
        }

        final TransportAddress remoteAddress = xffResolver.resolve(request);
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("Rest authentication request from {} [original: {}]", remoteAddress, request.getRemoteAddress().orElse(null));
        }

        threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, remoteAddress);

        boolean authenticated = false;

        User authenticatedUser = null;

        AuthCredentials authCredentials = null;

        HTTPAuthenticator firstChallengingHttpAuthenticator = null;

        // loop over all http/rest auth domains
        for (final AuthDomain authDomain : restAuthDomains) {
            if (isDebugEnabled) {
                log.debug(
                    "Check authdomain for rest {}/{} or {} in total",
                    authDomain.getBackend().getType(),
                    authDomain.getOrder(),
                    restAuthDomains.size()
                );
            }

            final HTTPAuthenticator httpAuthenticator = authDomain.getHttpAuthenticator();

            if (authDomain.isChallenge() && firstChallengingHttpAuthenticator == null) {
                firstChallengingHttpAuthenticator = httpAuthenticator;
            }

            if (isTraceEnabled) {
                log.trace("Try to extract auth creds from {} http authenticator", httpAuthenticator.getType());
            }
            final AuthCredentials ac;
            try {
                ac = httpAuthenticator.extractCredentials(request, threadPool.getThreadContext());
            } catch (Exception e1) {
                if (isDebugEnabled) {
                    log.debug("'{}' extracting credentials from {} http authenticator", e1.toString(), httpAuthenticator.getType(), e1);
                }
                continue;
            }

            if (ac != null && isBlocked(authDomain.getBackend().getClass().getName(), ac.getUsername())) {
                if (isDebugEnabled) {
                    log.debug("Rejecting REST request because of blocked user: {}, authDomain: {}", ac.getUsername(), authDomain);
                }

                continue;
            }

            authCredentials = ac;

            if (ac == null) {
                // no credentials found in request
                if (anonymousAuthEnabled && isRequestForAnonymousLogin(request.params(), request.getHeaders())) {
                    continue;
                }

                if (authDomain.isChallenge()) {
                    final Optional<SecurityResponse> restResponse = httpAuthenticator.reRequestAuthentication(request, null);
                    if (restResponse.isPresent()) {
                        // saml will always hit this to re-request authentication
                        if (!authDomain.getHttpAuthenticator().getType().equals(SAML_TYPE)) {
                            auditLog.logFailedLogin("<NONE>", false, null, request);
                        }
                        if (authDomain.getHttpAuthenticator().getType().equals(BASIC_TYPE)) {
                            log.warn("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                        }
                        notifyIpAuthFailureListeners(request, authCredentials);
                        request.queueForSending(restResponse.get());
                        return false;
                    }
                } else {
                    // no reRequest possible
                    if (isTraceEnabled) {
                        log.trace("No 'Authorization' header, send 403");
                    }
                    continue;
                }
            } else {
                org.apache.logging.log4j.ThreadContext.put("user", ac.getUsername());
                if (!ac.isComplete()) {
                    // credentials found in request but we need another client challenge
                    final Optional<SecurityResponse> restResponse = httpAuthenticator.reRequestAuthentication(request, ac);
                    if (restResponse.isPresent()) {
                        notifyIpAuthFailureListeners(request, ac);
                        request.queueForSending(restResponse.get());
                        return false;
                    } else {
                        // no reRequest possible
                        continue;
                    }

                }
            }

            // http completed
            // Try new plugin architecture first if plugins are registered
            AuthenticationContext authContext = new AuthenticationContext(ac);
            UserPrincipal principal = authenticateWithPlugins(authContext);
            
            if (principal != null) {
                // Successfully authenticated with new plugin architecture
                // Convert UserPrincipal to User for backward compatibility
                // Note: We need to resolve authorization roles first
                Set<String> securityRoles = new HashSet<>();
                
                // If authorization plugins are registered, use them to resolve permissions
                if (!authorizationPlugins.isEmpty()) {
                    for (AuthorizationPlugin authzPlugin : authorizationPlugins) {
                        try {
                            Set<String> resolvedRoles = authzPlugin.resolvePermissions(principal);
                            if (resolvedRoles != null) {
                                securityRoles.addAll(resolvedRoles);
                            }
                        } catch (Exception e) {
                            log.error(
                                "Error resolving permissions with plugin {} for user {}: {}",
                                authzPlugin.getType(),
                                principal.getName(),
                                e.getMessage(),
                                e
                            );
                        }
                    }
                }
                
                // Convert UserPrincipal to User
                authenticatedUser = User.fromPrincipal(principal, securityRoles);
                
                if (isDebugEnabled) {
                    log.debug(
                        "Successfully authenticated user {} with plugin architecture (type: {})",
                        authenticatedUser.getName(),
                        principal.getAuthenticationType()
                    );
                }
            } else {
                // Fall back to existing authentication flow
                authenticatedUser = authcz(userCache, restRoleCache, ac, authDomain.getBackend(), restAuthorizers);
            }

            if (authenticatedUser == null) {
                if (isDebugEnabled) {
                    log.debug(
                        "Cannot authenticate rest user {} (or add roles) with authdomain {}/{} of {}, try next",
                        ac.getUsername(),
                        authDomain.getBackend().getType(),
                        authDomain.getOrder(),
                        restAuthDomains
                    );
                }
                for (AuthFailureListener authFailureListener : this.authBackendFailureListeners.get(
                    authDomain.getBackend().getClass().getName()
                )) {
                    authFailureListener.onAuthFailure(
                        request.getRemoteAddress().map(InetSocketAddress::getAddress).orElse(null),
                        ac,
                        request
                    );
                }
                continue;
            }

            if (adminDns.isAdmin(authenticatedUser)) {
                log.error("Cannot authenticate rest user because admin user is not permitted to login via HTTP");
                auditLog.logFailedLogin(authenticatedUser.getName(), true, null, request);
                request.queueForSending(
                    new SecurityResponse(SC_FORBIDDEN, "Cannot authenticate user because admin user is not permitted to login via HTTP")
                );
                return false;
            }

            final String tenant = resolveTenantFrom(request);

            if (isDebugEnabled) {
                log.debug("Rest user '{}' is authenticated", authenticatedUser);
                log.debug("securitytenant '{}'", tenant);
            }

            if (tenant != null) {
                authenticatedUser = authenticatedUser.withRequestedTenant(tenant);
            }

            authenticated = true;
            break;
        }// end looping auth domains

        if (authenticated) {
            final User impersonatedUser = impersonate(request, authenticatedUser);
            final User effectiveUser = impersonatedUser == null ? authenticatedUser : impersonatedUser;
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, effectiveUser);
            threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INITIATING_USER, authenticatedUser.getName());

            UserSubject subject = new UserSubjectImpl(threadPool, effectiveUser);
            threadPool.getThreadContext().putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
        } else {
            if (isDebugEnabled) {
                log.debug("User still not authenticated after checking {} auth domains", restAuthDomains.size());
            }

            Optional<SecurityResponse> challengeResponse = Optional.empty();

            if (firstChallengingHttpAuthenticator != null) {

                if (isDebugEnabled) {
                    log.debug("Rerequest with {}", firstChallengingHttpAuthenticator.getClass());
                }

                challengeResponse = firstChallengingHttpAuthenticator.reRequestAuthentication(request, null);
                if (challengeResponse.isPresent()) {
                    if (isDebugEnabled) {
                        log.debug("Rerequest {} failed", firstChallengingHttpAuthenticator.getClass());
                    }
                }
            }

            if (authCredentials == null && anonymousAuthEnabled && isRequestForAnonymousLogin(request.params(), request.getHeaders())) {
                User anonymousUser = User.ANONYMOUS;

                final String tenant = resolveTenantFrom(request);
                if (tenant != null) {
                    anonymousUser = anonymousUser.withRequestedTenant(tenant);
                }

                // Create UserPrincipal for anonymous user to support new plugin architecture
                UserPrincipal anonymousPrincipal = anonymousUser.toPrincipal();

                // If authorization plugins are registered, use them for anonymous user
                if (!authorizationPlugins.isEmpty()) {
                    if (isDebugEnabled) {
                        log.debug("Authorizing anonymous user with {} authorization plugins", authorizationPlugins.size());
                    }
                    
                    // Create authorization context for anonymous user
                    // Anonymous users typically access public resources, so we don't need specific resource context here
                    // The actual authorization will happen per-request in the security filter
                    
                    // For now, just ensure the anonymous user is properly set up with the principal
                    // The authorization plugins will be invoked during actual resource access
                }

                UserSubject subject = new UserSubjectImpl(threadPool, anonymousUser);

                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, anonymousUser);
                threadPool.getThreadContext().putPersistent(ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER, subject);
                if (isDebugEnabled) {
                    log.debug("Anonymous User is authenticated");
                }
                return true;
            }

            log.warn(
                "Authentication finally failed for {} from {}",
                authCredentials == null ? null : authCredentials.getUsername(),
                remoteAddress
            );
            auditLog.logFailedLogin(authCredentials == null ? null : authCredentials.getUsername(), false, null, request);

            notifyIpAuthFailureListeners(request, authCredentials);

            request.queueForSending(
                challengeResponse.orElseGet(() -> new SecurityResponse(SC_UNAUTHORIZED, "Authentication finally failed"))
            );
            return false;
        }
        return authenticated;
    }

    /**
     * Authorizes a user for a specific action on a resource using the new plugin architecture.
     * This method should be called from REST and transport filters after authentication.
     * 
     * @param user The authenticated user
     * @param action The action being performed (e.g., "cluster:monitor/health", "indices:data/read/search")
     * @param resource The resource being accessed (e.g., index name, cluster name)
     * @return AuthorizationResult indicating whether access is allowed or denied, or null if no plugins configured
     */
    public AuthorizationResult authorize(User user, String action, String resource) {
        if (user == null) {
            log.warn("Cannot authorize null user");
            return AuthorizationResult.deny("No authenticated user provided");
        }

        // Convert User to UserPrincipal for plugin architecture
        UserPrincipal principal = user.toPrincipal();

        // Create authorization context
        AuthorizationContext context = AuthorizationContext.builder(action, resource).build();

        // Try authorization with plugins first
        AuthorizationResult result = authorizeWithPlugins(principal, context);

        if (result != null) {
            // Plugin-based authorization was used
            if (log.isDebugEnabled()) {
                log.debug(
                    "Authorization {} for user {} on action {} for resource {} using plugin architecture",
                    result.isAllowed() ? "allowed" : "denied",
                    user.getName(),
                    action,
                    resource
                );
            }
            return result;
        }

        // No plugins configured, fall back to existing authorization flow
        // This maintains backward compatibility
        if (log.isTraceEnabled()) {
            log.trace(
                "No authorization plugins configured, falling back to existing authorization flow for user {} on action {} for resource {}",
                user.getName(),
                action,
                resource
            );
        }

        // Return null to indicate that the caller should use the existing authorization flow
        return null;
    }

    /**
     * Checks if incoming auth request is from an anonymous user
     * Defaults all requests to yes, to allow anonymous authentication to succeed
     * @param params the query parameters passed in this request
     * @return false only if an explicit `auth_type` param is supplied, and its value is not anonymous, OR
     * if request contains no authorization headers
     * otherwise returns true
     */
    private boolean isRequestForAnonymousLogin(Map<String, String> params, Map<String, List<String>> headers) {
        if (params.containsKey("auth_type")) {
            return params.get("auth_type").equals("anonymous");
        }
        return !headers.containsKey(HttpHeaders.AUTHORIZATION);
    }

    private String resolveTenantFrom(final SecurityRequest request) {
        return Optional.ofNullable(request.header("securitytenant")).orElse(request.header("security_tenant"));
    }

    private void notifyIpAuthFailureListeners(SecurityRequestChannel request, AuthCredentials authCredentials) {
        notifyIpAuthFailureListeners(request.getRemoteAddress().map(InetSocketAddress::getAddress).orElse(null), authCredentials, request);
    }

    private void notifyIpAuthFailureListeners(InetAddress remoteAddress, AuthCredentials authCredentials, Object request) {
        for (AuthFailureListener authFailureListener : this.ipAuthFailureListeners) {
            authFailureListener.onAuthFailure(remoteAddress, authCredentials, request);
        }
    }

    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     *
     * @return null if user cannot b authenticated
     */
    private User checkExistsAndAuthz(
        final Cache<String, User> cache,
        final User user,
        final ImpersonationBackend impersonationBackend,
        final Set<AuthorizationBackend> authorizers
    ) {
        if (user == null) {
            return null;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isTraceEnabled = log.isTraceEnabled();

        try {
            return cache.get(user.getName(), new Callable<User>() { // no cache miss in case of noop
                @Override
                public User call() throws Exception {
                    if (isTraceEnabled) {
                        log.trace(
                            "Credentials for user {} not cached, return from {} backend directly",
                            user.getName(),
                            impersonationBackend.getType()
                        );
                    }

                    Optional<User> impersonatedUser = impersonationBackend.impersonate(user);
                    if (impersonatedUser.isPresent()) {
                        AuthenticationContext context = new AuthenticationContext(new AuthCredentials(user.getName()));
                        
                        // Use plugin-based authorization if plugins are registered
                        User resultUser = authz(context, impersonatedUser.get(), null, authorizers); // no role cache because no miss here in case of noop
                        
                        return resultUser;
                    }

                    if (isDebugEnabled) {
                        log.debug("User {} does not exist in {}", user.getName(), impersonationBackend.getType());
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            if (isDebugEnabled) {
                log.debug("Can not check and authorize {} due to ", user.getName(), e);
            }
            return null;
        }
    }

    private User authz(
        AuthenticationContext context,
        User authenticatedUser,
        Cache<User, Set<String>> roleCache,
        final Set<AuthorizationBackend> authorizers
    ) {

        if (authenticatedUser == null) {
            return authenticatedUser;
        }

        if (roleCache != null) {

            final Set<String> cachedBackendRoles = roleCache.getIfPresent(authenticatedUser);

            if (cachedBackendRoles != null) {
                return authenticatedUser.withRoles(cachedBackendRoles);
            }
        }

        // Try new plugin architecture first if plugins are registered
        if (!authorizationPlugins.isEmpty()) {
            final boolean isDebugEnabled = log.isDebugEnabled();
            final boolean isTraceEnabled = log.isTraceEnabled();
            
            // Convert User to UserPrincipal for plugin processing
            UserPrincipal principal = authenticatedUser.toPrincipal();
            
            // Check principal role cache first
            Set<String> cachedRoles = principalRoleCache.getIfPresent(principal);
            if (cachedRoles != null) {
                if (isDebugEnabled) {
                    log.debug("Resolved permissions for {} found in principal role cache", principal.getName());
                }
                authenticatedUser = authenticatedUser.withRoles(cachedRoles);
                
                // Also update the User-based role cache for backward compatibility
                if (roleCache != null) {
                    roleCache.put(authenticatedUser, new HashSet<>(cachedRoles));
                }
                
                return authenticatedUser;
            }
            
            if (isDebugEnabled) {
                log.debug(
                    "Resolved permissions for {} not cached, resolving with {} authorization plugin(s)",
                    principal.getName(),
                    authorizationPlugins.size()
                );
            }
            
            // Resolve permissions using authorization plugins
            Set<String> securityRoles = new HashSet<>();
            
            for (AuthorizationPlugin authzPlugin : authorizationPlugins) {
                try {
                    if (isTraceEnabled) {
                        log.trace(
                            "Resolving permissions for {} with plugin {} (type: {})",
                            principal.getName(),
                            authzPlugin.getClass().getSimpleName(),
                            authzPlugin.getType()
                        );
                    }
                    
                    Set<String> resolvedRoles = authzPlugin.resolvePermissions(principal);
                    if (resolvedRoles != null) {
                        securityRoles.addAll(resolvedRoles);
                        
                        if (isDebugEnabled) {
                            log.debug(
                                "Plugin {} (type: {}) resolved {} role(s) for user {}",
                                authzPlugin.getClass().getSimpleName(),
                                authzPlugin.getType(),
                                resolvedRoles.size(),
                                principal.getName()
                            );
                        }
                    }
                } catch (Exception e) {
                    log.error(
                        "Error resolving permissions with plugin {} for user {}: {}",
                        authzPlugin.getType(),
                        principal.getName(),
                        e.getMessage(),
                        e
                    );
                }
            }
            
            // Update user with resolved roles
            authenticatedUser = authenticatedUser.withRoles(securityRoles);
            
            // Cache the resolved roles in both caches
            principalRoleCache.put(principal, new HashSet<>(securityRoles));
            if (roleCache != null) {
                roleCache.put(authenticatedUser, new HashSet<>(authenticatedUser.getRoles()));
            }
            
            return authenticatedUser;
        }

        // Fall back to existing authorization flow
        if (authorizers == null || authorizers.isEmpty()) {
            return authenticatedUser;
        }

        final boolean isTraceEnabled = log.isTraceEnabled();
        for (final AuthorizationBackend ab : authorizers) {
            try {
                if (isTraceEnabled) {
                    log.trace(
                        "Backend roles for {} not cached, return from {} backend directly",
                        authenticatedUser.getName(),
                        ab.getType()
                    );
                }

                authenticatedUser = ab.addRoles(authenticatedUser, context);
            } catch (Exception e) {
                log.error("Cannot retrieve roles for {} from {} due to {}", authenticatedUser, ab.getType(), e.toString(), e);
            }
        }

        if (roleCache != null) {
            roleCache.put(authenticatedUser, new HashSet<String>(authenticatedUser.getRoles()));
        }

        return authenticatedUser;
    }

    /**
     * no auditlog, throw no exception, does also authz for all authorizers
     *
     * @return null if user cannot b authenticated
     */
    private User authcz(
        final Cache<AuthCredentials, User> cache,
        Cache<User, Set<String>> roleCache,
        final AuthCredentials ac,
        final AuthenticationBackend authBackend,
        final Set<AuthorizationBackend> authorizers
    ) {
        if (ac == null) {
            return null;
        }

        AuthenticationContext context = new AuthenticationContext(ac);

        try {
            // Try new plugin architecture first if plugins are registered
            UserPrincipal principal = authenticateWithPlugins(context);
            
            if (principal != null) {
                // Successfully authenticated with new plugin architecture
                // Resolve authorization roles using plugins if available
                Set<String> securityRoles = new HashSet<>();
                
                if (!authorizationPlugins.isEmpty()) {
                    for (AuthorizationPlugin authzPlugin : authorizationPlugins) {
                        try {
                            Set<String> resolvedRoles = authzPlugin.resolvePermissions(principal);
                            if (resolvedRoles != null) {
                                securityRoles.addAll(resolvedRoles);
                            }
                        } catch (Exception e) {
                            log.error(
                                "Error resolving permissions with plugin {} for user {}: {}",
                                authzPlugin.getType(),
                                principal.getName(),
                                e.getMessage(),
                                e
                            );
                        }
                    }
                }
                
                // Convert UserPrincipal to User
                return User.fromPrincipal(principal, securityRoles);
            }

            // Fall back to existing authentication flow
            // noop backend configured and no authorizers
            // that mean authc and authz was completely done via HTTP (like JWT or PKI)
            if (authBackend.getClass() == NoOpAuthenticationBackend.class && authorizers.isEmpty()) {
                // no cache
                return authBackend.authenticate(context);
            }

            return cache.get(ac, new Callable<User>() {
                @Override
                public User call() throws Exception {
                    if (log.isTraceEnabled()) {
                        log.trace(
                            "Credentials for user {} not cached, return from {} backend directly",
                            ac.getUsername(),
                            authBackend.getType()
                        );
                    }
                    final User authenticatedUser = authBackend.authenticate(context);
                    return authz(context, authenticatedUser, roleCache, authorizers);
                }
            });
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Can not authenticate {} due to exception", ac.getUsername(), e);
            }
            return null;
        } finally {
            ac.clearSecrets();
        }
    }

    private User impersonate(final SecurityRequest request, final User originalUser) throws OpenSearchSecurityException {

        final String impersonatedUserHeader = request.header("opendistro_security_impersonate_as");

        if (Strings.isNullOrEmpty(impersonatedUserHeader) || originalUser == null) {
            return null; // nothing to do
        }

        if (!isInitialized()) {
            throw new OpenSearchSecurityException("Could not check for impersonation because OpenSearch Security is not yet initialized");
        }

        if (adminDns.isAdminDN(impersonatedUserHeader)) {
            throw new OpenSearchSecurityException(
                "It is not allowed to impersonate as an adminuser  '" + impersonatedUserHeader + "'",
                RestStatus.FORBIDDEN
            );
        }

        if (!adminDns.isRestImpersonationAllowed(originalUser.getName(), impersonatedUserHeader)) {
            throw new OpenSearchSecurityException(
                "'" + originalUser.getName() + "' is not allowed to impersonate as '" + impersonatedUserHeader + "'",
                RestStatus.FORBIDDEN
            );
        } else {
            final boolean isDebugEnabled = log.isDebugEnabled();
            // loop over all http/rest auth domains
            for (final AuthDomain authDomain : restAuthDomains) {
                if (!(authDomain.getBackend() instanceof ImpersonationBackend impersonationBackend)) {
                    continue;
                }

                if (!authDomain.getHttpAuthenticator().supportsImpersonation()) {
                    continue;
                }

                User impersonatedUser = checkExistsAndAuthz(
                    restImpersonationCache,
                    new User(impersonatedUserHeader),
                    impersonationBackend,
                    restAuthorizers
                );

                if (impersonatedUser == null) {
                    log.debug(
                        "Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists in {}, try next ...",
                        originalUser.getName(),
                        impersonatedUserHeader,
                        impersonationBackend.getType()
                    );
                    continue;
                }

                if (isDebugEnabled) {
                    log.debug(
                        "Impersonate rest user from '{}' to '{}'",
                        originalUser.toStringWithAttributes(),
                        impersonatedUser.toStringWithAttributes()
                    );
                }

                if (originalUser.getRequestedTenant() != null) {
                    impersonatedUser = impersonatedUser.withRequestedTenant(originalUser.getRequestedTenant());
                }

                return impersonatedUser;
            }

            log.debug(
                "Unable to impersonate rest user from '{}' to '{}' because the impersonated user does not exists",
                originalUser.getName(),
                impersonatedUserHeader
            );
            throw new OpenSearchSecurityException("No such user:" + impersonatedUserHeader, RestStatus.FORBIDDEN);
        }

    }

    private boolean isBlocked(InetAddress address) {
        if (this.ipClientBlockRegistries == null || this.ipClientBlockRegistries.isEmpty()) {
            return false;
        }

        for (ClientBlockRegistry<InetAddress> clientBlockRegistry : ipClientBlockRegistries) {
            if (matchesIgnoreHostPatterns(clientBlockRegistry, address, hostResolverMode)) {
                return false;
            }
            if (clientBlockRegistry.isBlocked(address)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesIgnoreHostPatterns(
        ClientBlockRegistry<InetAddress> clientBlockRegistry,
        InetAddress address,
        String hostResolverMode
    ) {
        HostAndCidrMatcher ignoreHostsMatcher = ((AuthFailureListener) clientBlockRegistry).getIgnoreHostsMatcher();
        if (ignoreHostsMatcher == null || address == null) {
            return false;
        }
        return ignoreHostsMatcher.matches(address, hostResolverMode);

    }

    private boolean isBlocked(String authBackend, String userName) {

        if (this.authBackendClientBlockRegistries == null) {
            return false;
        }

        Collection<ClientBlockRegistry<String>> clientBlockRegistries = this.authBackendClientBlockRegistries.get(authBackend);

        if (clientBlockRegistries.isEmpty()) {
            return false;
        }

        for (ClientBlockRegistry<String> clientBlockRegistry : clientBlockRegistries) {
            if (clientBlockRegistry.isBlocked(userName)) {
                return true;
            }
        }

        return false;
    }

    // ========== New Plugin Architecture Registration Methods ==========

    /**
     * Registers an authentication plugin with the backend registry.
     * <p>
     * This method is part of the new plugin architecture that separates authentication
     * and authorization concerns. Authentication plugins verify user credentials and
     * extract claims, returning a {@link org.opensearch.security.user.UserPrincipal}.
     * <p>
     * Plugins are executed in the order they are registered. The first plugin that
     * successfully authenticates a user will be used.
     *
     * @param plugin The authentication plugin to register, must not be null
     * @throws IllegalArgumentException if plugin is null
     * @see AuthenticationPlugin
     * @see #registerAuthenticationBackend(AuthenticationBackend)
     */
    public void registerAuthenticationPlugin(AuthenticationPlugin plugin) {
        if (plugin == null) {
            throw new IllegalArgumentException("Authentication plugin must not be null");
        }

        if (log.isDebugEnabled()) {
            log.debug("Registering authentication plugin: {} (type: {})", plugin.getClass().getSimpleName(), plugin.getType());
        }

        authenticationPlugins.add(plugin);
    }

    /**
     * Registers an authorization plugin with the backend registry.
     * <p>
     * This method is part of the new plugin architecture that separates authentication
     * and authorization concerns. Authorization plugins make access control decisions
     * based on an authenticated {@link org.opensearch.security.user.UserPrincipal}.
     * <p>
     * Plugins are executed in the order they are registered. All registered plugins
     * must allow access for the request to proceed.
     *
     * @param plugin The authorization plugin to register, must not be null
     * @throws IllegalArgumentException if plugin is null
     * @see AuthorizationPlugin
     * @see #registerAuthorizationBackend(AuthorizationBackend)
     */
    public void registerAuthorizationPlugin(AuthorizationPlugin plugin) {
        if (plugin == null) {
            throw new IllegalArgumentException("Authorization plugin must not be null");
        }

        if (log.isDebugEnabled()) {
            log.debug("Registering authorization plugin: {} (type: {})", plugin.getClass().getSimpleName(), plugin.getType());
        }

        authorizationPlugins.add(plugin);
    }

    /**
     * Registers an authentication backend with the backend registry.
     * <p>
     * This method maintains backward compatibility with the existing authentication
     * backend interface. If the backend already implements {@link AuthenticationPlugin},
     * it is registered directly. Otherwise, it is automatically wrapped with an adapter
     * that implements the new {@link AuthenticationPlugin} interface.
     * <p>
     * <b>Adapter Usage:</b> As of the current release, all built-in authentication backends
     * have been converted to implement {@link AuthenticationPlugin} directly. The adapter
     * layer is now ONLY used for third-party custom backends that haven't migrated yet.
     * <p>
     * <b>Note:</b> This method is maintained for backward compatibility with third-party
     * plugins. New code should use {@link #registerAuthenticationPlugin(AuthenticationPlugin)} instead.
     * Third-party plugin developers should migrate to the new interface to eliminate adapter
     * overhead and prepare for eventual removal of the old interface.
     *
     * @param backend The authentication backend to register, must not be null
     * @throws IllegalArgumentException if backend is null
     * @see #registerAuthenticationPlugin(AuthenticationPlugin)
     */
    public void registerAuthenticationBackend(AuthenticationBackend backend) {
        if (backend == null) {
            throw new IllegalArgumentException("Authentication backend must not be null");
        }

        // Check if the backend already implements AuthenticationPlugin
        if (backend instanceof AuthenticationPlugin) {
            // Backend has been converted to implement AuthenticationPlugin directly
            // Register it directly without wrapping
            if (log.isDebugEnabled()) {
                log.debug(
                    "Registering converted authentication backend directly: {} (type: {})",
                    backend.getClass().getSimpleName(),
                    backend.getType()
                );
            }
            registerAuthenticationPlugin((AuthenticationPlugin) backend);
        } else {
            // Backend uses old interface, wrap with adapter
            if (log.isDebugEnabled()) {
                log.debug(
                    "Registering authentication backend (via adapter): {} (type: {})",
                    backend.getClass().getSimpleName(),
                    backend.getType()
                );
            }

            // Wrap the old backend with an adapter and register it as a plugin
            AuthenticationPlugin adapter = new AuthenticationBackendAdapter(backend);
            registerAuthenticationPlugin(adapter);
        }
    }

    /**
     * Registers an authorization backend with the backend registry.
     * <p>
     * This method maintains backward compatibility with the existing authorization
     * backend interface. If the backend already implements {@link AuthorizationPlugin},
     * it is registered directly. Otherwise, it is automatically wrapped with an adapter
     * that implements the new {@link AuthorizationPlugin} interface.
     * <p>
     * <b>Adapter Usage:</b> As of the current release, all built-in authorization backends
     * have been converted to implement {@link AuthorizationPlugin} directly. The adapter
     * layer is now ONLY used for third-party custom backends that haven't migrated yet.
     * <p>
     * <b>Note:</b> This method is maintained for backward compatibility with third-party
     * plugins. New code should use {@link #registerAuthorizationPlugin(AuthorizationPlugin)} instead.
     * Third-party plugin developers should migrate to the new interface to eliminate adapter
     * overhead and prepare for eventual removal of the old interface.
     *
     * @param backend The authorization backend to register, must not be null
     * @throws IllegalArgumentException if backend is null
     * @see #registerAuthorizationPlugin(AuthorizationPlugin)
     */
    public void registerAuthorizationBackend(AuthorizationBackend backend) {
        if (backend == null) {
            throw new IllegalArgumentException("Authorization backend must not be null");
        }

        // Check if the backend already implements AuthorizationPlugin
        if (backend instanceof AuthorizationPlugin) {
            // Backend has been converted to implement AuthorizationPlugin directly
            // Register it directly without wrapping
            if (log.isDebugEnabled()) {
                log.debug(
                    "Registering converted authorization backend directly: {} (type: {})",
                    backend.getClass().getSimpleName(),
                    backend.getType()
                );
            }
            registerAuthorizationPlugin((AuthorizationPlugin) backend);
        } else {
            // Backend uses old interface, wrap with adapter
            if (log.isDebugEnabled()) {
                log.debug(
                    "Registering authorization backend (via adapter): {} (type: {})",
                    backend.getClass().getSimpleName(),
                    backend.getType()
                );
            }

            // Wrap the old backend with an adapter and register it as a plugin
            AuthorizationPlugin adapter = new AuthorizationBackendAdapter(backend);
            registerAuthorizationPlugin(adapter);
        }
    }

    /**
     * Returns an unmodifiable view of the registered authentication plugins.
     * <p>
     * This method is provided for testing and debugging purposes.
     *
     * @return An unmodifiable list of registered authentication plugins
     */
    public List<AuthenticationPlugin> getAuthenticationPlugins() {
        return Collections.unmodifiableList(authenticationPlugins);
    }

    /**
     * Returns an unmodifiable view of the registered authorization plugins.
     * <p>
     * This method is provided for testing and debugging purposes.
     *
     * @return An unmodifiable list of registered authorization plugins
     */
    public List<AuthorizationPlugin> getAuthorizationPlugins() {
        return Collections.unmodifiableList(authorizationPlugins);
    }

    /**
     * Loads and registers plugins from OpenSearch settings.
     * <p>
     * This method reads plugin configurations from the settings and instantiates
     * the appropriate plugin implementations. Plugins are registered in the order
     * specified in the configuration.
     * <p>
     * Configuration format:
     * <pre>
     * plugins.security.authentication:
     *   - type: internal
     *     enabled: true
     *     order: 1
     *   - type: ldap
     *     enabled: true
     *     order: 2
     *     config:
     *       host: ldap.example.com
     * </pre>
     *
     * @param settings The OpenSearch settings containing plugin configurations
     */
    public void loadPluginConfigurations(Settings settings) {
        PluginConfigLoader loader = new PluginConfigLoader();

        // Load authentication plugin configurations
        List<AuthenticationPluginConfig> authConfigs = loader.loadAuthenticationPlugins(settings);
        log.info("Loaded {} authentication plugin configurations", authConfigs.size());

        // Load authorization plugin configurations
        List<AuthorizationPluginConfig> authzConfigs = loader.loadAuthorizationPlugins(settings);
        log.info("Loaded {} authorization plugin configurations", authzConfigs.size());

        // Note: Actual plugin instantiation would happen here in a complete implementation
        // For now, this method demonstrates the configuration loading integration
        // Future tasks will add plugin factory/instantiation logic
    }

    // ========== Cache Conversion Helper Methods ==========

    /**
     * Converts a cached User to a UserPrincipal for plugin processing.
     * <p>
     * This method is used internally to bridge between the existing User-based
     * cache and the new UserPrincipal-based plugin architecture. It allows
     * cached User objects to be used with authorization plugins without
     * re-authentication.
     * <p>
     * <b>Note:</b> This is an internal helper method for cache conversion.
     * The UserPrincipal created here is for internal processing only and
     * should not be serialized for inter-node communication.
     *
     * @param user The cached User object to convert
     * @return A UserPrincipal representation of the User, or null if user is null
     * @see User#toPrincipal()
     */
    private UserPrincipal convertUserToPrincipal(User user) {
        if (user == null) {
            return null;
        }
        return user.toPrincipal();
    }

    /**
     * Converts a cached UserPrincipal to a User for backward compatibility.
     * <p>
     * This method is used internally to bridge between the new UserPrincipal-based
     * plugin architecture and the existing User-based code. It allows UserPrincipal
     * objects from the cache to be used with existing code that expects User objects.
     * <p>
     * <b>Note:</b> This is an internal helper method for cache conversion.
     * The User object created here maintains the serialization format required
     * for inter-node communication.
     *
     * @param principal The cached UserPrincipal to convert
     * @param securityRoles The resolved security roles for the user
     * @return A User representation of the UserPrincipal, or null if principal is null
     * @see User#fromPrincipal(UserPrincipal, Set)
     */
    private User convertPrincipalToUser(UserPrincipal principal, Set<String> securityRoles) {
        if (principal == null) {
            return null;
        }
        return User.fromPrincipal(principal, securityRoles != null ? securityRoles : Collections.emptySet());
    }

    // ========== New Plugin Architecture Authentication Flow ==========

    /**
     * Authenticates a user using registered authentication plugins.
     * <p>
     * This method implements the new plugin-based authentication flow. It iterates
     * through registered {@link AuthenticationPlugin} instances in order, attempting
     * authentication with each plugin that supports the provided credentials.
     * <p>
     * The method returns the {@link UserPrincipal} from the first plugin that
     * successfully authenticates the user. If no plugins are registered, this method
     * returns null, allowing the caller to fall back to the existing authentication flow.
     * <p>
     * <b>Caching:</b> This method uses a cache to avoid repeated authentication calls
     * for the same credentials. The cache is keyed by {@link AuthCredentials} and stores
     * {@link UserPrincipal} objects. Cache entries expire based on the configured TTL.
     * <p>
     * <b>Authentication Flow:</b>
     * <ol>
     *   <li>Check if any authentication plugins are registered</li>
     *   <li>Check the cache for existing UserPrincipal</li>
     *   <li>If not cached, for each plugin in registration order:
     *     <ul>
     *       <li>Check if the plugin supports the credentials</li>
     *       <li>Attempt authentication</li>
     *       <li>Cache and return UserPrincipal on success</li>
     *       <li>Continue to next plugin on failure</li>
     *     </ul>
     *   </li>
     *   <li>Return null if no plugin succeeds</li>
     * </ol>
     * <p>
     * <b>Backward Compatibility:</b> This method is designed to work alongside the
     * existing authentication flow. When no plugins are registered, it returns null,
     * allowing the existing {@link #authcz} method to handle authentication.
     *
     * @param context The authentication context containing credentials and metadata
     * @return UserPrincipal if authentication succeeds, null if no plugins are registered
     *         or all plugins fail to authenticate
     * @see AuthenticationPlugin
     * @see UserPrincipal
     */
    private UserPrincipal authenticateWithPlugins(AuthenticationContext context) {
        // If no plugins are registered, return null to fall back to existing flow
        if (authenticationPlugins.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("No authentication plugins registered, falling back to existing authentication flow");
            }
            return null;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isTraceEnabled = log.isTraceEnabled();
        final AuthCredentials credentials = context.getCredentials();

        if (credentials == null) {
            if (isTraceEnabled) {
                log.trace("No credentials provided, cannot authenticate with plugins");
            }
            return null;
        }

        // Check cache first
        UserPrincipal cachedPrincipal = userPrincipalCache.getIfPresent(credentials);
        if (cachedPrincipal != null) {
            if (isDebugEnabled) {
                log.debug("UserPrincipal for user {} found in cache", credentials.getUsername());
            }
            return cachedPrincipal;
        }

        if (isDebugEnabled) {
            log.debug(
                "UserPrincipal for user {} not cached, attempting authentication with {} plugin(s)",
                credentials.getUsername(),
                authenticationPlugins.size()
            );
        }

        // Iterate through plugins in registration order
        for (AuthenticationPlugin plugin : authenticationPlugins) {
            if (isTraceEnabled) {
                log.trace(
                    "Checking if plugin {} (type: {}) supports credentials for user: {}",
                    plugin.getClass().getSimpleName(),
                    plugin.getType(),
                    credentials.getUsername()
                );
            }

            // Check if this plugin supports the credentials
            if (!plugin.supports(credentials)) {
                if (isTraceEnabled) {
                    log.trace(
                        "Plugin {} (type: {}) does not support credentials for user: {}",
                        plugin.getClass().getSimpleName(),
                        plugin.getType(),
                        credentials.getUsername()
                    );
                }
                continue;
            }

            // Measure execution time for audit logging
            long startTime = System.currentTimeMillis();
            
            try {
                if (isDebugEnabled) {
                    log.debug(
                        "Attempting authentication with plugin {} (type: {}) for user: {}",
                        plugin.getClass().getSimpleName(),
                        plugin.getType(),
                        credentials.getUsername()
                    );
                }
                
                // Attempt authentication with this plugin
                UserPrincipal principal = plugin.authenticate(context);
                
                long executionTimeMs = System.currentTimeMillis() - startTime;

                if (principal != null) {
                    if (isDebugEnabled) {
                        log.debug(
                            "Successfully authenticated user {} with plugin {} (type: {}), caching result",
                            principal.getName(),
                            plugin.getClass().getSimpleName(),
                            plugin.getType()
                        );
                    }
                    
                    // Audit log successful authentication
                    auditLog.logAuthenticationPluginExecution(
                        plugin.getType(),
                        "SUCCESS",
                        executionTimeMs,
                        principal.getName(),
                        principal.getClaims(),
                        null // SecurityRequest not available in this context
                    );
                    
                    // Cache the successful authentication result
                    userPrincipalCache.put(credentials, principal);
                    
                    return principal;
                } else {
                    if (isDebugEnabled) {
                        log.debug(
                            "Plugin {} (type: {}) returned null for user: {}",
                            plugin.getClass().getSimpleName(),
                            plugin.getType(),
                            credentials.getUsername()
                        );
                    }
                    
                    // Audit log failed authentication (null result)
                    auditLog.logAuthenticationPluginExecution(
                        plugin.getType(),
                        "FAILED_NULL_RESULT",
                        executionTimeMs,
                        credentials.getUsername(),
                        Collections.emptyMap(),
                        null
                    );
                }
            } catch (org.opensearch.security.auth.plugin.AuthenticationException e) {
                long executionTimeMs = System.currentTimeMillis() - startTime;
                
                // Authentication failed with this plugin, try next
                if (isDebugEnabled) {
                    log.debug(
                        "Authentication failed with plugin {} (type: {}) for user {}: {}",
                        plugin.getClass().getSimpleName(),
                        plugin.getType(),
                        credentials.getUsername(),
                        e.getMessage()
                    );
                }
                if (isTraceEnabled) {
                    log.trace("Authentication exception details", e);
                }
                
                // Audit log failed authentication
                auditLog.logAuthenticationPluginExecution(
                    plugin.getType(),
                    "FAILED_EXCEPTION: " + e.getMessage(),
                    executionTimeMs,
                    credentials.getUsername(),
                    Collections.emptyMap(),
                    null
                );
            } catch (Exception e) {
                long executionTimeMs = System.currentTimeMillis() - startTime;
                
                // Unexpected exception, log and try next plugin
                log.error(
                    "Unexpected exception during authentication with plugin {} (type: {}) for user {}: {}",
                    plugin.getClass().getSimpleName(),
                    plugin.getType(),
                    credentials.getUsername(),
                    e.getMessage(),
                    e
                );
                
                // Audit log unexpected exception
                auditLog.logAuthenticationPluginExecution(
                    plugin.getType(),
                    "ERROR: " + e.getMessage(),
                    executionTimeMs,
                    credentials.getUsername(),
                    Collections.emptyMap(),
                    null
                );
            }
        }

        // No plugin succeeded
        if (isDebugEnabled) {
            log.debug(
                "All {} authentication plugin(s) failed to authenticate user: {}",
                authenticationPlugins.size(),
                credentials.getUsername()
            );
        }

        return null;
    }

    // ========== New Plugin Architecture Authorization Flow ==========

    /**
     * Authorizes a user using registered authorization plugins.
     * <p>
     * This method implements the new plugin-based authorization flow. It iterates
     * through registered {@link AuthorizationPlugin} instances in order, evaluating
     * authorization for each plugin.
     * <p>
     * The method uses an AND logic: all plugins must allow access for the request
     * to proceed. If any plugin denies access, the method immediately returns the
     * deny result. If no plugins are registered, this method returns null, allowing
     * the caller to fall back to the existing authorization flow.
     * <p>
     * <b>Authorization Flow:</b>
     * <ol>
     *   <li>Check if any authorization plugins are registered</li>
     *   <li>For each plugin in registration order:
     *     <ul>
     *       <li>Call the plugin's authorize method</li>
     *       <li>If denied, immediately return the deny result</li>
     *       <li>If allowed, continue to next plugin</li>
     *     </ul>
     *   </li>
     *   <li>Return allow result if all plugins allow access</li>
     * </ol>
     * <p>
     * <b>Backward Compatibility:</b> This method is designed to work alongside the
     * existing authorization flow. When no plugins are registered, it returns null,
     * allowing the existing {@link #authz} method to handle authorization.
     *
     * @param principal The authenticated user principal containing identity and claims
     * @param context The authorization context containing resource, action, and metadata
     * @return AuthorizationResult if plugins are registered (allow or deny), null if no
     *         plugins are registered to fall back to existing flow
     * @see AuthorizationPlugin
     * @see AuthorizationResult
     * @see AuthorizationContext
     */
    private AuthorizationResult authorizeWithPlugins(UserPrincipal principal, AuthorizationContext context) {
        // If no plugins are registered, return null to fall back to existing flow
        if (authorizationPlugins.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("No authorization plugins registered, falling back to existing authorization flow");
            }
            return null;
        }

        final boolean isDebugEnabled = log.isDebugEnabled();
        final boolean isTraceEnabled = log.isTraceEnabled();

        if (principal == null) {
            if (isTraceEnabled) {
                log.trace("No principal provided, cannot authorize with plugins");
            }
            return AuthorizationResult.deny("No authenticated principal provided");
        }

        if (context == null) {
            if (isTraceEnabled) {
                log.trace("No authorization context provided, cannot authorize with plugins");
            }
            return AuthorizationResult.deny("No authorization context provided");
        }

        if (isDebugEnabled) {
            log.debug(
                "Attempting authorization with {} plugin(s) for user: {}, action: {}, resource: {}",
                authorizationPlugins.size(),
                principal.getName(),
                context.getAction(),
                context.getResource()
            );
        }

        // Iterate through plugins in registration order
        // All plugins must allow access (AND logic)
        for (AuthorizationPlugin plugin : authorizationPlugins) {
            if (isTraceEnabled) {
                log.trace(
                    "Evaluating authorization with plugin {} (type: {}) for user: {}, action: {}, resource: {}",
                    plugin.getClass().getSimpleName(),
                    plugin.getType(),
                    principal.getName(),
                    context.getAction(),
                    context.getResource()
                );
            }

            // Measure execution time for audit logging
            long startTime = System.currentTimeMillis();
            
            try {
                // Attempt authorization with this plugin
                AuthorizationResult result = plugin.authorize(principal, context);
                
                long executionTimeMs = System.currentTimeMillis() - startTime;

                if (result == null) {
                    // Plugin returned null, treat as deny
                    log.warn(
                        "Plugin {} (type: {}) returned null for user: {}, action: {}, resource: {} - treating as deny",
                        plugin.getClass().getSimpleName(),
                        plugin.getType(),
                        principal.getName(),
                        context.getAction(),
                        context.getResource()
                    );
                    
                    // Audit log null result
                    auditLog.logAuthorizationPluginExecution(
                        plugin.getType(),
                        "DENIED_NULL_RESULT",
                        executionTimeMs,
                        principal.getName(),
                        context.getAction(),
                        context.getResource(),
                        null
                    );
                    
                    return AuthorizationResult.deny(
                        "Authorization plugin " + plugin.getType() + " returned null result"
                    );
                }

                if (!result.isAllowed()) {
                    // Plugin denied access, return immediately (fail-fast)
                    if (isDebugEnabled) {
                        log.debug(
                            "Authorization denied by plugin {} (type: {}) for user: {}, action: {}, resource: {}. Reason: {}",
                            plugin.getClass().getSimpleName(),
                            plugin.getType(),
                            principal.getName(),
                            context.getAction(),
                            context.getResource(),
                            result.getReason()
                        );
                    }
                    
                    // Audit log denied authorization
                    auditLog.logAuthorizationPluginExecution(
                        plugin.getType(),
                        "DENIED: " + result.getReason(),
                        executionTimeMs,
                        principal.getName(),
                        context.getAction(),
                        context.getResource(),
                        null
                    );
                    
                    return result;
                } else {
                    // Plugin allowed access, continue to next plugin
                    if (isTraceEnabled) {
                        log.trace(
                            "Authorization allowed by plugin {} (type: {}) for user: {}, action: {}, resource: {}",
                            plugin.getClass().getSimpleName(),
                            plugin.getType(),
                            principal.getName(),
                            context.getAction(),
                            context.getResource()
                        );
                    }
                    
                    // Audit log allowed authorization
                    auditLog.logAuthorizationPluginExecution(
                        plugin.getType(),
                        "ALLOWED",
                        executionTimeMs,
                        principal.getName(),
                        context.getAction(),
                        context.getResource(),
                        null
                    );
                }
            } catch (Exception e) {
                long executionTimeMs = System.currentTimeMillis() - startTime;
                
                // Unexpected exception, log and treat as deny
                log.error(
                    "Unexpected exception during authorization with plugin {} (type: {}) for user: {}, action: {}, resource: {}: {}",
                    plugin.getClass().getSimpleName(),
                    plugin.getType(),
                    principal.getName(),
                    context.getAction(),
                    context.getResource(),
                    e.getMessage(),
                    e
                );
                
                // Audit log exception
                auditLog.logAuthorizationPluginExecution(
                    plugin.getType(),
                    "ERROR: " + e.getMessage(),
                    executionTimeMs,
                    principal.getName(),
                    context.getAction(),
                    context.getResource(),
                    null
                );
                
                return AuthorizationResult.deny(
                    "Authorization failed due to unexpected error in plugin " + plugin.getType()
                );
            }
        }

        // All plugins allowed access
        if (isDebugEnabled) {
            log.debug(
                "All {} authorization plugin(s) allowed access for user: {}, action: {}, resource: {}",
                authorizationPlugins.size(),
                principal.getName(),
                context.getAction(),
                context.getResource()
            );
        }

        return AuthorizationResult.allow();
    }

    /**
     * Checks if the BackendRegistry is using the new plugin architecture.
     * Returns true if any authentication or authorization plugins are registered.
     * 
     * @return true if plugin architecture is active, false otherwise
     */
    public boolean isUsingPluginArchitecture() {
        return !authenticationPlugins.isEmpty() || !authorizationPlugins.isEmpty();
    }

    /**
     * Returns the number of adapters currently in use.
     * Adapters indicate backends that have not been converted to the new plugin architecture.
     * 
     * @return count of adapters in use
     */
    public int getAdapterCount() {
        int count = 0;
        
        // Count authentication backend adapters
        for (AuthenticationPlugin plugin : authenticationPlugins) {
            if (plugin instanceof AuthenticationBackendAdapter) {
                count++;
            }
        }
        
        // Count authorization backend adapters
        for (AuthorizationPlugin plugin : authorizationPlugins) {
            if (plugin instanceof AuthorizationBackendAdapter) {
                count++;
            }
        }
        
        return count;
    }

    /**
     * Returns the number of authentication plugins registered.
     * 
     * @return count of authentication plugins
     */
    public int getAuthenticationPluginCount() {
        return authenticationPlugins.size();
    }

    /**
     * Returns the number of authorization plugins registered.
     * 
     * @return count of authorization plugins
     */
    public int getAuthorizationPluginCount() {
        return authorizationPlugins.size();
    }

}
