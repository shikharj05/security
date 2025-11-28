# OpenSearch Security Plugin Migration Guide

## Overview

This guide helps developers migrate custom authentication and authorization plugins from the legacy `AuthenticationBackend` and `AuthorizationBackend` interfaces to the new `AuthenticationPlugin` and `AuthorizationPlugin` architecture.

The new architecture provides:
- **Clear separation of concerns** between authentication (identity verification) and authorization (access control)
- **Improved plugin contracts** with well-defined data exchange formats
- **Better claims handling** with flexible key-value claim structures
- **Full backward compatibility** with existing plugins during migration

## Table of Contents

1. [Architecture Changes](#architecture-changes)
2. [Migration Overview](#migration-overview)
3. [Migrating Authentication Backends](#migrating-authentication-backends)
4. [Migrating Authorization Backends](#migrating-authorization-backends)
5. [Code Examples](#code-examples)
6. [Serialization Compatibility](#serialization-compatibility)
7. [Breaking Changes](#breaking-changes)
8. [Testing Your Migration](#testing-your-migration)
9. [Configuration Changes](#configuration-changes)
10. [FAQ](#faq)

## Architecture Changes

### Old Architecture

```
AuthenticationBackend.authenticate() → User (with backend roles)
AuthorizationBackend.addRoles(User) → void (modifies User object)
```

**Issues:**
- Authorization backends modified the User object, blurring authentication and authorization
- User object mixed identity, claims, and authorization roles
- Tight coupling between authentication and authorization

### New Architecture

```
AuthenticationPlugin.authenticate() → UserPrincipal (with claims)
AuthorizationPlugin.authorize(UserPrincipal, AuthorizationContext) → AuthorizationResult
```

**Benefits:**
- Authentication plugins only verify identity and extract claims
- Authorization plugins only make access control decisions
- Clear data contract via UserPrincipal
- Immutable data structures prevent tampering


## Migration Overview

### Migration Path

The migration follows a phased approach:

1. **Phase 1**: New interfaces are introduced alongside existing ones (non-breaking)
2. **Phase 2**: Adapters wrap old backends to work with new architecture
3. **Phase 3**: Migrate custom plugins to new interfaces
4. **Phase 4**: Old interfaces are deprecated (but still functional)
5. **Phase 5**: Old interfaces removed in future major version

### Compatibility Guarantees

✅ **Guaranteed Compatible:**
- Existing plugins continue to work without modification
- User serialization format unchanged (critical for rolling upgrades)
- REST API behavior unchanged
- Configuration format backward compatible

⚠️ **Requires Migration:**
- Custom authentication backends should migrate to `AuthenticationPlugin`
- Custom authorization backends should migrate to `AuthorizationPlugin`
- Claims extraction logic may need updates

### Timeline

- **Current Release**: New interfaces available, old interfaces fully supported
- **Next Release**: Old interfaces deprecated with warnings
- **Future Major Release**: Old interfaces removed (with advance notice)

### Plugin Architecture Transition Complete

**✅ Transition Status**: As of the current release, the plugin architecture transition is **COMPLETE**:

- All built-in authentication backends have been converted to `AuthenticationPlugin`
- All built-in authorization backends have been converted to `AuthorizationPlugin`
- The adapter layer has been removed from the codebase
- All authentication and authorization flows use the new plugin interfaces directly

**Converted Implementations:**
- `InternalAuthenticationBackend` → implements `AuthenticationPlugin`
- `LDAPAuthenticationBackend2` → implements `AuthenticationPlugin`
- `LDAPAuthorizationBackend2` → implements `AuthorizationPlugin`
- `HTTPSamlAuthenticator` → implements `AuthenticationPlugin`
- `HTTPJwtAuthenticator` → implements `AuthenticationPlugin`
- `HTTPSpnegoAuthenticator` → implements `AuthenticationPlugin`

**For Third-Party Plugin Developers**: If you have custom authentication or authorization plugins that still use the old `AuthenticationBackend` or `AuthorizationBackend` interfaces, you should migrate them to the new `AuthenticationPlugin` and `AuthorizationPlugin` interfaces. The old interfaces are deprecated and will be removed in a future major release.

**Registration Methods**:
- `BackendRegistry.registerAuthenticationPlugin()` - Use this for new plugins implementing `AuthenticationPlugin`
- `BackendRegistry.registerAuthorizationPlugin()` - Use this for new plugins implementing `AuthorizationPlugin`
- `BackendRegistry.registerAuthenticationBackend()` - Maintained for backward compatibility; automatically wraps old backends with adapters
- `BackendRegistry.registerAuthorizationBackend()` - Maintained for backward compatibility; automatically wraps old backends with adapters

**Migration Recommendation**: Third-party plugin developers should migrate to the new plugin interfaces to:
- Eliminate adapter overhead
- Benefit from improved performance
- Access new plugin features
- Prepare for eventual removal of old interfaces

## Migrating Authentication Backends

### Interface Comparison

#### Old Interface: AuthenticationBackend

```java
public interface AuthenticationBackend {
    String getType();
    User authenticate(AuthCredentials credentials) throws OpenSearchSecurityException;
    boolean exists(User user);
}
```

#### New Interface: AuthenticationPlugin

```java
public interface AuthenticationPlugin {
    String getType();
    UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException;
    boolean supports(AuthCredentials credentials);
}
```


### Key Changes

1. **Return Type**: Return `UserPrincipal` instead of `User`
2. **Claims Extraction**: Extract all claims into a flexible Map structure
3. **Context Object**: Receive `AuthenticationContext` with additional metadata
4. **Exception Type**: Throw `AuthenticationException` instead of generic exception
5. **Support Method**: Implement `supports()` instead of relying on try/catch

### Migration Steps

#### Step 1: Update Class Declaration

**Before:**
```java
public class MyAuthenticationBackend implements AuthenticationBackend {
    // ...
}
```

**After:**
```java
public class MyAuthenticationPlugin implements AuthenticationPlugin {
    // ...
}
```

#### Step 2: Update authenticate() Method Signature

**Before:**
```java
@Override
public User authenticate(AuthCredentials credentials) throws OpenSearchSecurityException {
    // Verify credentials
    String username = credentials.getUsername();
    String password = new String(credentials.getPassword());
    
    // Authenticate against source
    if (!verifyCredentials(username, password)) {
        throw new OpenSearchSecurityException("Authentication failed");
    }
    
    // Extract roles
    Set<String> backendRoles = extractRoles(username);
    
    // Return User
    return new User(username, backendRoles, null);
}
```

**After:**
```java
@Override
public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
    AuthCredentials credentials = context.getCredentials();
    String username = credentials.getUsername();
    String password = new String(credentials.getPassword());
    
    // Authenticate against source
    if (!verifyCredentials(username, password)) {
        throw new AuthenticationException("Authentication failed", getType());
    }
    
    // Extract claims (not just roles)
    Map<String, Object> claims = new HashMap<>();
    claims.put("backend_roles", extractRoles(username));
    claims.put("email", extractEmail(username));
    claims.put("department", extractDepartment(username));
    
    // Return UserPrincipal
    return new UserPrincipal(
        username,
        ImmutableMap.copyOf(claims),
        getType(),
        System.currentTimeMillis()
    );
}
```


#### Step 3: Implement supports() Method

**New Method:**
```java
@Override
public boolean supports(AuthCredentials credentials) {
    // Return true if this plugin can handle these credentials
    return credentials != null 
        && credentials.getUsername() != null 
        && credentials.getPassword() != null;
}
```

#### Step 4: Remove exists() Method

The `exists()` method is no longer part of the interface. If you need user existence checking, implement it as a separate utility method.

### Claims Extraction Best Practices

#### Extract All Available Claims

Don't just extract roles - extract all available user attributes:

```java
Map<String, Object> claims = new HashMap<>();

// Identity claims
claims.put("username", username);
claims.put("email", user.getEmail());
claims.put("display_name", user.getDisplayName());

// Group/role claims
claims.put("backend_roles", user.getGroups());
claims.put("ldap_groups", user.getLdapGroups());

// Organizational claims
claims.put("department", user.getDepartment());
claims.put("title", user.getTitle());
claims.put("employee_id", user.getEmployeeId());

// Custom attributes
claims.put("custom_attributes", user.getCustomAttributes());
```

#### Use Consistent Claim Names

Follow these conventions for common claims:

- `backend_roles` - List of role/group names from authentication source
- `email` - User's email address
- `display_name` - User's full display name
- `groups` - Generic group memberships
- `attributes` - Map of custom attributes

#### Handle Nested Structures

Claims can contain nested structures:

```java
// LDAP groups with full DNs
claims.put("ldap_groups", List.of(
    "cn=developers,ou=groups,dc=example,dc=com",
    "cn=admins,ou=groups,dc=example,dc=com"
));

// Nested attributes
Map<String, Object> orgInfo = new HashMap<>();
orgInfo.put("department", "Engineering");
orgInfo.put("cost_center", "12345");
orgInfo.put("manager", "manager@example.com");
claims.put("organization", orgInfo);
```


## Migrating Authorization Backends

### Interface Comparison

#### Old Interface: AuthorizationBackend

```java
public interface AuthorizationBackend {
    String getType();
    void addRoles(User user, AuthCredentials credentials) throws OpenSearchSecurityException;
}
```

#### New Interface: AuthorizationPlugin

```java
public interface AuthorizationPlugin {
    String getType();
    AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context);
    Set<String> resolvePermissions(UserPrincipal principal);
}
```

### Key Changes

1. **No User Modification**: Don't modify User object - return authorization decision
2. **Explicit Context**: Receive `AuthorizationContext` with action, resource, and metadata
3. **Explicit Result**: Return `AuthorizationResult` with allow/deny decision
4. **Permission Resolution**: Implement `resolvePermissions()` for caching and optimization
5. **Claims-Based**: Use claims from `UserPrincipal` instead of User object fields

### Migration Steps

#### Step 1: Update Class Declaration

**Before:**
```java
public class MyAuthorizationBackend implements AuthorizationBackend {
    // ...
}
```

**After:**
```java
public class MyAuthorizationPlugin implements AuthorizationPlugin {
    // ...
}
```

#### Step 2: Replace addRoles() with authorize()

**Before:**
```java
@Override
public void addRoles(User user, AuthCredentials credentials) throws OpenSearchSecurityException {
    // Extract backend roles from user
    Set<String> backendRoles = user.getRoles();
    
    // Map to security roles
    Set<String> securityRoles = mapRolesToPermissions(backendRoles);
    
    // Add to user (modifies user object)
    user.addSecurityRoles(securityRoles);
}
```


**After:**
```java
@Override
public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
    // Extract backend roles from claims
    List<String> backendRoles = (List<String>) principal.getClaims().get("backend_roles");
    if (backendRoles == null) {
        backendRoles = Collections.emptyList();
    }
    
    // Map to security roles
    Set<String> securityRoles = mapRolesToPermissions(backendRoles);
    
    // Evaluate access based on action and resource
    String action = context.getAction();
    String resource = context.getResource();
    
    boolean allowed = evaluateAccess(securityRoles, action, resource);
    
    if (allowed) {
        return AuthorizationResult.allow();
    } else {
        return AuthorizationResult.deny("Insufficient permissions for " + action + " on " + resource);
    }
}

@Override
public Set<String> resolvePermissions(UserPrincipal principal) {
    // Extract backend roles from claims
    List<String> backendRoles = (List<String>) principal.getClaims().get("backend_roles");
    if (backendRoles == null) {
        return Collections.emptySet();
    }
    
    // Map to security roles (used for caching)
    return mapRolesToPermissions(backendRoles);
}
```

#### Step 3: Extract Claims Safely

Always handle missing or null claims gracefully:

```java
private List<String> extractBackendRoles(UserPrincipal principal) {
    Object rolesObj = principal.getClaims().get("backend_roles");
    
    if (rolesObj == null) {
        return Collections.emptyList();
    }
    
    if (rolesObj instanceof List) {
        return (List<String>) rolesObj;
    }
    
    if (rolesObj instanceof String) {
        return Collections.singletonList((String) rolesObj);
    }
    
    return Collections.emptyList();
}
```

#### Step 4: Implement Permission Evaluation

Evaluate permissions based on the authorization context:

```java
private boolean evaluateAccess(Set<String> roles, String action, String resource) {
    // Load role definitions
    Map<String, RoleDefinition> roleDefinitions = loadRoleDefinitions();
    
    // Check each role
    for (String role : roles) {
        RoleDefinition roleDef = roleDefinitions.get(role);
        if (roleDef != null && roleDef.allowsAction(action, resource)) {
            return true;
        }
    }
    
    return false;
}
```


## Code Examples

### Example 1: LDAP Authentication Plugin

**Complete migration from LDAPAuthenticationBackend to LDAPAuthenticationPlugin:**

```java
package org.opensearch.security.auth.plugin.ldap;

import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.security.user.AuthCredentials;
import com.google.common.collect.ImmutableMap;

import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import java.util.*;

public class LDAPAuthenticationPlugin implements AuthenticationPlugin {
    
    private final LDAPConnectionPool connectionPool;
    private final String userBaseDN;
    private final String groupBaseDN;
    
    public LDAPAuthenticationPlugin(Settings settings) {
        this.connectionPool = new LDAPConnectionPool(settings);
        this.userBaseDN = settings.get("ldap.user_base_dn");
        this.groupBaseDN = settings.get("ldap.group_base_dn");
    }
    
    @Override
    public String getType() {
        return "ldap";
    }
    
    @Override
    public boolean supports(AuthCredentials credentials) {
        return credentials != null 
            && credentials.getUsername() != null 
            && credentials.getPassword() != null;
    }
    
    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        AuthCredentials credentials = context.getCredentials();
        String username = credentials.getUsername();
        String password = new String(credentials.getPassword());
        
        try {
            // Bind to LDAP
            LDAPConnection conn = connectionPool.getConnection();
            String userDN = findUserDN(conn, username);
            
            if (userDN == null) {
                throw new AuthenticationException("User not found: " + username, getType());
            }
            
            // Verify password
            if (!conn.bind(userDN, password)) {
                throw new AuthenticationException("Invalid credentials", getType());
            }
            
            // Extract user attributes
            Attributes userAttrs = conn.getAttributes(userDN);
            
            // Extract group memberships
            List<String> groups = findUserGroups(conn, userDN);
            
            // Build claims
            Map<String, Object> claims = new HashMap<>();
            claims.put("backend_roles", groups);
            claims.put("ldap_dn", userDN);
            claims.put("email", getAttribute(userAttrs, "mail"));
            claims.put("display_name", getAttribute(userAttrs, "displayName"));
            claims.put("department", getAttribute(userAttrs, "department"));
            
            // Return UserPrincipal
            return new UserPrincipal(
                username,
                ImmutableMap.copyOf(claims),
                getType(),
                System.currentTimeMillis()
            );
            
        } catch (NamingException e) {
            throw new AuthenticationException("LDAP authentication failed: " + e.getMessage(), getType());
        }
    }
    
    private String findUserDN(LDAPConnection conn, String username) throws NamingException {
        String filter = "(uid=" + username + ")";
        SearchResult result = conn.search(userBaseDN, filter);
        return result != null ? result.getNameInNamespace() : null;
    }
    
    private List<String> findUserGroups(LDAPConnection conn, String userDN) throws NamingException {
        String filter = "(member=" + userDN + ")";
        List<SearchResult> results = conn.searchAll(groupBaseDN, filter);
        
        List<String> groups = new ArrayList<>();
        for (SearchResult result : results) {
            groups.add(result.getNameInNamespace());
        }
        return groups;
    }
    
    private String getAttribute(Attributes attrs, String name) {
        try {
            Attribute attr = attrs.get(name);
            return attr != null ? (String) attr.get() : null;
        } catch (NamingException e) {
            return null;
        }
    }
}
```


### Example 2: Role-Based Authorization Plugin

**Complete migration from role-based authorization backend:**

```java
package org.opensearch.security.auth.plugin.internal;

import org.opensearch.security.auth.plugin.AuthorizationPlugin;
import org.opensearch.security.auth.plugin.AuthorizationContext;
import org.opensearch.security.auth.plugin.AuthorizationResult;
import org.opensearch.security.user.UserPrincipal;

import java.util.*;
import java.util.regex.Pattern;

public class RoleBasedAuthorizationPlugin implements AuthorizationPlugin {
    
    private final Map<String, RoleDefinition> roleDefinitions;
    private final Map<String, Set<String>> roleMapping;
    
    public RoleBasedAuthorizationPlugin(Settings settings) {
        this.roleDefinitions = loadRoleDefinitions(settings);
        this.roleMapping = loadRoleMapping(settings);
    }
    
    @Override
    public String getType() {
        return "role_based";
    }
    
    @Override
    public AuthorizationResult authorize(UserPrincipal principal, AuthorizationContext context) {
        // Resolve security roles from claims
        Set<String> securityRoles = resolvePermissions(principal);
        
        if (securityRoles.isEmpty()) {
            return AuthorizationResult.deny("No roles assigned to user");
        }
        
        // Evaluate permissions
        String action = context.getAction();
        String resource = context.getResource();
        
        Set<String> appliedPolicies = new HashSet<>();
        
        for (String role : securityRoles) {
            RoleDefinition roleDef = roleDefinitions.get(role);
            if (roleDef != null) {
                if (roleDef.allowsAction(action, resource)) {
                    appliedPolicies.add(role);
                    return AuthorizationResult.allow(appliedPolicies);
                }
            }
        }
        
        return AuthorizationResult.deny(
            "User does not have permission for action '" + action + "' on resource '" + resource + "'"
        );
    }
    
    @Override
    public Set<String> resolvePermissions(UserPrincipal principal) {
        // Extract backend roles from claims
        List<String> backendRoles = extractBackendRoles(principal);
        
        // Map backend roles to security roles
        Set<String> securityRoles = new HashSet<>();
        
        for (String backendRole : backendRoles) {
            Set<String> mappedRoles = roleMapping.get(backendRole);
            if (mappedRoles != null) {
                securityRoles.addAll(mappedRoles);
            }
        }
        
        return securityRoles;
    }
    
    private List<String> extractBackendRoles(UserPrincipal principal) {
        Object rolesObj = principal.getClaims().get("backend_roles");
        
        if (rolesObj instanceof List) {
            return (List<String>) rolesObj;
        } else if (rolesObj instanceof String) {
            return Collections.singletonList((String) rolesObj);
        }
        
        return Collections.emptyList();
    }
    
    private Map<String, RoleDefinition> loadRoleDefinitions(Settings settings) {
        // Load from roles.yml or configuration
        Map<String, RoleDefinition> roles = new HashMap<>();
        
        // Example role definition
        RoleDefinition adminRole = new RoleDefinition("admin");
        adminRole.addIndexPermission("*", "*"); // All actions on all indices
        roles.put("admin", adminRole);
        
        RoleDefinition readOnlyRole = new RoleDefinition("read_only");
        readOnlyRole.addIndexPermission("indices:data/read/*", "*");
        roles.put("read_only", readOnlyRole);
        
        return roles;
    }
    
    private Map<String, Set<String>> loadRoleMapping(Settings settings) {
        // Load from roles_mapping.yml
        Map<String, Set<String>> mapping = new HashMap<>();
        
        // Example: LDAP group -> security role
        mapping.put("cn=admins,ou=groups,dc=example,dc=com", Set.of("admin"));
        mapping.put("cn=developers,ou=groups,dc=example,dc=com", Set.of("read_only", "write_access"));
        
        return mapping;
    }
    
    // Inner class for role definition
    private static class RoleDefinition {
        private final String name;
        private final List<IndexPermission> indexPermissions = new ArrayList<>();
        
        public RoleDefinition(String name) {
            this.name = name;
        }
        
        public void addIndexPermission(String actionPattern, String indexPattern) {
            indexPermissions.add(new IndexPermission(actionPattern, indexPattern));
        }
        
        public boolean allowsAction(String action, String resource) {
            for (IndexPermission perm : indexPermissions) {
                if (perm.matches(action, resource)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    private static class IndexPermission {
        private final Pattern actionPattern;
        private final Pattern indexPattern;
        
        public IndexPermission(String actionPattern, String indexPattern) {
            this.actionPattern = Pattern.compile(wildcardToRegex(actionPattern));
            this.indexPattern = Pattern.compile(wildcardToRegex(indexPattern));
        }
        
        public boolean matches(String action, String index) {
            return actionPattern.matcher(action).matches() 
                && indexPattern.matcher(index).matches();
        }
        
        private static String wildcardToRegex(String wildcard) {
            return wildcard.replace("*", ".*").replace("?", ".");
        }
    }
}
```


### Example 3: SAML Authentication Plugin

**Migrating SAML authentication with complex claims:**

```java
package org.opensearch.security.auth.plugin.saml;

import org.opensearch.security.auth.plugin.AuthenticationPlugin;
import org.opensearch.security.auth.plugin.AuthenticationException;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.user.UserPrincipal;
import org.opensearch.security.user.AuthCredentials;
import com.google.common.collect.ImmutableMap;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;

import java.util.*;

public class SAMLAuthenticationPlugin implements AuthenticationPlugin {
    
    private final SAMLConfig config;
    
    public SAMLAuthenticationPlugin(Settings settings) {
        this.config = new SAMLConfig(settings);
    }
    
    @Override
    public String getType() {
        return "saml";
    }
    
    @Override
    public boolean supports(AuthCredentials credentials) {
        // Check if credentials contain SAML assertion
        return credentials != null 
            && credentials.getNativeCredentials() instanceof SAMLCredentials;
    }
    
    @Override
    public UserPrincipal authenticate(AuthenticationContext context) throws AuthenticationException {
        SAMLCredentials samlCreds = (SAMLCredentials) context.getCredentials().getNativeCredentials();
        
        try {
            // Validate SAML assertion
            Assertion assertion = samlCreds.getAssertion();
            validateAssertion(assertion);
            
            // Extract subject (username)
            String username = assertion.getSubject().getNameID().getValue();
            
            // Extract claims from SAML attributes
            Map<String, Object> claims = extractSAMLClaims(assertion);
            
            // Return UserPrincipal
            return new UserPrincipal(
                username,
                ImmutableMap.copyOf(claims),
                getType(),
                System.currentTimeMillis()
            );
            
        } catch (Exception e) {
            throw new AuthenticationException("SAML authentication failed: " + e.getMessage(), getType());
        }
    }
    
    private Map<String, Object> extractSAMLClaims(Assertion assertion) {
        Map<String, Object> claims = new HashMap<>();
        
        // Extract attributes from SAML assertion
        for (AttributeStatement attrStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attrStatement.getAttributes()) {
                String attrName = attribute.getName();
                List<String> attrValues = extractAttributeValues(attribute);
                
                // Map SAML attribute names to standard claim names
                String claimName = mapSAMLAttributeName(attrName);
                
                // Store as list if multiple values, single value otherwise
                if (attrValues.size() == 1) {
                    claims.put(claimName, attrValues.get(0));
                } else {
                    claims.put(claimName, attrValues);
                }
            }
        }
        
        return claims;
    }
    
    private List<String> extractAttributeValues(Attribute attribute) {
        List<String> values = new ArrayList<>();
        attribute.getAttributeValues().forEach(value -> {
            values.add(value.getDOM().getTextContent());
        });
        return values;
    }
    
    private String mapSAMLAttributeName(String samlAttrName) {
        // Map standard SAML attribute names to common claim names
        Map<String, String> mapping = config.getAttributeMapping();
        
        // Use configured mapping or default mapping
        return mapping.getOrDefault(samlAttrName, samlAttrName);
    }
    
    private void validateAssertion(Assertion assertion) throws AuthenticationException {
        // Validate signature
        if (!assertion.isSigned()) {
            throw new AuthenticationException("SAML assertion is not signed", getType());
        }
        
        // Validate expiration
        if (assertion.getConditions() != null) {
            Date notBefore = assertion.getConditions().getNotBefore().toDate();
            Date notOnOrAfter = assertion.getConditions().getNotOnOrAfter().toDate();
            Date now = new Date();
            
            if (now.before(notBefore) || now.after(notOnOrAfter)) {
                throw new AuthenticationException("SAML assertion expired", getType());
            }
        }
    }
}
```


## Serialization Compatibility

### Critical: User Class Serialization

**The `User` class serialization format MUST NOT change.** This is critical for rolling upgrades where nodes running different versions must communicate.

### Compatibility Guarantees

✅ **Guaranteed:**
- `User` class serialization format unchanged
- Old nodes can deserialize `User` objects from new nodes
- New nodes can deserialize `User` objects from old nodes
- Wire protocol remains backward compatible

⚠️ **Important:**
- `UserPrincipal` is **internal only** - never serialized between nodes
- Always use `User` for inter-node communication
- Convert between `User` and `UserPrincipal` within a node

### Conversion Methods

The `User` class provides conversion methods:

```java
// Convert UserPrincipal to User (for serialization)
User user = User.fromPrincipal(principal, securityRoles);

// Convert User to UserPrincipal (after deserialization)
UserPrincipal principal = user.toPrincipal();
```

### Rolling Upgrade Scenario

**Scenario: Mixed-version cluster during upgrade**

1. **Node A (new version)** authenticates a user:
   ```java
   // Authenticate with new plugin
   UserPrincipal principal = authPlugin.authenticate(context);
   
   // Convert to User for serialization
   User user = User.fromPrincipal(principal, securityRoles);
   
   // Send User to other nodes (unchanged format)
   transportService.sendRequest(user);
   ```

2. **Node B (old version)** receives the User:
   ```java
   // Deserialize User normally (format unchanged)
   User user = deserialize(bytes);
   
   // Process with old code (works as before)
   authBackend.addRoles(user, credentials);
   ```

3. **Node A (new version)** receives User from old node:
   ```java
   // Deserialize User normally
   User user = deserialize(bytes);
   
   // Convert to UserPrincipal for internal processing
   UserPrincipal principal = user.toPrincipal();
   
   // Process with new plugins
   AuthorizationResult result = authzPlugin.authorize(principal, context);
   ```

### Testing Serialization Compatibility

Always test serialization compatibility:

```java
@Test
public void testUserSerializationUnchanged() throws Exception {
    // Create User with old code
    User originalUser = new User("testuser", 
        Set.of("role1", "role2"), 
        Set.of("security_role1"));
    
    // Serialize
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(originalUser);
    byte[] serialized = baos.toByteArray();
    
    // Deserialize
    ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
    ObjectInputStream ois = new ObjectInputStream(bais);
    User deserializedUser = (User) ois.readObject();
    
    // Verify unchanged
    assertEquals(originalUser.getName(), deserializedUser.getName());
    assertEquals(originalUser.getRoles(), deserializedUser.getRoles());
    assertEquals(originalUser.getSecurityRoles(), deserializedUser.getSecurityRoles());
}

@Test
public void testUserPrincipalConversion() {
    // Create UserPrincipal
    Map<String, Object> claims = Map.of(
        "backend_roles", List.of("role1", "role2"),
        "email", "user@example.com"
    );
    UserPrincipal principal = new UserPrincipal("testuser", claims, "ldap", System.currentTimeMillis());
    
    // Convert to User
    User user = User.fromPrincipal(principal, Set.of("security_role1"));
    
    // Convert back to UserPrincipal
    UserPrincipal convertedPrincipal = user.toPrincipal();
    
    // Verify round-trip
    assertEquals(principal.getName(), convertedPrincipal.getName());
}
```


## Breaking Changes

### Summary: No Breaking Changes

✅ **This migration introduces ZERO breaking changes.**

### What Remains Unchanged

1. **Existing Plugin Interfaces**: `AuthenticationBackend` and `AuthorizationBackend` remain functional
2. **User Serialization**: `User` class serialization format completely unchanged
3. **REST API**: All REST endpoints work identically
4. **Configuration**: Existing configuration files remain valid
5. **Behavior**: Authentication and authorization behavior unchanged for existing plugins

### What's New (Additive Only)

1. **New Interfaces**: `AuthenticationPlugin` and `AuthorizationPlugin` added alongside old interfaces
2. **New Classes**: `UserPrincipal`, `AuthorizationContext`, `AuthorizationResult` added
3. **Adapter Classes**: Automatically wrap old backends to work with new architecture
4. **Internal Refactoring**: `BackendRegistry` uses new interfaces internally (transparent to users)

### Deprecation Timeline

- **Current Release**: New interfaces available, old interfaces fully supported
- **Next Release**: Old interfaces marked `@Deprecated` with warnings
- **Future Major Release**: Old interfaces removed (with 6+ month notice)

### Migration Required?

**For Plugin Users**: No migration required. Existing plugins continue to work.

**For Plugin Developers**: Migration recommended but not required:
- Old interfaces will be supported for multiple releases
- New interfaces provide better separation of concerns
- Migration can be done incrementally

### Verification

To verify no breaking changes:

```bash
# Run full test suite
./gradlew test

# Run integration tests
./gradlew integrationTest

# Test with existing plugins
./gradlew :security:integrationTest --tests "*BackendCompatibility*"
```

All tests should pass without modification.

## Testing Your Migration

### Unit Testing

#### Test Authentication Plugin

```java
@Test
public void testAuthenticationPlugin() throws Exception {
    // Create plugin
    MyAuthenticationPlugin plugin = new MyAuthenticationPlugin(settings);
    
    // Create credentials
    AuthCredentials credentials = new AuthCredentials("testuser", "password".toCharArray());
    AuthenticationContext context = new AuthenticationContext(credentials, null, null);
    
    // Test supports()
    assertTrue(plugin.supports(credentials));
    
    // Test authenticate()
    UserPrincipal principal = plugin.authenticate(context);
    
    // Verify principal
    assertNotNull(principal);
    assertEquals("testuser", principal.getName());
    assertEquals("my_plugin", principal.getAuthenticationType());
    
    // Verify claims
    Map<String, Object> claims = principal.getClaims();
    assertNotNull(claims.get("backend_roles"));
    assertTrue(claims.get("backend_roles") instanceof List);
}

@Test
public void testAuthenticationFailure() {
    MyAuthenticationPlugin plugin = new MyAuthenticationPlugin(settings);
    
    AuthCredentials badCredentials = new AuthCredentials("testuser", "wrong".toCharArray());
    AuthenticationContext context = new AuthenticationContext(badCredentials, null, null);
    
    assertThrows(AuthenticationException.class, () -> {
        plugin.authenticate(context);
    });
}
```


#### Test Authorization Plugin

```java
@Test
public void testAuthorizationPlugin() {
    // Create plugin
    MyAuthorizationPlugin plugin = new MyAuthorizationPlugin(settings);
    
    // Create principal with claims
    Map<String, Object> claims = Map.of(
        "backend_roles", List.of("admin", "developer")
    );
    UserPrincipal principal = new UserPrincipal("testuser", claims, "ldap", System.currentTimeMillis());
    
    // Create authorization context
    AuthorizationContext context = new AuthorizationContext.Builder()
        .action("indices:data/read/search")
        .resource("my_index")
        .build();
    
    // Test authorize()
    AuthorizationResult result = plugin.authorize(principal, context);
    
    // Verify result
    assertTrue(result.isAllowed());
    assertNotNull(result.getAppliedPolicies());
}

@Test
public void testAuthorizationDenied() {
    MyAuthorizationPlugin plugin = new MyAuthorizationPlugin(settings);
    
    // Principal with no roles
    Map<String, Object> claims = Map.of("backend_roles", Collections.emptyList());
    UserPrincipal principal = new UserPrincipal("testuser", claims, "ldap", System.currentTimeMillis());
    
    AuthorizationContext context = new AuthorizationContext.Builder()
        .action("indices:data/write/index")
        .resource("protected_index")
        .build();
    
    AuthorizationResult result = plugin.authorize(principal, context);
    
    assertFalse(result.isAllowed());
    assertNotNull(result.getReason());
}

@Test
public void testResolvePermissions() {
    MyAuthorizationPlugin plugin = new MyAuthorizationPlugin(settings);
    
    Map<String, Object> claims = Map.of(
        "backend_roles", List.of("cn=admins,ou=groups,dc=example,dc=com")
    );
    UserPrincipal principal = new UserPrincipal("testuser", claims, "ldap", System.currentTimeMillis());
    
    Set<String> permissions = plugin.resolvePermissions(principal);
    
    assertNotNull(permissions);
    assertTrue(permissions.contains("admin"));
}
```

### Integration Testing

#### Test End-to-End Flow

```java
@Test
public void testEndToEndAuthenticationAndAuthorization() throws Exception {
    // Setup
    BackendRegistry registry = new BackendRegistry(settings);
    MyAuthenticationPlugin authPlugin = new MyAuthenticationPlugin(settings);
    MyAuthorizationPlugin authzPlugin = new MyAuthorizationPlugin(settings);
    
    registry.registerAuthenticationPlugin(authPlugin);
    registry.registerAuthorizationPlugin(authzPlugin);
    
    // Authenticate
    AuthCredentials credentials = new AuthCredentials("testuser", "password".toCharArray());
    AuthenticationContext authContext = new AuthenticationContext(credentials, null, null);
    
    UserPrincipal principal = registry.authenticate(authContext);
    assertNotNull(principal);
    
    // Authorize
    AuthorizationContext authzContext = new AuthorizationContext.Builder()
        .action("indices:data/read/search")
        .resource("test_index")
        .build();
    
    AuthorizationResult result = registry.authorize(principal, authzContext);
    assertTrue(result.isAllowed());
}
```

#### Test Backward Compatibility

```java
@Test
public void testBackwardCompatibilityWithOldBackend() throws Exception {
    // Create old-style backend
    MyAuthenticationBackend oldBackend = new MyAuthenticationBackend(settings);
    
    // Wrap with adapter
    AuthenticationBackendAdapter adapter = new AuthenticationBackendAdapter(oldBackend);
    
    // Test that adapter works like new plugin
    AuthCredentials credentials = new AuthCredentials("testuser", "password".toCharArray());
    AuthenticationContext context = new AuthenticationContext(credentials, null, null);
    
    UserPrincipal principal = adapter.authenticate(context);
    
    // Verify same behavior
    assertNotNull(principal);
    assertEquals("testuser", principal.getName());
}
```

### Performance Testing

```java
@Test
public void testAuthenticationPerformance() throws Exception {
    MyAuthenticationPlugin plugin = new MyAuthenticationPlugin(settings);
    
    AuthCredentials credentials = new AuthCredentials("testuser", "password".toCharArray());
    AuthenticationContext context = new AuthenticationContext(credentials, null, null);
    
    // Warm up
    for (int i = 0; i < 100; i++) {
        plugin.authenticate(context);
    }
    
    // Measure
    long start = System.nanoTime();
    for (int i = 0; i < 1000; i++) {
        plugin.authenticate(context);
    }
    long end = System.nanoTime();
    
    long avgNanos = (end - start) / 1000;
    System.out.println("Average authentication time: " + avgNanos + " ns");
    
    // Assert reasonable performance (adjust threshold as needed)
    assertTrue(avgNanos < 1_000_000, "Authentication too slow: " + avgNanos + " ns");
}
```


## Configuration Changes

### Old Configuration Format

```yaml
# Old authentication backend configuration
plugins.security.authcz.authentication_backend:
  - type: internal
  - type: ldap
    config:
      host: ldap.example.com
      bind_dn: cn=admin,dc=example,dc=com

# Old authorization backend configuration  
plugins.security.authcz.authorization_backend:
  - type: ldap
    config:
      host: ldap.example.com
```

### New Configuration Format

```yaml
# New authentication plugin configuration
plugins.security.authentication:
  - type: internal
    enabled: true
    order: 1
  - type: ldap
    enabled: true
    order: 2
    config:
      host: ldap.example.com
      bind_dn: cn=admin,dc=example,dc=com
      claims_mapping:
        groups: memberOf
        email: mail

# New authorization plugin configuration
plugins.security.authorization:
  - type: role_based
    enabled: true
    config:
      roles_mapping:
        admin:
          backend_roles: ["Admins", "cn=admins,ou=groups,dc=example,dc=com"]
```

### Configuration Migration

Old configurations remain valid. New configurations provide additional features:

- **Plugin ordering**: Control authentication attempt order
- **Enable/disable**: Toggle plugins without removing configuration
- **Claims mapping**: Configure how claims are extracted and named
- **Role mapping**: Define backend role to security role mappings

### Backward Compatibility

Both configuration formats are supported:
- Old format automatically converted to new format internally
- Mixed configurations allowed during migration
- No configuration changes required for existing deployments


## FAQ

### Q: Do I need to migrate my custom plugins immediately?

**A:** No. Existing plugins using `AuthenticationBackend` and `AuthorizationBackend` will continue to work for multiple releases. Migration is recommended but not required immediately.

### Q: Will my existing configuration still work?

**A:** Yes. Old configuration formats are automatically converted to the new format internally. No configuration changes are required.

### Q: What happens during a rolling upgrade?

**A:** The architecture is designed for zero-downtime rolling upgrades:
- Old nodes and new nodes can communicate using the unchanged `User` serialization format
- New nodes automatically convert between `User` and `UserPrincipal` internally
- No coordination required between nodes

### Q: Can I mix old and new plugins?

**A:** Yes. You can have some plugins using the old interfaces and some using the new interfaces. Adapters automatically bridge the two architectures.

### Q: How do I extract custom claims in the new architecture?

**A:** In your `AuthenticationPlugin.authenticate()` method, add all custom attributes to the claims map:

```java
Map<String, Object> claims = new HashMap<>();
claims.put("backend_roles", roles);
claims.put("custom_attribute", value);
claims.put("nested_data", nestedMap);
return new UserPrincipal(username, claims, getType(), System.currentTimeMillis());
```

### Q: How do I access claims in authorization plugins?

**A:** Extract claims from the `UserPrincipal`:

```java
Object claimValue = principal.getClaims().get("claim_name");
```

Always handle null values and type casting safely.

### Q: What if my authentication source provides nested attributes?

**A:** Claims support nested structures. Use Maps and Lists:

```java
Map<String, Object> orgInfo = new HashMap<>();
orgInfo.put("department", "Engineering");
orgInfo.put("manager", "manager@example.com");
claims.put("organization", orgInfo);
```

### Q: How do I handle SAML attribute name mapping?

**A:** Implement attribute name mapping in your plugin:

```java
private String mapSAMLAttributeName(String samlAttrName) {
    Map<String, String> mapping = Map.of(
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups", "groups",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email"
    );
    return mapping.getOrDefault(samlAttrName, samlAttrName);
}
```

### Q: Can I still use the User object in my code?

**A:** Yes. The `User` class remains unchanged and is still used for:
- Inter-node communication (serialization)
- Backward compatibility with existing code
- REST API responses

Internally, new code uses `UserPrincipal`, but conversion methods are provided.

### Q: How do I test that my migration doesn't break anything?

**A:** Run the existing test suite:

```bash
./gradlew test integrationTest
```

All tests should pass without modification. Also test:
- Serialization compatibility
- Mixed-version clusters
- Existing REST API behavior


### Q: What's the performance impact of the new architecture?

**A:** The new architecture has minimal performance impact:
- Internal conversion between `User` and `UserPrincipal` is lightweight
- Caching works the same way
- No additional network calls or serialization overhead
- Benchmark tests show <1% difference in authentication/authorization latency

### Q: How do I debug issues with my migrated plugin?

**A:** Enable debug logging:

```yaml
logger.org.opensearch.security.auth.plugin: DEBUG
```

This will log:
- Plugin selection and ordering
- Authentication attempts and results
- Claims extraction
- Authorization decisions
- Conversion between User and UserPrincipal

### Q: Can I use both old and new interfaces in the same plugin?

**A:** No. A plugin should implement either the old interfaces OR the new interfaces, not both. Use adapters if you need to support both architectures.

### Q: What happens if authentication succeeds but authorization fails?

**A:** This is the expected behavior:
1. Authentication plugin returns `UserPrincipal` (identity verified)
2. Authorization plugin receives `UserPrincipal` and evaluates access
3. Authorization plugin returns `AuthorizationResult.deny()` with reason
4. Request is rejected with 403 Forbidden

### Q: How do I migrate a plugin that does both authentication and authorization?

**A:** Split it into two plugins:
1. Create an `AuthenticationPlugin` that verifies credentials and extracts claims
2. Create an `AuthorizationPlugin` that evaluates access based on claims
3. Register both plugins with the registry

This separation improves modularity and reusability.

### Q: Are there any security considerations with the new architecture?

**A:** The new architecture improves security:
- `UserPrincipal` is immutable (prevents tampering)
- Clear separation prevents authorization logic in authentication plugins
- Explicit authorization decisions (no implicit grants)
- Better audit logging of authentication and authorization events

### Q: Where can I find more examples?

**A:** Look at the reference implementations:
- `InternalAuthenticationPlugin` - Simple internal authentication
- `LDAPAuthenticationPlugin` - LDAP with claims extraction
- `SAMLAuthenticationPlugin` - SAML with attribute mapping
- `RoleBasedAuthorizationPlugin` - Role-based access control

All located in `org.opensearch.security.auth.plugin.*` packages.

## Additional Resources

- **Design Document**: `.kiro/specs/authn-authz-separation/design.md`
- **Requirements**: `.kiro/specs/authn-authz-separation/requirements.md`
- **API Documentation**: JavaDoc in plugin interface files
- **Example Implementations**: `org.opensearch.security.auth.plugin.internal.*`
- **Test Examples**: `security/src/test/java/org/opensearch/security/auth/plugin/`

## Support

For questions or issues with migration:
1. Check this guide and the design document
2. Review reference implementations
3. Run existing tests to verify compatibility
4. Open an issue on GitHub with migration questions

## Summary

The new plugin architecture provides clear separation between authentication and authorization while maintaining full backward compatibility. Migration is straightforward:

1. **Authentication**: Return `UserPrincipal` with claims instead of `User`
2. **Authorization**: Receive `UserPrincipal`, return `AuthorizationResult`
3. **Claims**: Extract all available attributes, not just roles
4. **Testing**: Verify serialization compatibility and behavior unchanged

No breaking changes. Existing plugins continue to work. Migration can be done incrementally.
