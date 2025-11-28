# OpenSearch Security Plugin Architecture Configuration

## Overview

OpenSearch Security now supports a new plugin architecture with clear separation between authentication (identity verification) and authorization (access control). This document explains the new configuration format and how to use it.

## Key Concepts

### Authentication Plugins
- **Purpose**: Verify user credentials and extract claims (roles, attributes)
- **Input**: User credentials (username/password, SAML assertion, JWT token, etc.)
- **Output**: UserPrincipal containing identity and claims
- **Examples**: Internal, LDAP, SAML, JWT, Kerberos

### Authorization Plugins
- **Purpose**: Make access control decisions based on authenticated user claims
- **Input**: UserPrincipal (from authentication) and AuthorizationContext (action, resource)
- **Output**: AuthorizationResult (allow/deny with reason)
- **Examples**: Role-based, LDAP group-based

### Claims
- Key-value pairs extracted during authentication
- Examples: backend_roles, email, display_name, department, employee_id
- Used by authorization plugins to make access decisions

## Configuration Files

### Main Configuration Files

1. **config.yml** - Main security configuration
   - Contains both legacy and new plugin configuration formats
   - Legacy format still supported for backward compatibility
   - New format recommended for new deployments

2. **config_plugin_architecture.yml.example** - Comprehensive example
   - Demonstrates all available authentication plugins
   - Shows authorization plugin configuration
   - Includes detailed comments and examples

3. **config_migration_example.yml** - Migration guide
   - Shows side-by-side comparison of legacy vs new format
   - Includes step-by-step migration instructions
   - Demonstrates how both formats can coexist

4. **README_PLUGIN_ARCHITECTURE.md** - This file
   - Overview of plugin architecture
   - Configuration reference
   - Quick start guide

### Supporting Configuration Files

- **internal_users.yml** - Internal user database (unchanged)
- **roles.yml** - Security role definitions (unchanged)
- **roles_mapping.yml** - Backend role to security role mapping (can be replaced by inline config)

## Quick Start

### Example 1: Internal Authentication Only

```yaml
config:
  dynamic:
    authentication_plugins:
      - type: internal
        enabled: true
        order: 1
    
    authorization_plugins:
      - type: role_based
        enabled: true
        config:
          use_roles_mapping_file: true
```

### Example 2: LDAP Authentication with Role Mapping

```yaml
config:
  dynamic:
    authentication_plugins:
      - type: ldap
        enabled: true
        order: 1
        config:
          hosts: [ldap.example.com:389]
          bind_dn: cn=admin,dc=example,dc=com
          password: password
          userbase: 'ou=people,dc=example,dc=com'
          usersearch: '(uid={0})'
          claims_mapping:
            backend_roles: memberOf
            email: mail
    
    authorization_plugins:
      - type: role_based
        enabled: true
        config:
          roles_mapping:
            admin:
              backend_roles: [cn=admins,ou=groups,dc=example,dc=com]
            readall:
              backend_roles: [cn=developers,ou=groups,dc=example,dc=com]
```

### Example 3: Multiple Authentication Sources

```yaml
config:
  dynamic:
    authentication_plugins:
      - type: internal
        enabled: true
        order: 1
      
      - type: ldap
        enabled: true
        order: 2
        config:
          hosts: [ldap.example.com:389]
          # ... LDAP config
      
      - type: saml
        enabled: true
        order: 3
        config:
          idp_metadata_url: https://idp.example.com/metadata
          # ... SAML config
    
    authorization_plugins:
      - type: role_based
        enabled: true
        config:
          roles_mapping:
            admin:
              backend_roles:
                - admin                                    # Internal
                - cn=admins,ou=groups,dc=example,dc=com   # LDAP
                - http://schemas.xmlsoap.org/claims/admin # SAML
```

## Configuration Reference

### Authentication Plugin Configuration

```yaml
authentication_plugins:
  - type: <plugin_type>          # Required: internal, ldap, saml, jwt, kerberos
    enabled: <boolean>            # Required: true or false
    order: <number>               # Required: evaluation order (lower first)
    description: <string>         # Optional: human-readable description
    config:                       # Optional: plugin-specific configuration
      <key>: <value>
```

### Authorization Plugin Configuration

```yaml
authorization_plugins:
  - type: <plugin_type>          # Required: role_based, ldap
    enabled: <boolean>            # Required: true or false
    description: <string>         # Optional: human-readable description
    config:                       # Optional: plugin-specific configuration
      <key>: <value>
```

### Available Authentication Plugins

#### Internal
```yaml
- type: internal
  enabled: true
  order: 1
  # No additional config needed - uses internal_users.yml
```

#### LDAP
```yaml
- type: ldap
  enabled: true
  order: 2
  config:
    enable_ssl: false
    hosts: [ldap.example.com:389]
    bind_dn: cn=admin,dc=example,dc=com
    password: password
    userbase: 'ou=people,dc=example,dc=com'
    usersearch: '(uid={0})'
    claims_mapping:
      backend_roles: memberOf
      email: mail
      display_name: displayName
```

#### SAML
```yaml
- type: saml
  enabled: true
  order: 3
  config:
    idp_metadata_url: https://idp.example.com/metadata
    sp_entity_id: https://opensearch.example.com
    claims_mapping:
      backend_roles: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups
      email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
```

#### JWT
```yaml
- type: jwt
  enabled: true
  order: 4
  config:
    jwks_uri: https://auth.example.com/.well-known/jwks.json
    jwt_header: Authorization
    claims_mapping:
      backend_roles: roles
      email: email
```

#### Kerberos
```yaml
- type: kerberos
  enabled: true
  order: 5
  config:
    krb_debug: false
    strip_realm_from_principal: true
```

### Available Authorization Plugins

#### Role-Based
```yaml
- type: role_based
  enabled: true
  config:
    roles_mapping:
      admin:
        backend_roles: [Admins, cn=admins,ou=groups,dc=example,dc=com]
      readall:
        backend_roles: [Developers, cn=developers,ou=groups,dc=example,dc=com]
    # Or use file:
    # use_roles_mapping_file: true
```

#### LDAP
```yaml
- type: ldap
  enabled: true
  config:
    enable_ssl: false
    hosts: [ldap.example.com:389]
    bind_dn: cn=admin,dc=example,dc=com
    password: password
    rolebase: 'ou=groups,dc=example,dc=com'
    rolesearch: '(member={0})'
    rolename: cn
    resolve_nested_roles: true
```

## Claims Mapping

Claims mapping allows you to extract user attributes from authentication sources and make them available to authorization plugins.

### Common Claim Names

- `backend_roles` - List of roles/groups from authentication source
- `email` - User's email address
- `display_name` - User's full name
- `department` - User's department
- `employee_id` - Employee identifier
- `manager` - Manager identifier
- `title` - Job title

### LDAP Claims Mapping

```yaml
claims_mapping:
  backend_roles: memberOf        # LDAP attribute: memberOf
  email: mail                    # LDAP attribute: mail
  display_name: displayName      # LDAP attribute: displayName
  department: department         # LDAP attribute: department
  employee_id: employeeNumber    # LDAP attribute: employeeNumber
```

### SAML Claims Mapping

```yaml
claims_mapping:
  backend_roles: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups
  email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
  display_name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
```

### JWT Claims Mapping

```yaml
claims_mapping:
  backend_roles: roles           # JWT claim: roles
  email: email                   # JWT claim: email
  display_name: name             # JWT claim: name
  groups: groups                 # JWT claim: groups
```

## Role Mapping

Role mapping connects backend roles (from authentication claims) to security roles (defined in roles.yml).

### Inline Role Mapping

```yaml
authorization_plugins:
  - type: role_based
    enabled: true
    config:
      roles_mapping:
        admin:                    # Security role (from roles.yml)
          backend_roles:          # Backend roles (from authentication)
            - Admins
            - cn=admins,ou=groups,dc=example,dc=com
            - http://schemas.xmlsoap.org/claims/admin
        
        readall:
          backend_roles:
            - Developers
            - cn=developers,ou=groups,dc=example,dc=com
```

### File-Based Role Mapping

```yaml
authorization_plugins:
  - type: role_based
    enabled: true
    config:
      use_roles_mapping_file: true
```

Then configure roles_mapping.yml as usual.

## Migration from Legacy Format

### Legacy Format (Still Supported)

```yaml
authc:
  basic_internal_auth_domain:
    http_enabled: true
    order: 1
    http_authenticator:
      type: basic
    authentication_backend:
      type: intern

authz:
  roles_from_ldap:
    authorization_backend:
      type: ldap
      config:
        # ... LDAP config
```

### New Format (Recommended)

```yaml
authentication_plugins:
  - type: internal
    enabled: true
    order: 1

authorization_plugins:
  - type: role_based
    enabled: true
    config:
      use_roles_mapping_file: true
```

### Migration Steps

1. Review current configuration in authc and authz sections
2. Identify authentication backends and authorization backends
3. Create equivalent authentication_plugins configuration
4. Create equivalent authorization_plugins configuration
5. Test in non-production environment
6. Deploy to production (both formats can coexist)
7. Monitor and verify
8. Remove legacy configuration after verification

### Migration Tool

Use the configuration migration tool to automatically convert:

```bash
./tools/config-migration.sh config.yml
```

See `tools/CONFIG_MIGRATION_README.md` for details.

## Backward Compatibility

### Guaranteed Compatible

- Legacy authc/authz format continues to work
- Automatically converted to new plugin format internally
- User serialization format unchanged (critical for rolling upgrades)
- REST API behavior unchanged
- No configuration changes required for existing deployments

### Both Formats Can Coexist

During migration, you can have:
- Some authentication domains using legacy format
- Some authentication domains using new plugin format
- Legacy and new formats in the same configuration file

The system will handle both transparently.

## Troubleshooting

### Enable Debug Logging

```yaml
# In opensearch.yml or log4j2.properties
logger.org.opensearch.security.auth.plugin: DEBUG
```

This will log:
- Plugin selection and ordering
- Authentication attempts and results
- Claims extraction
- Authorization decisions
- Role mapping

### Common Issues

#### Authentication Fails

1. Check plugin order - plugins are tried in order
2. Verify credentials are correct
3. Check claims_mapping configuration
4. Review authentication plugin logs

#### Authorization Fails

1. Verify backend roles are extracted correctly (check logs)
2. Check role mapping configuration
3. Verify security roles exist in roles.yml
4. Review authorization plugin logs

#### Claims Not Extracted

1. Verify claims_mapping configuration
2. Check that authentication source provides the attributes
3. Review authentication plugin logs
4. Test with debug logging enabled

## Additional Resources

- **PLUGIN_MIGRATION_GUIDE.md** - Detailed migration guide for plugin developers
- **config_plugin_architecture.yml.example** - Comprehensive configuration example
- **config_migration_example.yml** - Side-by-side migration example
- **Design Document** - `.kiro/specs/authn-authz-separation/design.md`

## Support

For questions or issues:
1. Check this README and example configurations
2. Review PLUGIN_MIGRATION_GUIDE.md
3. Enable debug logging and review logs
4. Open an issue on GitHub



## Adapter Layer and Backward Compatibility

### Overview

As of the current release, all built-in authentication and authorization backends have been converted to use the new plugin interfaces directly. The adapter layer is now **ONLY** used for third-party custom backends that haven't migrated yet.

### Built-in Backends (Converted - No Adapters)

The following built-in backends now implement the new plugin interfaces directly:

**Authentication:**
- `InternalAuthenticationBackend` → implements `AuthenticationPlugin`
- `LDAPAuthenticationBackend2` → implements `AuthenticationPlugin`
- `HTTPSamlAuthenticator` → implements `AuthenticationPlugin`
- `HTTPJwtAuthenticator` → implements `AuthenticationPlugin`
- `HTTPSpnegoAuthenticator` → implements `AuthenticationPlugin`

**Authorization:**
- `LDAPAuthorizationBackend2` → implements `AuthorizationPlugin`
- `RoleBasedAuthorizationPlugin` → implements `AuthorizationPlugin`

### Adapter Usage

**When Adapters Are Used:**
- Only for third-party custom backends that still implement the old `AuthenticationBackend` or `AuthorizationBackend` interfaces
- Automatically by `BackendRegistry` when registering unconverted backends
- Transparent to the end user - no configuration changes needed

**When Adapters Are NOT Used:**
- All built-in backends (listed above) are registered directly without adapters
- Any custom backends that have been migrated to the new plugin interfaces
- Results in better performance and clearer stack traces

### Migration for Third-Party Plugins

If you have custom authentication or authorization backends, you should migrate them to the new plugin interfaces:

**Benefits of Migration:**
1. **Performance**: Eliminates adapter overhead
2. **Clarity**: Direct method calls without adapter intermediaries
3. **Features**: Access to new plugin capabilities
4. **Future-Proof**: Prepares for eventual removal of old interfaces

**Migration Steps:**
1. Update your backend class to implement `AuthenticationPlugin` or `AuthorizationPlugin`
2. Change return types: Return `UserPrincipal` instead of `User` for authentication
3. Extract claims: Put all user attributes into the claims map
4. Update registration: Use `registerAuthenticationPlugin()` or `registerAuthorizationPlugin()`
5. Test thoroughly: Verify behavior matches the old implementation

**Detailed Migration Guide:**
See `PLUGIN_MIGRATION_GUIDE.md` in the project root for comprehensive migration instructions with code examples.

### Deprecation Timeline

- **Current Release**: Adapters maintained for third-party plugins; old interfaces fully supported
- **Next Release**: Old interfaces (`AuthenticationBackend`, `AuthorizationBackend`) will be marked `@Deprecated`
- **Future Major Release**: Old interfaces will be removed (with advance notice)

### Configuration Impact

**No Configuration Changes Required:**
- Existing configuration files continue to work
- Both legacy and new configuration formats are supported
- Adapters are used automatically when needed
- No user-visible difference in behavior

**Recommended for New Deployments:**
- Use the new plugin configuration format (shown in examples above)
- Provides clearer separation of authentication and authorization
- Better aligns with the new architecture

## Troubleshooting

### How to Tell if Adapters Are Being Used

Check the OpenSearch logs during startup:

```
# Direct plugin registration (no adapter)
[INFO] Registering authentication plugin: InternalAuthenticationPlugin (type: internal)

# Adapter wrapping (third-party backend)
[INFO] Registering authentication backend (via adapter): CustomAuthBackend (type: custom)
```

### Performance Considerations

- **Converted backends**: Direct method calls, optimal performance
- **Unconverted backends**: Slight adapter overhead (conversion between User and UserPrincipal)
- **Recommendation**: Migrate custom backends to eliminate adapter overhead

### Compatibility Verification

To verify your custom backend works with the new architecture:

1. **Test with current release**: Backend should work via adapter
2. **Check logs**: Look for adapter wrapping messages
3. **Verify behavior**: Ensure authentication/authorization works as expected
4. **Plan migration**: Follow migration guide to eliminate adapter

## Additional Resources

- **Plugin Migration Guide**: `PLUGIN_MIGRATION_GUIDE.md` - Detailed migration instructions
- **Configuration Examples**: `config_plugin_architecture.yml.example` - Comprehensive examples
- **Migration Example**: `config_migration_example.yml` - Side-by-side comparison
- **Design Document**: `.kiro/specs/authn-authz-separation/design.md` - Architecture details
