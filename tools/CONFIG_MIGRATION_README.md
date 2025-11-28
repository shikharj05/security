# Configuration Migration Tool

## Overview

The Configuration Migration Tool helps you migrate from the old authentication/authorization backend configuration format to the new plugin-based configuration format introduced in the authentication and authorization plugin separation feature.

## What Does It Migrate?

The tool migrates:

1. **Authentication Domains** (`config.dynamic.authc`) → **Authentication Plugins** (`plugins.security.authentication`)
2. **Authorization Backends** (`config.dynamic.authz`) → **Authorization Plugins** (`plugins.security.authorization`)

### Supported Backend Types

**Authentication:**
- Internal (`intern` → `internal`)
- LDAP (`ldap` → `ldap`)
- No-op (`noop` → `noop`)

**Authorization:**
- LDAP (`ldap` → `ldap`)
- No-op (`noop` → `noop`)
- Other types → `role_based`

## Usage

### Linux/macOS

```bash
./tools/config-migration.sh <old-config-path> <new-config-path>
```

### Windows

```cmd
tools\config-migration.bat <old-config-path> <new-config-path>
```

### Options

- `-h, --help`: Display help message
- `-v, --verbose`: Enable verbose output
- `-d, --dry-run`: Preview migration without writing output

### Examples

**Basic migration:**
```bash
./tools/config-migration.sh /etc/opensearch/config.yml /etc/opensearch/config-new.yml
```

**Dry run to preview changes:**
```bash
./tools/config-migration.sh --dry-run /etc/opensearch/config.yml /tmp/config-preview.yml
```

**Verbose output:**
```bash
./tools/config-migration.sh --verbose /etc/opensearch/config.yml /etc/opensearch/config-new.yml
```

## Migration Examples

### Example 1: Internal Authentication

**Old Configuration:**
```yaml
config:
  dynamic:
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 4
        http_authenticator:
          type: basic
          challenge: true
        authentication_backend:
          type: intern
```

**New Configuration:**
```yaml
plugins.security.authentication:
  - type: internal
    enabled: true
    order: 4
    _comment: "Authenticate via HTTP Basic against internal users database"
```

### Example 2: LDAP Authentication

**Old Configuration:**
```yaml
config:
  dynamic:
    authc:
      ldap:
        description: "Authenticate via LDAP"
        http_enabled: true
        transport_enabled: true
        order: 5
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: ldap
          config:
            enable_ssl: false
            hosts:
              - localhost:8389
            bind_dn: null
            password: null
            userbase: 'ou=people,dc=example,dc=com'
            usersearch: '(sAMAccountName={0})'
            username_attribute: null
```

**New Configuration:**
```yaml
plugins.security.authentication:
  - type: ldap
    enabled: true
    order: 5
    config:
      hosts: localhost:8389
      bind_dn: null
      password: null
      userbase: ou=people,dc=example,dc=com
      usersearch: (sAMAccountName={0})
      username_attribute: null
      enable_ssl: false
      claims_mapping:
        groups: memberOf
        email: mail
    _comment: "Authenticate via LDAP"
```

### Example 3: LDAP Authorization

**Old Configuration:**
```yaml
config:
  dynamic:
    authz:
      roles_from_myldap:
        description: "Authorize via LDAP"
        http_enabled: true
        transport_enabled: true
        authorization_backend:
          type: ldap
          config:
            enable_ssl: false
            hosts:
              - localhost:8389
            bind_dn: null
            password: null
            rolebase: 'ou=groups,dc=example,dc=com'
            rolesearch: '(member={0})'
            rolename: cn
            resolve_nested_roles: true
```

**New Configuration:**
```yaml
plugins.security.authorization:
  - type: ldap
    enabled: true
    config:
      hosts: localhost:8389
      bind_dn: null
      password: null
      rolebase: ou=groups,dc=example,dc=com
      rolesearch: (member={0})
      rolename: cn
      resolve_nested_roles: true
      enable_ssl: false
    _comment: "Authorize via LDAP"
```

## What Gets Migrated?

### Authentication Domains

For each authentication domain, the tool migrates:

- **Type**: Backend type (mapped to plugin type)
- **Enabled**: Derived from `http_enabled` and `transport_enabled`
- **Order**: Plugin execution order
- **Configuration**: Backend-specific settings
- **Description**: Preserved as `_comment` field

### Authorization Backends

For each authorization backend, the tool migrates:

- **Type**: Backend type (mapped to plugin type)
- **Enabled**: Derived from `http_enabled` and `transport_enabled`
- **Configuration**: Backend-specific settings
- **Description**: Preserved as `_comment` field

### Special Handling

1. **LDAP Claims Mapping**: The tool automatically adds a `claims_mapping` section for LDAP authentication plugins with default mappings:
   - `groups: memberOf`
   - `email: mail`

2. **Disabled Domains**: Domains with both `http_enabled: false` and `transport_enabled: false` are migrated with `enabled: false`

3. **Multiple Domains**: All authentication domains and authorization backends are migrated, preserving their order

## Validation

The tool validates the migrated configuration to ensure:

1. All plugins have a `type` field
2. The `type` field is not empty
3. All plugins have an `enabled` field
4. Configuration structure is valid

If validation fails, the tool will report the error and exit without writing the output file.

## Important Notes

### Before Migration

1. **Backup your configuration**: Always create a backup of your current configuration before migration
2. **Review the old configuration**: Ensure your old configuration is valid and working
3. **Build the project**: The migration tool requires the project to be built first:
   ```bash
   ./gradlew build
   ```

### After Migration

1. **Review the new configuration**: Carefully review the migrated configuration
2. **Test in non-production**: Test the new configuration in a development or staging environment first
3. **Update OpenSearch**: Replace your old configuration with the new one
4. **Restart OpenSearch**: Restart OpenSearch to apply the new configuration
5. **Verify functionality**: Verify that authentication and authorization work as expected

### Limitations

1. **HTTP Authenticator Settings**: The tool does not migrate HTTP authenticator settings (e.g., `challenge`, `jwt_header`). These need to be configured separately in the new plugin system.

2. **Custom Backends**: If you have custom authentication or authorization backends, you may need to manually adjust the migrated configuration.

3. **Complex Configurations**: For very complex configurations with custom settings, manual review and adjustment may be necessary.

4. **Comments**: YAML comments in the old configuration are not preserved (except for the `description` field which becomes `_comment`).

## Troubleshooting

### JAR File Not Found

**Error**: `OpenSearch Security JAR file not found`

**Solution**: Build the project first:
```bash
./gradlew build
```

### Old Configuration Not Found

**Error**: `Old configuration file not found`

**Solution**: Verify the path to your old configuration file is correct.

### Validation Errors

**Error**: `Authentication plugin missing required 'type' field`

**Solution**: Check that your old configuration has valid authentication backends with a `type` field.

### Permission Errors

**Error**: Permission denied when writing new configuration

**Solution**: Ensure you have write permissions to the output directory.

## Getting Help

If you encounter issues with the migration tool:

1. Check the error messages for specific details
2. Review the [Plugin Migration Guide](../PLUGIN_MIGRATION_GUIDE.md)
3. Consult the OpenSearch Security documentation
4. Open an issue on the OpenSearch Security GitHub repository

## See Also

- [Plugin Migration Guide](../PLUGIN_MIGRATION_GUIDE.md) - Guide for migrating custom plugins
- [Design Document](../.kiro/specs/authn-authz-separation/design.md) - Detailed design of the new plugin architecture
- [Requirements Document](../.kiro/specs/authn-authz-separation/requirements.md) - Requirements for the plugin separation feature
