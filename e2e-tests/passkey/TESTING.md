# Passkey Authentication E2E Testing Guide

## Overview

This guide explains how to run end-to-end tests for the passkey authentication feature.

## Prerequisites

1. **Docker and Docker Compose**: Required to run the test OpenSearch cluster
2. **Node.js 18+**: Required to run the test suite
3. **OpenSearch Security Plugin**: Must be built before running tests

## Setup

### 1. Install Dependencies

```bash
cd security/e2e-tests/passkey
npm install
```

### 2. Generate Test Certificates

```bash
./scripts/generate-certs.sh
```

This will create self-signed certificates in the `certs/` directory for SSL/TLS.

### 3. Start Test Cluster

```bash
npm run cluster:start
# or
./scripts/start-cluster.sh
```

This starts a Docker-based OpenSearch cluster with the Security plugin configured for passkey authentication.

## Running Tests

### Run All Tests

```bash
npm test
```

### Run Specific Test Suite

```bash
npm test -- tests/registration.test.js
npm test -- tests/authentication.test.js
npm test -- tests/credential-mgmt.test.js
npm test -- tests/security.test.js
npm test -- tests/multi-backend.test.js
```

### Run with Coverage

```bash
npm run test:coverage
```

### Watch Mode

```bash
npm run test:watch
```

## Test Suites

### 1. Registration Flow Tests (`registration.test.js`)

Tests the complete passkey registration flow:
- Generate registration options
- Register credential with virtual authenticator
- Verify credential storage
- Test different authenticator types
- Test user verification requirements
- Test duplicate credential prevention
- Test error scenarios

### 2. Authentication Flow Tests (`authentication.test.js`)

Tests the complete passkey authentication flow:
- Generate authentication options
- Authenticate with virtual authenticator
- Verify session creation
- Test multiple credentials
- Test expired challenges
- Test invalid signatures
- Test unknown credentials

### 3. Credential Management Tests (`credential-mgmt.test.js`)

Tests credential management operations:
- List user credentials
- Delete credentials
- Rename credentials
- Test credential isolation between users

### 4. Security Scenario Tests (`security.test.js`)

Tests security properties:
- Replay attack prevention
- Signature counter regression detection
- Origin validation enforcement
- RP ID validation enforcement
- Challenge expiration handling

### 5. Multi-Backend Integration Tests (`multi-backend.test.js`)

Tests integration with other authentication backends:
- Passkey alongside basic auth
- Fallback to other methods
- Authentication domain configuration
- Role mapping with passkey authentication

## Cleanup

### Stop Test Cluster

```bash
npm run cluster:stop
```

### Clean Up Test Data

```bash
npm run cleanup
```

This removes test credentials, challenges, and other test data from the cluster.

## Troubleshooting

### Cluster Won't Start

1. Check Docker is running: `docker ps`
2. Check logs: `docker-compose logs opensearch`
3. Verify ports are available: `lsof -i :9200`

### Tests Failing

1. Ensure cluster is running: `curl -k https://localhost:9200`
2. Check cluster health: `curl -k https://localhost:9200/_cluster/health`
3. Review test logs for specific errors
4. Check OpenSearch logs: `docker-compose logs opensearch`

### Certificate Issues

1. Regenerate certificates: `./scripts/generate-certs.sh`
2. Restart cluster: `npm run cluster:stop && npm run cluster:start`

## Adding New Tests

1. Create a new test file in `tests/` directory
2. Import test utilities from `utils/`
3. Follow existing test patterns
4. Add test to CI/CD pipeline if needed

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```bash
# In CI pipeline
cd security/e2e-tests/passkey
npm install
./scripts/start-cluster.sh
npm test
./scripts/cleanup.sh
npm run cluster:stop
```

## Test Architecture

### Virtual Authenticator

The `utils/virtual-authenticator.js` module simulates a WebAuthn authenticator:
- Generates key pairs
- Creates attestation objects
- Signs authentication assertions
- Supports different authenticator types

### Test Client

The `utils/test-client.js` module provides HTTP client functionality:
- Makes authenticated requests to OpenSearch
- Handles SSL/TLS
- Manages sessions and cookies
- Formats WebAuthn requests/responses

### Test Helpers

The `utils/test-helpers.js` module provides common utilities:
- User creation and cleanup
- Credential verification
- Challenge validation
- Assertion helpers

## Performance Considerations

- Tests run sequentially to avoid race conditions
- Each test suite uses isolated test users
- Cleanup runs after each test to prevent state leakage
- Cluster is shared across all tests for efficiency

## Security Notes

- Test certificates are self-signed and for testing only
- Test users have minimal permissions
- Test data is cleaned up after tests
- Do not use test configuration in production
