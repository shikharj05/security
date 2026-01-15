# Contributing to Passkey E2E Tests

## Adding New Tests

### Test Structure

All tests should follow this structure:

```javascript
import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { TestClient } from '../utils/test-client.js';
import { VirtualAuthenticator } from '../utils/virtual-authenticator.js';
import { /* helpers */ } from '../utils/test-helpers.js';

describe('Test Suite Name', () => {
  let client;
  let authenticator;
  const testUsers = [];
  const testCredentials = [];

  beforeAll(async () => {
    client = new TestClient({
      baseUrl: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      username: 'admin',
      password: 'Admin123!'
    });
    await client.waitForCluster(60000);
    authenticator = new VirtualAuthenticator();
  });

  afterAll(async () => {
    // Cleanup test data
  });

  test('Test case description', async () => {
    // Test implementation
  });
});
```

### Test Guidelines

1. **Isolation**: Each test should be independent and not rely on other tests
2. **Cleanup**: Always clean up test data in `afterAll` hooks
3. **Assertions**: Use descriptive assertion messages
4. **Naming**: Use clear, descriptive test names that explain what is being tested
5. **Documentation**: Add comments for complex test logic

### Test Categories

- **registration.test.js**: Registration flow tests
- **authentication.test.js**: Authentication flow tests
- **credential-mgmt.test.js**: Credential management tests
- **security.test.js**: Security scenario tests
- **multi-backend.test.js**: Multi-backend integration tests

### Helper Functions

Use helper functions from `test-helpers.js`:

```javascript
import {
  generateUsername,
  assertStatus,
  assertHasField,
  verifyCredentialStructure,
  sleep
} from '../utils/test-helpers.js';
```

### Virtual Authenticator

The `VirtualAuthenticator` simulates a WebAuthn authenticator:

```javascript
const authenticator = new VirtualAuthenticator({
  type: 'platform', // or 'cross-platform'
  supportsUserVerification: true,
  supportsResidentKey: true
});

// Create credential
const credential = authenticator.makeCredential({
  rpId: 'localhost',
  userId: 'user-id',
  challenge: challengeBuffer
});

// Get assertion
const assertion = authenticator.getAssertion({
  rpId: 'localhost',
  challenge: challengeBuffer,
  allowCredentials: []
});
```

### Test Client

The `TestClient` provides HTTP methods for OpenSearch API:

```javascript
// Passkey operations
await client.getRegistrationOptions(username);
await client.verifyRegistration(credential);
await client.getAuthenticationOptions(username);
await client.verifyAuthentication(assertion);
await client.listCredentials();
await client.deleteCredential(credentialId);
await client.updateCredential(credentialId, metadata);

// General operations
await client.get(path);
await client.post(path, body);
await client.put(path, body);
await client.delete(path);
```

## Running Tests Locally

### Prerequisites

- Docker and Docker Compose
- Node.js 18+
- OpenSearch Security plugin built

### Setup

```bash
cd security/e2e-tests/passkey
npm install
./scripts/generate-certs.sh
./scripts/start-cluster.sh
```

### Run Tests

```bash
# All tests
npm test

# Specific test file
npm test -- tests/registration.test.js

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Cleanup

```bash
npm run cleanup
npm run cluster:stop
```

## Debugging Tests

### View Cluster Logs

```bash
docker-compose logs -f opensearch
```

### Check Cluster Health

```bash
curl -k -u admin:Admin123! https://localhost:9200/_cluster/health
```

### Inspect Test Data

```bash
# List credentials
curl -k -u admin:Admin123! https://localhost:9200/.passkey-credentials/_search

# List challenges
curl -k -u admin:Admin123! https://localhost:9200/.passkey-challenges/_search
```

### Debug Test Failures

1. Check test output for error messages
2. Review cluster logs for server-side errors
3. Add `console.log` statements to tests
4. Use `sleep()` to add delays if timing issues
5. Run single test in isolation

## Common Issues

### Cluster Won't Start

- Check Docker is running: `docker ps`
- Check ports are available: `lsof -i :9200`
- Review logs: `docker-compose logs`
- Try: `docker-compose down -v && docker-compose up -d`

### Tests Timeout

- Increase test timeout in jest.config.js
- Check cluster is responsive: `curl -k https://localhost:9200`
- Verify network connectivity

### Certificate Errors

- Regenerate certificates: `./scripts/generate-certs.sh`
- Restart cluster: `npm run cluster:stop && npm run cluster:start`

### Test Data Conflicts

- Run cleanup: `npm run cleanup`
- Use unique usernames: `generateUsername()`
- Clean up in `afterAll` hooks

## Best Practices

1. **Test Independence**: Don't rely on test execution order
2. **Unique Data**: Generate unique usernames and credentials
3. **Proper Cleanup**: Always clean up test data
4. **Clear Assertions**: Use descriptive error messages
5. **Minimal Tests**: Test one thing per test case
6. **Fast Tests**: Avoid unnecessary delays
7. **Readable Code**: Use helper functions and clear variable names
8. **Documentation**: Comment complex logic

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Passkey E2E Tests

on: [push, pull_request]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - name: Run E2E Tests
        run: |
          cd security/e2e-tests/passkey
          ./scripts/ci-run.sh
```

### Jenkins Example

```groovy
pipeline {
  agent any
  stages {
    stage('E2E Tests') {
      steps {
        sh '''
          cd security/e2e-tests/passkey
          ./scripts/ci-run.sh
        '''
      }
    }
  }
}
```

## Questions?

For questions or issues with e2e tests, please:
1. Check this documentation
2. Review existing tests for examples
3. Check the main TESTING.md guide
4. Open an issue with details
