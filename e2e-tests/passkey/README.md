# Passkey Authentication End-to-End Tests

This directory contains end-to-end integration tests for the passkey authentication feature in OpenSearch Security.

## Directory Structure

```
e2e-tests/passkey/
├── README.md                    # This file
├── docker-compose.yml           # Docker setup for test cluster
├── config/                      # Test configuration files
│   ├── opensearch.yml          # OpenSearch configuration
│   ├── config.yml              # Security plugin configuration
│   ├── internal_users.yml      # Test users
│   └── roles_mapping.yml       # Role mappings
├── certs/                       # SSL certificates for testing
├── utils/                       # Test utilities and helpers
│   ├── virtual-authenticator.js # WebAuthn simulator
│   ├── test-client.js          # HTTP client for API calls
│   └── test-helpers.js         # Common test utilities
├── tests/                       # Test suites
│   ├── registration.test.js    # Registration flow tests
│   ├── authentication.test.js  # Authentication flow tests
│   ├── credential-mgmt.test.js # Credential management tests
│   ├── security.test.js        # Security scenario tests
│   └── multi-backend.test.js   # Multi-backend integration tests
└── scripts/                     # Automation scripts
    ├── start-cluster.sh        # Start test cluster
    ├── run-tests.sh            # Run all tests
    └── cleanup.sh              # Clean up test data
```

## Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for test execution)
- OpenSearch Security plugin built

## Running Tests

See the main documentation in `TESTING.md` for detailed instructions.

## Test Coverage

These end-to-end tests validate:
- Complete registration and authentication flows
- Credential management operations
- Security properties (replay prevention, counter checks, etc.)
- Multi-backend integration
- Error handling and edge cases
