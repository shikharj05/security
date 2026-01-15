# Passkey E2E Test Scenarios

This document describes all test scenarios covered by the passkey e2e test suite.

## Test Coverage Overview

| Category | Test File | Requirements | Test Count |
|----------|-----------|--------------|------------|
| Registration | registration.test.js | 2.1, 2.2, 2.3, 2.4, 2.5 | 8 |
| Authentication | authentication.test.js | 3.1, 3.2, 3.3, 3.4, 3.5 | 8 |
| Credential Management | credential-mgmt.test.js | 5.1, 5.2, 5.3, 5.4 | 9 |
| Security | security.test.js | 4.1, 4.2, 4.3, 4.4, 4.5 | 9 |
| Multi-Backend | multi-backend.test.js | 1.5, 7.1, 7.2, 7.3, 7.4 | 8 |

## Registration Flow Tests

### 1. Complete Registration Flow
**File:** registration.test.js  
**Requirements:** 2.1, 2.2, 2.3, 2.4

**Scenario:**
1. User requests registration options
2. System generates challenge and returns options
3. User creates credential with authenticator
4. System verifies attestation
5. System stores credential
6. Credential appears in user's credential list

**Expected Result:** Credential successfully registered and stored

### 2. Platform Authenticator Registration
**File:** registration.test.js  
**Requirements:** 2.1, 2.2, 2.3

**Scenario:**
- Register credential using platform authenticator (e.g., Touch ID, Windows Hello)

**Expected Result:** Registration succeeds with platform authenticator

### 3. Cross-Platform Authenticator Registration
**File:** registration.test.js  
**Requirements:** 2.1, 2.2, 2.3

**Scenario:**
- Register credential using cross-platform authenticator (e.g., USB security key)

**Expected Result:** Registration succeeds with cross-platform authenticator

### 4. User Verification Required
**File:** registration.test.js  
**Requirements:** 2.1, 2.2, 2.3

**Scenario:**
- Register credential with user verification requirement set to "required"

**Expected Result:** Registration succeeds with user verification

### 5. Duplicate Credential Prevention
**File:** registration.test.js  
**Requirements:** 2.5

**Scenario:**
1. User registers first credential
2. User requests registration options again
3. System excludes first credential from options

**Expected Result:** First credential ID appears in excludeCredentials list

### 6. Invalid Attestation Error
**File:** registration.test.js  
**Requirements:** 2.3

**Scenario:**
- Submit registration with invalid attestation data

**Expected Result:** Registration fails with appropriate error

### 7. Challenge Mismatch Error
**File:** registration.test.js  
**Requirements:** 2.3

**Scenario:**
- Submit registration with wrong challenge

**Expected Result:** Registration fails with challenge mismatch error

### 8. Expired Challenge Error
**File:** registration.test.js  
**Requirements:** 2.3

**Scenario:**
- Wait for challenge to expire, then submit registration

**Expected Result:** Registration fails with expired challenge error (if expired)

## Authentication Flow Tests

### 1. Complete Authentication Flow
**File:** authentication.test.js  
**Requirements:** 3.1, 3.2, 3.3, 3.4, 3.5

**Scenario:**
1. User requests authentication options
2. System generates challenge and returns options
3. User creates assertion with authenticator
4. System verifies signature
5. System validates challenge
6. System creates user principal

**Expected Result:** Authentication succeeds and user session created

### 2. Multiple Credentials Authentication
**File:** authentication.test.js  
**Requirements:** 3.1, 3.2, 3.3, 3.5

**Scenario:**
1. User registers multiple credentials
2. User authenticates with first credential
3. User authenticates with second credential

**Expected Result:** Both authentications succeed

### 3. Expired Challenge Error
**File:** authentication.test.js  
**Requirements:** 3.4

**Scenario:**
- Wait for challenge to expire, then submit authentication

**Expected Result:** Authentication fails with expired challenge error (if expired)

### 4. Invalid Signature Error
**File:** authentication.test.js  
**Requirements:** 3.3

**Scenario:**
- Submit authentication with corrupted signature

**Expected Result:** Authentication fails with signature verification error

### 5. Unknown Credential Error
**File:** authentication.test.js  
**Requirements:** 3.3

**Scenario:**
- Attempt authentication with non-existent credential

**Expected Result:** Authentication fails with unknown credential error

### 6. Challenge Mismatch Error
**File:** authentication.test.js  
**Requirements:** 3.4

**Scenario:**
- Submit authentication with wrong challenge

**Expected Result:** Authentication fails with challenge mismatch error

### 7. Authentication Without Username
**File:** authentication.test.js  
**Requirements:** 3.1, 3.2

**Scenario:**
- Request authentication options without specifying username

**Expected Result:** System returns options for any registered credential

### 8. Multiple Authentication Attempts
**File:** authentication.test.js  
**Requirements:** 3.1, 3.2, 3.3

**Scenario:**
- Perform multiple authentication attempts in sequence

**Expected Result:** All attempts work independently

## Credential Management Tests

### 1. List User Credentials
**File:** credential-mgmt.test.js  
**Requirements:** 5.1

**Scenario:**
1. User registers multiple credentials
2. User requests credential list

**Expected Result:** All credentials returned with complete metadata

### 2. Credential Metadata Completeness
**File:** credential-mgmt.test.js  
**Requirements:** 5.2

**Scenario:**
- Verify credential metadata includes all required fields

**Expected Result:** Metadata includes createdAt, lastUsedAt, friendlyName

### 3. Delete Credential
**File:** credential-mgmt.test.js  
**Requirements:** 5.3

**Scenario:**
1. User registers credential
2. User deletes credential
3. Credential no longer appears in list
4. Authentication with deleted credential fails

**Expected Result:** Credential successfully deleted and unusable

### 4. Rename Credential
**File:** credential-mgmt.test.js  
**Requirements:** 5.4

**Scenario:**
1. User registers credential with name "Original Name"
2. User renames credential to "New Name"
3. Credential list shows updated name

**Expected Result:** Friendly name successfully updated

### 5. Credential Isolation Between Users
**File:** credential-mgmt.test.js  
**Requirements:** 5.1, 5.3

**Scenario:**
1. User 1 registers credential
2. User 2 registers credential
3. User 1's credential not visible to User 2
4. User 2's credential not visible to User 1

**Expected Result:** Credentials properly isolated by user

### 6. Delete Non-Existent Credential Error
**File:** credential-mgmt.test.js  
**Requirements:** 5.3

**Scenario:**
- Attempt to delete non-existent credential

**Expected Result:** Returns 404 or appropriate error

### 7. Update Non-Existent Credential Error
**File:** credential-mgmt.test.js  
**Requirements:** 5.4

**Scenario:**
- Attempt to update non-existent credential

**Expected Result:** Returns 404 or appropriate error

### 8. Empty Credential List
**File:** credential-mgmt.test.js  
**Requirements:** 5.1

**Scenario:**
- Request credential list for user with no credentials

**Expected Result:** Returns empty array

### 9. Multiple Credential Management
**File:** credential-mgmt.test.js  
**Requirements:** 5.1, 5.3, 5.4

**Scenario:**
- Register, list, rename, and delete multiple credentials

**Expected Result:** All operations work correctly with multiple credentials

## Security Scenario Tests

### 1. Replay Attack Prevention
**File:** security.test.js  
**Requirements:** 4.3

**Scenario:**
1. User authenticates successfully
2. Attacker captures and replays same assertion

**Expected Result:** Replay attempt fails

### 2. Signature Counter Regression Detection
**File:** security.test.js  
**Requirements:** 4.3

**Scenario:**
1. User authenticates (counter = 1)
2. User authenticates again (counter = 2)
3. Verify counter increased

**Expected Result:** Counter increases with each authentication

### 3. Origin Validation Enforcement
**File:** security.test.js  
**Requirements:** 4.2

**Scenario:**
- Verify assertions with correct origin succeed

**Expected Result:** Origin validation enforced

### 4. RP ID Validation Enforcement
**File:** security.test.js  
**Requirements:** 4.2

**Scenario:**
- Verify assertions with correct RP ID succeed
- Assertions with wrong RP ID fail

**Expected Result:** RP ID validation enforced

### 5. Challenge Expiration Handling
**File:** security.test.js  
**Requirements:** 4.4

**Scenario:**
- Wait for challenge to expire, then use it

**Expected Result:** Expired challenges rejected

### 6. Challenge Uniqueness
**File:** security.test.js  
**Requirements:** 4.1

**Scenario:**
- Request multiple challenges
- Verify all are unique

**Expected Result:** All challenges are unique

### 7. Challenge Entropy
**File:** security.test.js  
**Requirements:** 4.1

**Scenario:**
- Verify challenge has sufficient length and randomness

**Expected Result:** Challenge has at least 128 bits of entropy

### 8. Multiple Failed Attempts
**File:** security.test.js  
**Requirements:** 3.3

**Scenario:**
1. Attempt multiple failed authentications
2. Attempt successful authentication

**Expected Result:** Failed attempts don't block legitimate authentication

### 9. Challenge Cleanup
**File:** security.test.js  
**Requirements:** 4.5

**Scenario:**
- Verify used/expired challenges are removed

**Expected Result:** Challenges cleaned up after use/expiration

## Multi-Backend Integration Tests

### 1. Passkey Alongside Basic Auth
**File:** multi-backend.test.js  
**Requirements:** 1.5

**Scenario:**
- Verify both passkey and basic auth work concurrently

**Expected Result:** Both authentication methods work

### 2. Fallback to Basic Auth
**File:** multi-backend.test.js  
**Requirements:** 1.5

**Scenario:**
1. Passkey authentication fails
2. Basic authentication still works

**Expected Result:** Fallback to basic auth succeeds

### 3. Authentication Domain Configuration
**File:** multi-backend.test.js  
**Requirements:** 1.1

**Scenario:**
- Verify passkey domain is properly configured

**Expected Result:** Configuration includes passkey domain

### 4. Role Mapping
**File:** multi-backend.test.js  
**Requirements:** 7.2

**Scenario:**
- Verify passkey authentication applies role mappings

**Expected Result:** User principal has correct roles

### 5. User Attributes Population
**File:** multi-backend.test.js  
**Requirements:** 7.5

**Scenario:**
- Verify user attributes are populated after passkey auth

**Expected Result:** User principal has username and attributes

### 6. Authorization Consistency
**File:** multi-backend.test.js  
**Requirements:** 7.4

**Scenario:**
- Verify passkey and basic auth use same authorization rules

**Expected Result:** Same permissions apply regardless of auth method

### 7. Multiple Authentication Attempts
**File:** multi-backend.test.js  
**Requirements:** 1.5

**Scenario:**
- Alternate between passkey and basic auth

**Expected Result:** Both methods work without interference

### 8. Authentication Order
**File:** multi-backend.test.js  
**Requirements:** 1.1

**Scenario:**
- Verify passkey domain has correct order in configuration

**Expected Result:** Passkey tried before basic auth

## Test Execution

### Running All Tests
```bash
npm test
```

### Running Specific Test Suite
```bash
npm test -- tests/registration.test.js
npm test -- tests/authentication.test.js
npm test -- tests/credential-mgmt.test.js
npm test -- tests/security.test.js
npm test -- tests/multi-backend.test.js
```

### Running Specific Test
```bash
npm test -- -t "Complete registration flow"
```

## Coverage Goals

- **Line Coverage:** > 80%
- **Branch Coverage:** > 75%
- **Function Coverage:** > 80%
- **Statement Coverage:** > 80%

## Test Maintenance

Tests should be updated when:
- New features are added
- Requirements change
- Bugs are discovered
- API changes occur
- Security vulnerabilities are found

## Related Documentation

- [TESTING.md](TESTING.md) - How to run tests
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to add new tests
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
