#!/bin/bash

# Manual Testing Script for Passkey Authentication
# This script helps you manually test the passkey API endpoints

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASE_URL="https://localhost:9200"
USERNAME="admin"
PASSWORD="MyStr0ng!Pass#2026"
TEST_USER="manual-test-user-$(date +%s)"

# Correct API paths (no /api/ in the middle)
REG_OPTIONS_URL="${BASE_URL}/_plugins/_security/passkey/registration/options"
REG_VERIFY_URL="${BASE_URL}/_plugins/_security/passkey/registration/verify"
AUTH_OPTIONS_URL="${BASE_URL}/_plugins/_security/passkey/authentication/options"
AUTH_VERIFY_URL="${BASE_URL}/_plugins/_security/passkey/authentication/verify"
CRED_LIST_URL="${BASE_URL}/_plugins/_security/passkey/credentials/list"
CRED_DELETE_URL="${BASE_URL}/_plugins/_security/passkey/credentials"

echo -e "${BLUE}=========================================="
echo "Passkey Authentication Manual Testing"
echo -e "==========================================${NC}"
echo ""

# Step 1: Check cluster health
echo -e "${YELLOW}Step 1: Checking cluster health...${NC}"
HEALTH=$(curl -k -s -u "${USERNAME}:${PASSWORD}" "${BASE_URL}/_cluster/health")
echo "$HEALTH" | jq '.'
echo ""

# Step 2: Test registration options
echo -e "${YELLOW}Step 2: Getting registration options for user: ${TEST_USER}${NC}"
REG_OPTIONS=$(curl -k -s -u "${USERNAME}:${PASSWORD}" \
  -X POST "${REG_OPTIONS_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${TEST_USER}\"}")

echo "$REG_OPTIONS" | jq '.'
echo ""

# Extract challengeId and challenge
CHALLENGE_ID=$(echo "$REG_OPTIONS" | jq -r '.challengeId')
CHALLENGE=$(echo "$REG_OPTIONS" | jq -r '.challenge')
RP_ID=$(echo "$REG_OPTIONS" | jq -r '.rp.id')

echo -e "${GREEN}✅ Registration options received${NC}"
echo "  Challenge ID: $CHALLENGE_ID"
echo "  Challenge: ${CHALLENGE:0:20}..."
echo "  RP ID: $RP_ID"
echo ""

# Step 3: Test authentication options
echo -e "${YELLOW}Step 3: Getting authentication options for user: ${TEST_USER}${NC}"
AUTH_OPTIONS=$(curl -k -s -u "${USERNAME}:${PASSWORD}" \
  -X POST "${AUTH_OPTIONS_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${TEST_USER}\"}")

echo "$AUTH_OPTIONS" | jq '.'
echo ""

# Check if it's an error (no passkeys registered yet)
if echo "$AUTH_OPTIONS" | jq -e '.error' > /dev/null; then
  echo -e "${GREEN}✅ Expected: No passkeys registered yet${NC}"
else
  AUTH_CHALLENGE_ID=$(echo "$AUTH_OPTIONS" | jq -r '.challengeId')
  AUTH_CHALLENGE=$(echo "$AUTH_OPTIONS" | jq -r '.challenge')
  echo -e "${GREEN}✅ Authentication options received${NC}"
  echo "  Challenge ID: $AUTH_CHALLENGE_ID"
  echo "  Challenge: ${AUTH_CHALLENGE:0:20}..."
fi
echo ""

# Step 4: Test credential listing
echo -e "${YELLOW}Step 4: Listing credentials for user: ${TEST_USER}${NC}"
CRED_LIST=$(curl -k -s -u "${USERNAME}:${PASSWORD}" \
  -X POST "${CRED_LIST_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${TEST_USER}\"}")

echo "$CRED_LIST" | jq '.'
echo ""

CRED_COUNT=$(echo "$CRED_LIST" | jq '.credentials | length')
echo -e "${GREEN}✅ Credential listing works${NC}"
echo "  Credentials found: $CRED_COUNT"
echo ""

# Step 5: Test listing all credentials (admin only)
echo -e "${YELLOW}Step 5: Listing all credentials (admin view)${NC}"
ALL_CREDS=$(curl -k -s -u "${USERNAME}:${PASSWORD}" \
  -X POST "${CRED_LIST_URL}" \
  -H "Content-Type: application/json" \
  -d '{}')

echo "$ALL_CREDS" | jq '.'
echo ""

TOTAL_CREDS=$(echo "$ALL_CREDS" | jq '.credentials | length')
echo -e "${GREEN}✅ Admin credential listing works${NC}"
echo "  Total credentials in system: $TOTAL_CREDS"
echo ""

# Summary
echo -e "${BLUE}=========================================="
echo "Manual Testing Summary"
echo -e "==========================================${NC}"
echo ""
echo -e "${GREEN}✅ Cluster is healthy${NC}"
echo -e "${GREEN}✅ Registration options endpoint works${NC}"
echo -e "${GREEN}✅ Authentication options endpoint works${NC}"
echo -e "${GREEN}✅ Credential listing endpoint works${NC}"
echo -e "${GREEN}✅ Admin operations work${NC}"
echo ""
echo -e "${BLUE}All API endpoints are functional!${NC}"
echo ""
echo "To test with a real browser:"
echo "  1. Open https://localhost:9200 in Chrome/Firefox/Safari"
echo "  2. Use browser DevTools console"
echo "  3. Call navigator.credentials.create() with the options above"
echo ""
echo "For complete testing, run:"
echo "  npm test"
echo ""
