#!/bin/bash

# Clean up test data from OpenSearch cluster

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Cleaning up test data..."

# Check if cluster is running
if ! curl -k -s -u admin:Admin123! https://localhost:9200/_cluster/health > /dev/null 2>&1; then
  echo "Warning: OpenSearch cluster is not running. Skipping cleanup."
  exit 0
fi

BASE_URL="https://localhost:9200"
AUTH="admin:Admin123!"

# Delete test indices
echo "Deleting test indices..."
curl -k -s -u "$AUTH" -X DELETE "$BASE_URL/test-*" > /dev/null 2>&1 || true
curl -k -s -u "$AUTH" -X DELETE "$BASE_URL/basic-*" > /dev/null 2>&1 || true

# Delete passkey credentials index (if exists)
echo "Deleting passkey credentials..."
curl -k -s -u "$AUTH" -X DELETE "$BASE_URL/.passkey-credentials" > /dev/null 2>&1 || true

# Delete challenge store (if exists)
echo "Deleting challenge store..."
curl -k -s -u "$AUTH" -X DELETE "$BASE_URL/.passkey-challenges" > /dev/null 2>&1 || true

# Refresh indices
echo "Refreshing indices..."
curl -k -s -u "$AUTH" -X POST "$BASE_URL/_refresh" > /dev/null 2>&1 || true

echo "Cleanup completed!"
