#!/bin/bash

# Run all passkey e2e tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Running passkey e2e tests..."

# Check if cluster is running
if ! curl -k -s -u admin:Admin123! https://localhost:9200/_cluster/health > /dev/null 2>&1; then
  echo "Error: OpenSearch cluster is not running."
  echo "Start the cluster with: npm run cluster:start"
  exit 1
fi

# Check if node_modules exists
if [ ! -d "$PROJECT_DIR/node_modules" ]; then
  echo "Installing dependencies..."
  cd "$PROJECT_DIR"
  npm install
fi

# Run tests
cd "$PROJECT_DIR"

if [ $# -eq 0 ]; then
  # Run all tests
  echo "Running all tests..."
  npm test
else
  # Run specific test file
  echo "Running tests: $@"
  npm test -- "$@"
fi

echo ""
echo "Tests completed!"
