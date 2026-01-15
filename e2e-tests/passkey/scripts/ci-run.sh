#!/bin/bash

# CI/CD pipeline script for running passkey e2e tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Passkey E2E Tests CI Pipeline ==="
echo ""

# Step 1: Install dependencies
echo "Step 1: Installing dependencies..."
cd "$PROJECT_DIR"
npm install
echo "✓ Dependencies installed"
echo ""

# Step 2: Generate certificates
echo "Step 2: Generating certificates..."
"$SCRIPT_DIR/generate-certs.sh"
echo "✓ Certificates generated"
echo ""

# Step 3: Start cluster
echo "Step 3: Starting OpenSearch cluster..."
"$SCRIPT_DIR/start-cluster.sh"
echo "✓ Cluster started"
echo ""

# Step 4: Run tests
echo "Step 4: Running tests..."
EXIT_CODE=0
npm test || EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✓ All tests passed"
else
  echo "✗ Tests failed with exit code $EXIT_CODE"
fi
echo ""

# Step 5: Cleanup
echo "Step 5: Cleaning up..."
"$SCRIPT_DIR/cleanup.sh"
echo "✓ Cleanup completed"
echo ""

# Step 6: Stop cluster
echo "Step 6: Stopping cluster..."
cd "$PROJECT_DIR"
docker-compose down -v
echo "✓ Cluster stopped"
echo ""

# Step 7: Generate coverage report (if available)
if [ -d "$PROJECT_DIR/coverage" ]; then
  echo "Step 7: Coverage report available at: $PROJECT_DIR/coverage/index.html"
  echo ""
fi

echo "=== CI Pipeline Completed ==="
exit $EXIT_CODE
