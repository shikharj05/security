#!/bin/bash

# Start OpenSearch test cluster for passkey e2e tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Starting OpenSearch test cluster for passkey e2e tests..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker is not running. Please start Docker and try again."
  exit 1
fi

# Check if certificates exist
if [ ! -f "$PROJECT_DIR/certs/root-ca.pem" ]; then
  echo "Certificates not found. Generating certificates..."
  "$SCRIPT_DIR/generate-certs.sh"
fi

# Stop any existing cluster
echo "Stopping any existing cluster..."
cd "$PROJECT_DIR"
docker-compose down -v 2>/dev/null || true

# Start cluster
echo "Starting cluster..."
docker-compose up -d

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
MAX_WAIT=120
WAIT_TIME=0

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
  if curl -k -s -u admin:Admin123! https://localhost:9200/_cluster/health > /dev/null 2>&1; then
    echo "Cluster is ready!"
    
    # Show cluster health
    echo ""
    echo "Cluster health:"
    curl -k -s -u admin:Admin123! https://localhost:9200/_cluster/health | jq '.' || \
      curl -k -s -u admin:Admin123! https://localhost:9200/_cluster/health
    
    echo ""
    echo "Cluster started successfully!"
    echo "OpenSearch is available at: https://localhost:9200"
    echo "Username: admin"
    echo "Password: Admin123!"
    echo ""
    echo "To view logs: docker-compose logs -f"
    echo "To stop cluster: docker-compose down"
    echo ""
    exit 0
  fi
  
  echo "Waiting... ($WAIT_TIME/$MAX_WAIT seconds)"
  sleep 5
  WAIT_TIME=$((WAIT_TIME + 5))
done

echo "Error: Cluster did not become ready within $MAX_WAIT seconds"
echo "Check logs with: docker-compose logs"
exit 1
