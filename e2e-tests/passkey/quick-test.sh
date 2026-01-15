#!/bin/bash
# Quick test script for rapid iteration
set -e

echo "Killing OpenSearch..."
ps aux | grep opensearch | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
sleep 2

echo "Reinstalling plugin..."
rm -rf ../../opensearch-runtime/plugins/opensearch-security
mkdir -p ../../opensearch-runtime/plugins/opensearch-security
unzip -q ../../build/distributions/opensearch-security-3.5.0.0-SNAPSHOT.zip -d ../../opensearch-runtime/plugins/opensearch-security

echo "Starting OpenSearch..."
../../opensearch-runtime/bin/opensearch > /dev/null 2>&1 &
OSPID=$!

echo "Waiting for OpenSearch to start..."
sleep 45

echo "Running tests..."
npm test 2>&1 | grep -E "Test Suites:|Tests:"

echo "Done!"
