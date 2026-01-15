#!/bin/bash

# Passkey Authentication - Production Readiness Verification Script
# This script verifies that all tests pass and the implementation is ready for production

set -e

echo "=========================================="
echo "Passkey Authentication"
echo "Production Readiness Verification"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Function to run a check
run_check() {
    local name="$1"
    local command="$2"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -n "[$TOTAL_CHECKS] Checking $name... "
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

echo "Running verification checks..."
echo ""

# Check 1: E2E Tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "E2E Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

run_check "Registration tests (6 tests)" "npm test -- tests/registration.test.js --silent"
run_check "Authentication tests (7 tests)" "npm test -- tests/authentication.test.js --silent"
run_check "Credential management tests (8 tests)" "npm test -- tests/credential-mgmt.test.js --silent"
run_check "Security scenario tests (8 tests)" "npm test -- tests/security.test.js --silent"
run_check "Multi-backend tests (8 tests)" "npm test -- tests/multi-backend.test.js --silent"

echo ""

# Check 2: Property-Based Tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Property-Based Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd ../../
run_check "All property tests (30 tests)" "./gradlew test --tests '*Property*' --quiet"
cd e2e-tests/passkey

echo ""

# Check 3: Build
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Build Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd ../../
run_check "Plugin builds successfully" "./gradlew assemble -x spotbugsMain --quiet"
run_check "Plugin artifact exists" "test -f build/distributions/opensearch-security-*.zip"
cd e2e-tests/passkey

echo ""

# Check 4: Documentation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Documentation Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

run_check "Configuration guide exists" "test -f ../../PASSKEY_AUTHENTICATION.md"
run_check "Quick reference exists" "test -f ../../PASSKEY_QUICK_REFERENCE.md"
run_check "Security review exists" "test -f ../../../.kiro/specs/passkey-authentication/SECURITY_REVIEW.md"
run_check "Performance analysis exists" "test -f ../../../.kiro/specs/passkey-authentication/PERFORMANCE_ANALYSIS.md"
run_check "Deployment guide exists" "test -f ../../../.kiro/specs/passkey-authentication/DEPLOYMENT_GUIDE.md"

echo ""

# Check 5: Configuration
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Configuration Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

run_check "Example configuration exists" "test -f ../../config/passkey_config_example.yml"
run_check "Test configuration exists" "test -f config/config.yml"

echo ""

# Summary
echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo ""
echo "Total Checks: $TOTAL_CHECKS"
echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
echo ""

if [ $FAILED_CHECKS -eq 0 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ ALL CHECKS PASSED${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "🎉 Passkey Authentication is PRODUCTION READY!"
    echo ""
    echo "Next Steps:"
    echo "  1. Review EXECUTIVE_SUMMARY.md"
    echo "  2. Review key decisions (API change, admin privileges)"
    echo "  3. Deploy to staging"
    echo "  4. Deploy to production"
    echo ""
    echo "Documentation:"
    echo "  - Executive Summary: .kiro/specs/passkey-authentication/EXECUTIVE_SUMMARY.md"
    echo "  - Work Log: .kiro/specs/passkey-authentication/WORK_SESSION_SUMMARY.md"
    echo "  - Deployment Guide: .kiro/specs/passkey-authentication/DEPLOYMENT_GUIDE.md"
    echo ""
    exit 0
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}❌ SOME CHECKS FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Please review the failed checks above."
    echo ""
    exit 1
fi
