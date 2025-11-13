#!/bin/bash

# TLS Security Test Suite
# Tests all security validations for HTTPS implementation

# Don't use set -e because tests are expected to fail
set +e

# Change to project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT" || exit 1

echo "🔒 TLS Security Test Suite for secure_auth_rs"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_pattern="$3"
    
    echo -n "Testing: $test_name... "
    
    # Filter out cargo warnings and only check actual output
    local output=$(eval "$test_cmd" 2>&1 | grep -v "warning:" | grep -v -- "-->" | grep -v "^[0-9][0-9]" | grep -v "^ *|")
    
    if echo "$output" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  Expected: $expected_pattern"
        echo "  Got: $(echo "$output" | head -3)"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test 1: Valid configuration should start server
echo "1. Valid TLS Configuration"
run_test "Server starts with valid certs" \
    "timeout 3 cargo run 2>&1" \
    "HTTPS server starting"

# Test 2: Invalid certificate file
echo ""
echo "2. Invalid Certificate Tests"
run_test "Rejects invalid certificate data" \
    "echo 'INVALID' > /tmp/bad_cert.pem && TLS_CERT_PATH=/tmp/bad_cert.pem timeout 2 cargo run 2>&1" \
    "No certificates found in PEM file"

run_test "Rejects missing certificate file" \
    "TLS_CERT_PATH=/nonexistent.pem timeout 2 cargo run 2>&1" \
    "Certificate file not found"

# Test 3: Invalid private key file
echo ""
echo "3. Invalid Private Key Tests"
run_test "Rejects invalid private key data" \
    "mkdir -p /tmp/test_tls && echo 'INVALID' > /tmp/test_tls/bad_key.pem && cp certs/.key_password /tmp/test_tls/ && TLS_KEY_PATH=/tmp/test_tls/bad_key.pem timeout 2 cargo run 2>&1" \
    "No private keys found in PEM file"

run_test "Rejects missing private key file" \
    "TLS_KEY_PATH=/nonexistent.pem timeout 2 cargo run 2>&1" \
    "Private key file not found"

# Test 4: Password validation
echo ""
echo "4. Password Validation Tests"
run_test "Rejects incorrect password" \
    "TLS_KEY_PASSWORD='wrong_password' timeout 2 cargo run 2>&1" \
    "TLS password validation failed"

run_test "Accepts correct password" \
    "timeout 3 cargo run 2>&1" \
    "TLS password validation successful"

# Test 5: HTTPS connectivity
echo ""
echo "5. HTTPS Connectivity Tests"
echo -n "Testing: HTTPS endpoint accessible... "
cargo run > /tmp/server_test.log 2>&1 & SERVER_PID=$!
sleep 3

if curl -k -s https://127.0.0.1:3443/health | grep -q "OK"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    ((TESTS_FAILED++))
fi

kill $SERVER_PID 2>/dev/null || true
sleep 1

# Test 6: Certificate validity
echo ""
echo "6. Certificate Validity Tests"
echo -n "Testing: Certificate is properly signed... "
cargo run > /tmp/server_test.log 2>&1 & SERVER_PID=$!
sleep 3

if echo | openssl s_client -connect 127.0.0.1:3443 2>/dev/null | openssl x509 -noout -text | grep -q "CN=localhost"; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    ((TESTS_FAILED++))
fi

kill $SERVER_PID 2>/dev/null || true

# Summary
echo ""
echo "=============================================="
echo "Test Summary:"
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
else
    echo -e "  Failed: 0"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All security tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi
