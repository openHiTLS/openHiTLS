#!/bin/bash
#
# Test script for openHiTLS s_client and s_server tools
# This script creates test certificates and verifies basic functionality
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
HITLS_BIN="./hitls"
TEST_DIR="test_tls_tools"
CA_KEY="$TEST_DIR/ca.key"
CA_CERT="$TEST_DIR/ca.pem"
SERVER_KEY="$TEST_DIR/server.key"
SERVER_CERT="$TEST_DIR/server.pem"
CLIENT_KEY="$TEST_DIR/client.key"
CLIENT_CERT="$TEST_DIR/client.pem"
SERVER_PORT=14433
DTLS_PORT=14434

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_binary() {
    if [ ! -f "$HITLS_BIN" ]; then
        log_error "openHiTLS binary not found: $HITLS_BIN"
        log_info "Please build openHiTLS with apps enabled and run this script from the build directory"
        exit 1
    fi
}

create_test_dir() {
    log_info "Creating test directory: $TEST_DIR"
    mkdir -p "$TEST_DIR"
}

generate_certificates() {
    log_info "Generating test certificates..."
    
    # Generate CA private key
    if ! $HITLS_BIN genpkey -algorithm RSA -out "$CA_KEY" -pkcs8 2>/dev/null; then
        log_error "Failed to generate CA private key"
        return 1
    fi
    
    # Generate CA certificate
    if ! $HITLS_BIN req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days 30 \
        -subj "/C=CN/ST=Test/L=Test/O=openHiTLS/OU=Test/CN=Test CA" 2>/dev/null; then
        log_error "Failed to generate CA certificate"
        return 1
    fi
    
    # Generate server private key
    if ! $HITLS_BIN genpkey -algorithm RSA -out "$SERVER_KEY" -pkcs8 2>/dev/null; then
        log_error "Failed to generate server private key"
        return 1
    fi
    
    # Generate server certificate request
    if ! $HITLS_BIN req -new -key "$SERVER_KEY" -out "$TEST_DIR/server.csr" \
        -subj "/C=CN/ST=Test/L=Test/O=openHiTLS/OU=Test/CN=localhost" 2>/dev/null; then
        log_error "Failed to generate server certificate request"
        return 1
    fi
    
    # Sign server certificate
    if ! $HITLS_BIN x509 -req -in "$TEST_DIR/server.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -out "$SERVER_CERT" -days 30 -CAcreateserial 2>/dev/null; then
        log_error "Failed to sign server certificate"
        return 1
    fi
    
    # Generate client private key
    if ! $HITLS_BIN genpkey -algorithm RSA -out "$CLIENT_KEY" -pkcs8 2>/dev/null; then
        log_error "Failed to generate client private key"
        return 1
    fi
    
    # Generate client certificate request
    if ! $HITLS_BIN req -new -key "$CLIENT_KEY" -out "$TEST_DIR/client.csr" \
        -subj "/C=CN/ST=Test/L=Test/O=openHiTLS/OU=Test/CN=testclient" 2>/dev/null; then
        log_error "Failed to generate client certificate request"
        return 1
    fi
    
    # Sign client certificate
    if ! $HITLS_BIN x509 -req -in "$TEST_DIR/client.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -out "$CLIENT_CERT" -days 30 -CAcreateserial 2>/dev/null; then
        log_error "Failed to sign client certificate"
        return 1
    fi
    
    log_info "Test certificates generated successfully"
}

test_help_commands() {
    log_info "Testing help commands..."
    
    if $HITLS_BIN s_client -help >/dev/null 2>&1; then
        log_info "s_client help: PASS"
    else
        log_warn "s_client help: FAIL"
    fi
    
    if $HITLS_BIN s_server -help >/dev/null 2>&1; then
        log_info "s_server help: PASS"
    else
        log_warn "s_server help: FAIL"
    fi
}

test_tls_connection() {
    log_info "Testing basic TLS connection..."
    
    # Start TLS server in background
    $HITLS_BIN s_server -cert "$SERVER_CERT" -key "$SERVER_KEY" -port $SERVER_PORT \
        -accept_once -quiet 2>/dev/null &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Test client connection
    if echo "Hello Server" | $HITLS_BIN s_client -host localhost -port $SERVER_PORT \
        -CAfile "$CA_CERT" -quiet -prexit >/dev/null 2>&1; then
        log_info "Basic TLS connection: PASS"
        TEST_RESULT="PASS"
    else
        log_warn "Basic TLS connection: FAIL"
        TEST_RESULT="FAIL"
    fi
    
    # Clean up server process
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    return $([ "$TEST_RESULT" = "PASS" ] && echo 0 || echo 1)
}

test_mutual_auth() {
    log_info "Testing mutual authentication..."
    
    # Start server with client verification
    $HITLS_BIN s_server -cert "$SERVER_CERT" -key "$SERVER_KEY" -port $SERVER_PORT \
        -CAfile "$CA_CERT" -verify 1 -accept_once -quiet 2>/dev/null &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Test client with certificate
    if echo "Hello Server" | $HITLS_BIN s_client -host localhost -port $SERVER_PORT \
        -CAfile "$CA_CERT" -cert "$CLIENT_CERT" -key "$CLIENT_KEY" \
        -quiet -prexit >/dev/null 2>&1; then
        log_info "Mutual authentication: PASS"
        TEST_RESULT="PASS"
    else
        log_warn "Mutual authentication: FAIL"
        TEST_RESULT="FAIL"
    fi
    
    # Clean up server process
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    return $([ "$TEST_RESULT" = "PASS" ] && echo 0 || echo 1)
}

test_tls13() {
    log_info "Testing TLS 1.3 connection..."
    
    # Start TLS 1.3 server
    $HITLS_BIN s_server -tls1_3 -cert "$SERVER_CERT" -key "$SERVER_KEY" \
        -port $SERVER_PORT -accept_once -quiet 2>/dev/null &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Test TLS 1.3 client
    if echo "Hello TLS 1.3" | $HITLS_BIN s_client -tls1_3 -host localhost \
        -port $SERVER_PORT -CAfile "$CA_CERT" -quiet -prexit >/dev/null 2>&1; then
        log_info "TLS 1.3 connection: PASS"
        TEST_RESULT="PASS"
    else
        log_warn "TLS 1.3 connection: FAIL"
        TEST_RESULT="FAIL"
    fi
    
    # Clean up server process
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    return $([ "$TEST_RESULT" = "PASS" ] && echo 0 || echo 1)
}

test_dtls() {
    log_info "Testing DTLS connection..."
    
    # Start DTLS server
    timeout 10s $HITLS_BIN s_server -dtls1_2 -cert "$SERVER_CERT" -key "$SERVER_KEY" \
        -port $DTLS_PORT -accept_once -quiet 2>/dev/null &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Test DTLS client
    if echo "Hello DTLS" | timeout 5s $HITLS_BIN s_client -dtls1_2 -host localhost \
        -port $DTLS_PORT -CAfile "$CA_CERT" -quiet -prexit >/dev/null 2>&1; then
        log_info "DTLS connection: PASS"
        TEST_RESULT="PASS"
    else
        log_warn "DTLS connection: FAIL (may not be fully implemented)"
        TEST_RESULT="FAIL"
    fi
    
    # Clean up server process
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    return $([ "$TEST_RESULT" = "PASS" ] && echo 0 || echo 1)
}

cleanup() {
    log_info "Cleaning up test files..."
    rm -rf "$TEST_DIR"
    
    # Kill any remaining server processes
    pkill -f "hitls s_server" 2>/dev/null || true
}

run_tests() {
    local passed=0
    local total=0
    
    log_info "Starting openHiTLS TLS tools test suite..."
    echo
    
    # Test help commands
    test_help_commands
    
    # Generate certificates
    if ! generate_certificates; then
        log_error "Certificate generation failed, skipping connection tests"
        return 1
    fi
    
    # Run connection tests
    total=$((total + 1))
    if test_tls_connection; then
        passed=$((passed + 1))
    fi
    
    total=$((total + 1))
    if test_mutual_auth; then
        passed=$((passed + 1))
    fi
    
    total=$((total + 1))
    if test_tls13; then
        passed=$((passed + 1))
    fi
    
    total=$((total + 1))
    if test_dtls; then
        passed=$((passed + 1))
    fi
    
    echo
    log_info "Test Results: $passed/$total tests passed"
    
    if [ $passed -eq $total ]; then
        log_info "All tests passed! ✓"
        return 0
    else
        log_warn "Some tests failed. Check the implementation."
        return 1
    fi
}

# Main execution
main() {
    check_binary
    create_test_dir
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    if run_tests; then
        exit 0
    else
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    -h|--help)
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  -h, --help    Show this help message"
        echo "  -c, --clean   Clean up test files and exit"
        echo ""
        echo "This script tests the openHiTLS s_client and s_server tools."
        echo "Make sure to run it from the openHiTLS build directory."
        exit 0
        ;;
    -c|--clean)
        cleanup
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac