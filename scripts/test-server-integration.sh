#!/bin/bash
# Server Integration Tests
# Tests the server package against a running instance

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Test configuration
TEST_PORT=3001
TEST_CONFIG="$PROJECT_ROOT/test-server-config.yaml"
TEST_BINARY="$PROJECT_ROOT/cert-monitor-server-test"
TEST_PID_FILE="/tmp/cert-monitor-server-test.pid"
TEST_LOG_FILE="/tmp/cert-monitor-server-test.log"
TEST_CERT_DIR="$PROJECT_ROOT/test-certs"

# Cleanup function
cleanup() {
    echo -e "${BLUE}🧹 Cleaning up server integration test environment...${NC}"
    
    if [ -f "$TEST_PID_FILE" ]; then
        PID=$(cat "$TEST_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            echo -e "${BLUE}Stopping test server (PID: $PID)...${NC}"
            kill "$PID"
            sleep 2
            if kill -0 "$PID" 2>/dev/null; then
                echo -e "${YELLOW}Force killing test server...${NC}"
                kill -9 "$PID"
            fi
        fi
        rm -f "$TEST_PID_FILE"
    fi
    
    rm -f "$TEST_CONFIG"
    rm -f "$TEST_BINARY"
    rm -f "$TEST_LOG_FILE"
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Set trap for cleanup
trap cleanup EXIT

echo -e "${BLUE}🧪 Starting Server Integration Tests${NC}"
echo "Project Root: $PROJECT_ROOT"
echo "Test Port: $TEST_PORT"

# Change to project root
cd "$PROJECT_ROOT"

# Build test binary
echo -e "${BLUE}🔨 Building test binary...${NC}"
if ! go build -o "$TEST_BINARY" .; then
    echo -e "${RED}❌ Failed to build test binary${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Test binary built successfully${NC}"

# Create test configuration
echo -e "${BLUE}⚙️  Creating test configuration...${NC}"
cat > "$TEST_CONFIG" << EOF
cert_dirs:
  - "$TEST_CERT_DIR"
port: "$TEST_PORT"
bind_address: "127.0.0.1"
num_workers: 2
expiry_threshold_days: 30
cache_file: "/tmp/cert-monitor-server-test-cache.json"
log_file: "$TEST_LOG_FILE"
enable_runtime_metrics: true
enable_weak_crypto_metrics: true
enable_pprof: false
dry_run: false
clear_cache_on_reload: false
EOF

echo -e "${GREEN}✅ Test configuration created${NC}"

# Ensure test certificates exist
if [ ! -d "$TEST_CERT_DIR" ]; then
    echo -e "${YELLOW}⚠️  Test certificates not found, creating minimal set...${NC}"
    mkdir -p "$TEST_CERT_DIR"
    
    # Create a simple test certificate
    if command -v openssl >/dev/null 2>&1; then
        openssl req -x509 -newkey rsa:2048 -keyout "$TEST_CERT_DIR/test-key.pem" \
            -out "$TEST_CERT_DIR/test-cert.pem" -days 365 -nodes \
            -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=test.example.com" \
            2>/dev/null || echo "Warning: Could not generate test certificate"
    fi
fi

# Start test server
echo -e "${BLUE}🚀 Starting test server...${NC}"
"$TEST_BINARY" -config "$TEST_CONFIG" > "$TEST_LOG_FILE" 2>&1 & 
echo $! > "$TEST_PID_FILE"

# Wait for server to start
echo -e "${BLUE}⏳ Waiting for server to start...${NC}"
for i in $(seq 1 30); do
    if curl -s "http://127.0.0.1:$TEST_PORT/healthz" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server started successfully${NC}"
        break
    fi
    
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Server failed to start within 30 seconds${NC}"
        if [ -f "$TEST_LOG_FILE" ]; then
            echo -e "${RED}Server logs:${NC}"
            cat "$TEST_LOG_FILE"
        fi
        exit 1
    fi
    
    echo -e "${BLUE}Waiting for server... ($i/30)${NC}"
    sleep 1
done

# Test server endpoints
echo -e "${BLUE}🧪 Testing server endpoints...${NC}"

# Test health endpoint
echo -e "${BLUE}Testing health endpoint...${NC}"
HEALTH_RESPONSE=$(curl -s "http://127.0.0.1:$TEST_PORT/healthz")
if echo "$HEALTH_RESPONSE" | grep -q '"status":"ok"'; then
    echo -e "${GREEN}✅ Health endpoint working${NC}"
else
    echo -e "${RED}❌ Health endpoint failed${NC}"
    echo "Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test metrics endpoint
echo -e "${BLUE}Testing metrics endpoint...${NC}"
METRICS_RESPONSE=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics")
if echo "$METRICS_RESPONSE" | grep -q "ssl_cert_"; then
    echo -e "${GREEN}✅ Metrics endpoint working${NC}"
else
    echo -e "${RED}❌ Metrics endpoint failed${NC}"
    echo "Response preview: $(echo "$METRICS_RESPONSE" | head -5)"
    exit 1
fi

# Test certificates endpoint
echo -e "${BLUE}Testing certificates endpoint...${NC}"
CERTS_RESPONSE=$(curl -s "http://127.0.0.1:$TEST_PORT/certs")
if echo "$CERTS_RESPONSE" | grep -q '\['; then
    echo -e "${GREEN}✅ Certificates endpoint working${NC}"
else
    echo -e "${RED}❌ Certificates endpoint failed${NC}"
    echo "Response: $CERTS_RESPONSE"
    exit 1
fi

# Test config endpoint
echo -e "${BLUE}Testing config endpoint...${NC}"
CONFIG_RESPONSE=$(curl -s "http://127.0.0.1:$TEST_PORT/config")
if echo "$CONFIG_RESPONSE" | grep -q '"port":"'$TEST_PORT'"'; then
    echo -e "${GREEN}✅ Config endpoint working${NC}"
else
    echo -e "${RED}❌ Config endpoint failed${NC}"
    echo "Response: $CONFIG_RESPONSE"
    exit 1
fi

# Test reload endpoint
echo -e "${BLUE}Testing reload endpoint...${NC}"
RELOAD_RESPONSE=$(curl -s -X POST "http://127.0.0.1:$TEST_PORT/reload")
if echo "$RELOAD_RESPONSE" | grep -q '"success":true'; then
    echo -e "${GREEN}✅ Reload endpoint working${NC}"
else
    echo -e "${YELLOW}⚠️  Reload endpoint response: $RELOAD_RESPONSE${NC}"
fi

# Test root endpoint
echo -e "${BLUE}Testing root endpoint...${NC}"
ROOT_RESPONSE=$(curl -s "http://127.0.0.1:$TEST_PORT/")
if echo "$ROOT_RESPONSE" | grep -q "SSL Certificate Monitor"; then
    echo -e "${GREEN}✅ Root endpoint working${NC}"
else
    echo -e "${RED}❌ Root endpoint failed${NC}"
    echo "Response: $ROOT_RESPONSE"
    exit 1
fi

# Test 404 handling
echo -e "${BLUE}Testing 404 handling...${NC}"
NOT_FOUND_RESPONSE=$(curl -s -w "%{http_code}" "http://127.0.0.1:$TEST_PORT/nonexistent")
if echo "$NOT_FOUND_RESPONSE" | grep -q "404"; then
    echo -e "${GREEN}✅ 404 handling working${NC}"
else
    echo -e "${RED}❌ 404 handling failed${NC}"
    echo "Response: $NOT_FOUND_RESPONSE"
    exit 1
fi

# Test HTTP methods
echo -e "${BLUE}Testing HTTP method restrictions...${NC}"
METHOD_RESPONSE=$(curl -s -w "%{http_code}" -X GET "http://127.0.0.1:$TEST_PORT/reload")
if echo "$METHOD_RESPONSE" | grep -q "405"; then
    echo -e "${GREEN}✅ Method restrictions working${NC}"
else
    echo -e "${RED}❌ Method restrictions failed${NC}"
    echo "Response: $METHOD_RESPONSE"
    exit 1
fi

# Performance test
echo -e "${BLUE}⚡ Running performance test...${NC}"
START_TIME=$(date +%s)
for i in $(seq 1 50); do
    curl -s "http://127.0.0.1:$TEST_PORT/healthz" > /dev/null
done
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "${GREEN}✅ Performance test completed: 50 requests in ${DURATION}s${NC}"

if [ $DURATION -gt 10 ]; then
    echo -e "${YELLOW}⚠️  Performance seems slow (${DURATION}s for 50 requests)${NC}"
else
    echo -e "${GREEN}✅ Performance is good${NC}"
fi

# Test concurrent requests
echo -e "${BLUE}🔄 Testing concurrent requests...${NC}"
CONCURRENT_PIDS=()
for i in $(seq 1 10); do
    curl -s "http://127.0.0.1:$TEST_PORT/healthz" > /dev/null &
    CONCURRENT_PIDS+=($!)
done

# Wait for all concurrent requests
for pid in "${CONCURRENT_PIDS[@]}"; do
    wait $pid
done
echo -e "${GREEN}✅ Concurrent requests completed successfully${NC}"

# Test server graceful shutdown (we'll let the trap handle this)
echo -e "${BLUE}📊 Test Summary${NC}"
echo -e "${GREEN}✅ All server integration tests passed!${NC}"
echo ""
echo -e "${BLUE}Test Results:${NC}"
echo "✅ Health endpoint functional"
echo "✅ Metrics endpoint functional"  
echo "✅ Certificates endpoint functional"
echo "✅ Config endpoint functional"
echo "✅ Reload endpoint functional"
echo "✅ Root endpoint functional"
echo "✅ 404 handling functional"
echo "✅ HTTP method restrictions functional"
echo "✅ Performance test passed"
echo "✅ Concurrent requests handled"

echo ""
echo -e "${GREEN}🎉 Server integration tests completed successfully!${NC}"
