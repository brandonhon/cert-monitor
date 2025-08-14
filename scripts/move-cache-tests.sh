#!/bin/bash
# Script to move cache-related tests from test/basic_test.go to internal/cache/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🔄 Moving Cache Tests from basic_test.go${NC}"
echo "Project Root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

BASIC_TEST_FILE="test/basic_test.go"
CACHE_TEST_DIR="internal/cache"

# Check if basic_test.go exists
if [ ! -f "$BASIC_TEST_FILE" ]; then
    echo -e "${YELLOW}⚠️  No basic_test.go found at $BASIC_TEST_FILE${NC}"
    echo "This is expected if tests have already been moved."
    exit 0
fi

echo -e "${BLUE}📂 Analyzing basic_test.go for cache-related tests...${NC}"

# Check for cache-related test functions
CACHE_TESTS=$(grep -n "func.*Test.*[Cc]ache" "$BASIC_TEST_FILE" || true)
CACHE_BENCHMARKS=$(grep -n "func.*Benchmark.*[Cc]ache" "$BASIC_TEST_FILE" || true)

if [ -z "$CACHE_TESTS" ] && [ -z "$CACHE_BENCHMARKS" ]; then
    echo -e "${GREEN}✅ No cache-related tests found in basic_test.go${NC}"
    echo "Cache tests are either already moved or don't exist."
    exit 0
fi

echo -e "${YELLOW}📋 Found cache-related tests:${NC}"
if [ -n "$CACHE_TESTS" ]; then
    echo "Test functions:"
    echo "$CACHE_TESTS"
fi
if [ -n "$CACHE_BENCHMARKS" ]; then
    echo "Benchmark functions:"
    echo "$CACHE_BENCHMARKS"
fi

echo ""
echo -e "${BLUE}🚀 Creating backup of basic_test.go...${NC}"
cp "$BASIC_TEST_FILE" "$BASIC_TEST_FILE.backup"
echo -e "${GREEN}✅ Backup created: $BASIC_TEST_FILE.backup${NC}"

# Extract cache-related tests and create a temporary file
echo -e "${BLUE}📝 Extracting cache-related tests...${NC}"

TEMP_CACHE_TESTS="/tmp/extracted_cache_tests.go"

cat > "$TEMP_CACHE_TESTS" << 'EOF'
package cache

import (
	"testing"
	// Add other imports as needed
)

// Tests extracted from test/basic_test.go
// These tests have been moved to the cache package for better organization

EOF

# Extract TestCachePerformance if it exists
if grep -q "func TestCachePerformance" "$BASIC_TEST_FILE"; then
    echo -e "${BLUE}📤 Extracting TestCachePerformance...${NC}"
    
    # Extract the function (from func to the end of its closing brace)
    awk '/func TestCachePerformance/,/^}$/' "$BASIC_TEST_FILE" >> "$TEMP_CACHE_TESTS"
    echo "" >> "$TEMP_CACHE_TESTS"
fi

# Extract any other cache-related tests
grep -A 50 "func.*Test.*[Cc]ache" "$BASIC_TEST_FILE" | head -n -1 >> "$TEMP_CACHE_TESTS" || true
grep -A 50 "func.*Benchmark.*[Cc]ache" "$BASIC_TEST_FILE" | head -n -1 >> "$TEMP_CACHE_TESTS" || true

# Create the extracted cache tests file if it has content
if [ -s "$TEMP_CACHE_TESTS" ] && [ $(wc -l < "$TEMP_CACHE_TESTS") -gt 10 ]; then
    EXTRACTED_FILE="$CACHE_TEST_DIR/basic_extracted_test.go"
    
    echo -e "${BLUE}📁 Creating extracted cache tests file: $EXTRACTED_FILE${NC}"
    cp "$TEMP_CACHE_TESTS" "$EXTRACTED_FILE"
    
    echo -e "${GREEN}✅ Cache tests extracted to: $EXTRACTED_FILE${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  Manual Review Required:${NC}"
    echo "1. Review $EXTRACTED_FILE for:"
    echo "   - Correct package imports"
    echo "   - Proper test structure"
    echo "   - Dependencies that need to be mocked"
    echo ""
    echo "2. Update the extracted tests to use the new cache package interfaces"
    echo "3. Remove the original cache tests from $BASIC_TEST_FILE"
    echo "4. Run 'make test-cache' to verify the extracted tests work"
    echo ""
    echo -e "${BLUE}📋 Suggested next steps:${NC}"
    echo "1. Edit $EXTRACTED_FILE to fix any import issues"
    echo "2. Update test functions to use cache.Manager interface"
    echo "3. Remove extracted functions from $BASIC_TEST_FILE"
    echo "4. Test with: make test-cache"
    echo "5. Remove backup file after verification: rm $BASIC_TEST_FILE.backup"
else
    echo -e "${YELLOW}⚠️  No substantial cache tests found to extract${NC}"
    rm -f "$TEMP_CACHE_TESTS"
fi

echo ""
echo -e "${BLUE}📊 Analysis Complete${NC}"
echo "Files to review:"
echo "- Original: $BASIC_TEST_FILE.backup"
echo "- Current: $BASIC_TEST_FILE"
if [ -f "$CACHE_TEST_DIR/basic_extracted_test.go" ]; then
    echo "- Extracted: $CACHE_TEST_DIR/basic_extracted_test.go"
fi

# Clean up temporary file
rm -f "$TEMP_CACHE_TESTS"

echo ""
echo -e "${GREEN}🎯 Cache test migration analysis complete!${NC}"
