#!/bin/bash
# Cache Package Test Runner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🧪 Cache Package Testing${NC}"
cd "$PROJECT_ROOT"

# Run cache tests
echo -e "${BLUE}🔬 Running cache tests...${NC}"
if go test -v ./internal/cache/...; then
    echo -e "${GREEN}✅ Cache tests passed${NC}"
else
    echo -e "${RED}❌ Cache tests failed${NC}"
    exit 1
fi

# Run cache tests with race detection
echo -e "${BLUE}🏃 Running cache tests with race detection...${NC}"
if go test -race -v ./internal/cache/...; then
    echo -e "${GREEN}✅ Cache race tests passed${NC}"
else
    echo -e "${RED}❌ Cache race tests failed${NC}"
    exit 1
fi

# Generate coverage
echo -e "${BLUE}📊 Generating coverage report...${NC}"
if go test -coverprofile=coverage-cache.out ./internal/cache/...; then
    go tool cover -html=coverage-cache.out -o coverage-cache.html
    coverage=$(go tool cover -func=coverage-cache.out | tail -1 | awk '{print $3}')
    echo -e "${GREEN}✅ Coverage report generated: coverage-cache.html${NC}"
    echo -e "${BLUE}📈 Cache package coverage: $coverage${NC}"
else
    echo -e "${RED}❌ Coverage generation failed${NC}"
fi

echo -e "${GREEN}🎉 Cache testing completed successfully!${NC}"
