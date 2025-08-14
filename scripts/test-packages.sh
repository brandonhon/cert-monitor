#!/bin/bash
# Package Tests Script
# Runs tests for individual packages with detailed reporting

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
RACE_ENABLED=${RACE_ENABLED:-false}
COVERAGE_ENABLED=${COVERAGE_ENABLED:-false}
VERBOSE=${VERBOSE:-false}

# Package list
PACKAGES=(
    "internal/config"
    "internal/certificate"
    "internal/metrics"
    "internal/cache"
    "internal/server"
    "pkg/utils"
)

# Test results tracking
declare -A TEST_RESULTS
declare -A TEST_COVERAGE

echo -e "${BLUE}🧪 Running Package Tests${NC}"
echo "Project Root: $PROJECT_ROOT"
echo "Race Detection: $RACE_ENABLED"
echo "Coverage: $COVERAGE_ENABLED"
echo "Verbose: $VERBOSE"
echo ""

cd "$PROJECT_ROOT"

# Function to run tests for a specific package
run_package_tests() {
    local package=$1
    local package_name=$(basename "$package")
    
    echo -e "${BLUE}🔍 Testing package: $package_name${NC}"
    
    # Build test command
    local test_cmd="go test"
    
    if [ "$RACE_ENABLED" = "true" ]; then
        test_cmd="$test_cmd -race"
    fi
    
    if [ "$COVERAGE_ENABLED" = "true" ]; then
        test_cmd="$test_cmd -coverprofile=coverage-$package_name.out"
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        test_cmd="$test_cmd -v"
    fi
    
    test_cmd="$test_cmd ./$package"
    
    # Run the test
    local start_time=$(date +%s)
    
    if eval "$test_cmd"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        TEST_RESULTS["$package_name"]="PASS ($duration"s")"
        echo -e "${GREEN}✅ $package_name tests passed in ${duration}s${NC}"
        
        # Generate coverage report if enabled
        if [ "$COVERAGE_ENABLED" = "true" ] && [ -f "coverage-$package_name.out" ]; then
            local coverage=$(go tool cover -func="coverage-$package_name.out" | tail -1 | awk '{print $3}')
            TEST_COVERAGE["$package_name"]="$coverage"
            echo -e "${BLUE}📊 $package_name coverage: $coverage${NC}"
            
            # Generate HTML coverage report
            go tool cover -html="coverage-$package_name.out" -o "coverage-$package_name.html"
            echo -e "${BLUE}📄 Coverage report: coverage-$package_name.html${NC}"
        fi
        
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        TEST_RESULTS["$package_name"]="FAIL ($duration"s")"
        echo -e "${RED}❌ $package_name tests failed in ${duration}s${NC}"
        return 1
    fi
    
    echo ""
}

# Function to run benchmarks for a package
run_package_benchmarks() {
    local package=$1
    local package_name=$(basename "$package")
    
    echo -e "${BLUE}⚡ Running benchmarks for: $package_name${NC}"
    
    if go test -bench=. -benchmem "./$package" > "bench-$package_name.out" 2>&1; then
        echo -e "${GREEN}✅ $package_name benchmarks completed${NC}"
        
        # Show benchmark summary
        if [ -f "bench-$package_name.out" ]; then
            local bench_count=$(grep "^Benchmark" "bench-$package_name.out" | wc -l)
            echo -e "${BLUE}📊 $package_name: $bench_count benchmarks completed${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  $package_name: No benchmarks or benchmark failed${NC}"
    fi
    
    echo ""
}

# Function to check for test files
check_test_files() {
    local package=$1
    local package_name=$(basename "$package")
    
    local test_files=$(find "$package" -name "*_test.go" 2>/dev/null | wc -l)
    
    if [ "$test_files" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  $package_name: No test files found${NC}"
        TEST_RESULTS["$package_name"]="NO_TESTS"
        return 1
    fi
    
    echo -e "${BLUE}📝 $package_name: Found $test_files test file(s)${NC}"
    return 0
}

# Main test execution
echo -e "${BLUE}🚀 Starting package test execution...${NC}"
echo ""

failed_packages=()
no_test_packages=()

for package in "${PACKAGES[@]}"; do
    package_name=$(basename "$package")
    
    # Check if package directory exists
    if [ ! -d "$package" ]; then
        echo -e "${YELLOW}⚠️  Skipping $package_name: Directory not found${NC}"
        TEST_RESULTS["$package_name"]="SKIP"
        continue
    fi
    
    # Check for test files
    if ! check_test_files "$package"; then
        no_test_packages+=("$package_name")
        continue
    fi
    
    # Run tests
    if ! run_package_tests "$package"; then
        failed_packages+=("$package_name")
    fi
    
    # Run benchmarks if requested
    if [ "${RUN_BENCHMARKS:-false}" = "true" ]; then
        run_package_benchmarks "$package"
    fi
done

# Generate combined coverage report if enabled
if [ "$COVERAGE_ENABLED" = "true" ]; then
    echo -e "${BLUE}📊 Generating combined coverage report...${NC}"
    
    # Combine coverage files
    coverage_files=$(ls coverage-*.out 2>/dev/null || echo "")
    if [ -n "$coverage_files" ]; then
        # Create combined coverage
        echo "mode: set" > coverage-combined.out
        for file in $coverage_files; do
            tail -n +2 "$file" >> coverage-combined.out
        done
        
        # Generate combined HTML report
        go tool cover -html=coverage-combined.out -o coverage-combined.html
        
        # Calculate total coverage
        total_coverage=$(go tool cover -func=coverage-combined.out | tail -1 | awk '{print $3}')
        echo -e "${GREEN}📊 Total combined coverage: $total_coverage${NC}"
        echo -e "${BLUE}📄 Combined coverage report: coverage-combined.html${NC}"
    fi
fi

# Print summary
echo ""
echo -e "${BLUE}📋 Test Summary${NC}"
echo "=============="

for package_name in "${!TEST_RESULTS[@]}"; do
    result="${TEST_RESULTS[$package_name]}"
    
    case "$result" in
        PASS*)
            echo -e "${GREEN}✅ $package_name: $result${NC}"
            if [ "$COVERAGE_ENABLED" = "true" ] && [ -n "${TEST_COVERAGE[$package_name]}" ]; then
                echo -e "   📊 Coverage: ${TEST_COVERAGE[$package_name]}"
            fi
            ;;
        FAIL*)
            echo -e "${RED}❌ $package_name: $result${NC}"
            ;;
        NO_TESTS)
            echo -e "${YELLOW}⚠️  $package_name: No test files${NC}"
            ;;
        SKIP)
            echo -e "${YELLOW}⏭  $package_name: Skipped${NC}"
            ;;
    esac
done

# Final results
echo ""
total_packages=${#PACKAGES[@]}
passed_packages=$((total_packages - ${#failed_packages[@]} - ${#no_test_packages[@]}))

echo -e "${BLUE}📊 Final Results:${NC}"
echo "Total packages: $total_packages"
echo -e "${GREEN}Passed: $passed_packages${NC}"
echo -e "${RED}Failed: ${#failed_packages[@]}${NC}"
echo -e "${YELLOW}No tests: ${#no_test_packages[@]}${NC}"

if [ ${#failed_packages[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Failed packages:${NC}"
    for pkg in "${failed_packages[@]}"; do
        echo "   - $pkg"
    done
fi

if [ ${#no_test_packages[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}⚠️  Packages without tests:${NC}"
    for pkg in "${no_test_packages[@]}"; do
        echo "   - $pkg"
    done
fi

# Exit with error if any tests failed
if [ ${#failed_packages[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}🚨 Some package tests failed!${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}🎉 All package tests passed!${NC}"
fi
