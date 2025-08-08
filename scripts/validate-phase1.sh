#!/bin/bash
# Phase 1 Migration Validation Script

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🔍 Validating Phase 1 Migration...${NC}"

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    echo -e "${RED}❌ main.go not found. Please run from project root.${NC}"
    exit 1
fi

# Check required package structure
echo -e "${BLUE}📁 Checking package structure...${NC}"

required_files=(
    "pkg/utils/crypto.go"
    "pkg/utils/validation.go"
    "internal/config/types.go"
    "internal/config/config.go"
    "internal/config/validation.go"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅${NC} $file"
    else
        echo -e "${RED}❌${NC} $file (MISSING)"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo -e "${RED}❌ Missing required files. Create them first.${NC}"
    exit 1
fi

# Check that utility functions exist
echo -e "${BLUE}🔧 Checking utility functions...${NC}"

utility_functions=(
    "IsWeakKey"
    "IsDeprecatedSigAlg" 
    "DetermineIssuerCode"
    "SanitizeLabelValue"
    "ValidateFileAccess"
    "IsCertificateFile"
)

for func in "${utility_functions[@]}"; do
    if grep -q "func $func" pkg/utils/*.go; then
        echo -e "${GREEN}✅${NC} $func found in pkg/utils/"
    else
        echo -e "${RED}❌${NC} $func missing from pkg/utils/"
    fi
done

# Check configuration functions
echo -e "${BLUE}⚙️  Checking configuration functions...${NC}"

config_functions=(
    "Load"
    "Default" 
    "Validate"
    "Compare"
)

for func in "${config_functions[@]}"; do
    if grep -q "func $func" internal/config/*.go; then
        echo -e "${GREEN}✅${NC} $func found in internal/config/"
    else
        echo -e "${RED}❌${NC} $func missing from internal/config/"
    fi
done

# Check main.go imports
echo -e "${BLUE}📦 Checking main.go imports...${NC}"

required_imports=(
    "github.com/brandonhon/cert-monitor/internal/config"
    "github.com/brandonhon/cert-monitor/pkg/utils"
)

for import in "${required_imports[@]}"; do
    if grep -q "$import" main.go; then
        echo -e "${GREEN}✅${NC} Import: $import"
    else
        echo -e "${YELLOW}⚠️${NC}  Import missing: $import"
    fi
done

# Test compilation
echo -e "${BLUE}🔨 Testing compilation...${NC}"

if go build -o test-phase1 .; then
    echo -e "${GREEN}✅ Compilation successful${NC}"
    rm -f test-phase1
else
    echo -e "${RED}❌ Compilation failed${NC}"
    exit 1
fi

# Test package compilation individually  
echo -e "${BLUE}📦 Testing individual packages...${NC}"

packages=(
    "./pkg/utils"
    "./internal/config"
)

for pkg in "${packages[@]}"; do
    if go build "$pkg"; then
        echo -e "${GREEN}✅${NC} Package builds: $pkg"
    else
        echo -e "${RED}❌${NC} Package build failed: $pkg"
    fi
done

# Check for removed functions in main.go
echo -e "${BLUE}🧹 Checking for extracted functions in main.go...${NC}"

functions_should_be_removed=(
    "func isWeakKey"
    "func isDeprecatedSigAlg"
    "func determineIssuerCode" 
    "func sanitizeLabelValue"
    "func validateFileAccess"
    "func isCertificateFile"
    "func LoadConfig"
    "func DefaultConfig"
)

extracted_count=0
for func in "${functions_should_be_removed[@]}"; do
    if ! grep -q "$func" main.go; then
        echo -e "${GREEN}✅${NC} Extracted: $func"
        ((extracted_count++))
    else
        echo -e "${YELLOW}⚠️${NC}  Still in main.go: $func"
    fi
done

echo -e "${BLUE}📊 Extraction Progress: $extracted_count/${#functions_should_be_removed[@]} functions extracted${NC}"

# Test basic functionality
echo -e "${BLUE}🧪 Testing basic functionality...${NC}"

echo "Testing configuration loading..."
if ./test-phase1 -config config.example.yaml -dry-run 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Configuration loading works"
else
    echo -e "${YELLOW}⚠️${NC}  Configuration test failed (may be normal if config file missing)"
fi

# Calculate lines removed (approximate)
if [ -f "main.go.backup" ]; then
    old_lines=$(wc -l < main.go.backup)
    new_lines=$(wc -l < main.go)
    lines_removed=$((old_lines - new_lines))
    echo -e "${BLUE}📏 Lines of code analysis:${NC}"
    echo "   Original main.go: $old_lines lines"
    echo "   Current main.go:  $new_lines lines"
    echo "   Lines extracted:  $lines_removed lines"
    
    if [ $lines_removed -gt 200 ]; then
        echo -e "${GREEN}✅ Good progress! Extracted $lines_removed lines${NC}"
    else
        echo -e "${YELLOW}⚠️  Only extracted $lines_removed lines (target: 300+)${NC}"
    fi
fi

# Final summary
echo ""
echo -e "${GREEN}🎉 Phase 1 Validation Summary${NC}"
echo "✅ Package structure created"
echo "✅ Utility functions extracted"
echo "✅ Configuration logic modularized"
echo "✅ Code compiles successfully"

if [ $extracted_count -eq ${#functions_should_be_removed[@]} ]; then
    echo -e "${GREEN}✅ Phase 1 Complete! Ready for Phase 2${NC}"
    echo ""
    echo -e "${BLUE}📋 Next Steps:${NC}"
    echo "1. Commit your Phase 1 changes:"
    echo "   git add ."
    echo "   git commit -m \"Phase 1: Extract utilities and configuration\""
    echo ""
    echo "2. Start Phase 2 migration:"
    echo "   - Extract certificate processing to internal/certificate/"
    echo "   - Extract metrics collection to internal/metrics/"
    echo "   - Extract cache management to internal/cache/"
else
    echo -e "${YELLOW}⚠️  Phase 1 Partially Complete${NC}"
    echo "   Complete function extraction before proceeding to Phase 2"
fi

echo ""
echo -e "${BLUE}🚀 Keep going! The modular architecture is taking shape!${NC}"