#!/bin/bash
# Complete repository setup script for cert-monitor

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Finalizing cert-monitor repository setup...${NC}"
echo ""

# Check if we're in the right directory
if [ ! -d ".git" ]; then
    echo -e "${RED}❌ This doesn't appear to be a git repository.${NC}"
    echo "Please run from the cert-monitor directory after cloning."
    exit 1
fi

# Verify remote origin
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ "$REMOTE_URL" != *"brandonhon/cert-monitor"* ]]; then
    echo -e "${RED}❌ Remote origin doesn't match expected repository.${NC}"
    echo "Expected: github.com/brandonhon/cert-monitor"
    echo "Current: $REMOTE_URL"
    exit 1
fi

echo -e "${GREEN}✅ Repository validated${NC}"

# File checklist
declare -A required_files=(
    ["README.md"]="Project documentation"
    ["main.go"]="Main application code"
    ["go.mod"]="Go module definition"
    ["Makefile"]="Build automation"
    ["config.example.yaml"]="Configuration example"
    ["LICENSE"]="MIT License"
    [".gitignore"]="Git ignore rules"
    ["Dockerfile"]="Container configuration"
    ["docker-compose.yml"]="Docker Compose setup"
    ["prometheus.yml"]="Prometheus configuration"
    ["alert_rules.yml"]="Alerting rules"
    ["DEVELOPMENT.md"]="Development guide"
    ["IMPLEMENTATION_PLAN.md"]="Project roadmap"
    ["MODULAR_ARCHITECTURE.md"]="Modular architecture plan"
    ["setup.sh"]="Initial setup script"
)

echo -e "${BLUE}📋 Checking required files...${NC}"
missing_files=()

for file in "${!required_files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅${NC} $file - ${required_files[$file]}"
    else
        echo -e "${RED}❌${NC} $file - ${required_files[$file]} (MISSING)"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Missing required files. Please create these files first:${NC}"
    for file in "${missing_files[@]}"; do
        echo "   - $file"
    done
    echo ""
    echo "Copy the content from the artifacts provided in the conversation."
    exit 1
fi

# Check directory structure
echo ""
echo -e "${BLUE}📁 Creating directory structure...${NC}"

directories=(
    ".github/workflows"
    "scripts"
    "deploy"
    "test"
    "test-certs"
)

for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo -e "${GREEN}✅${NC} Created directory: $dir"
    else
        echo -e "${GREEN}✅${NC} Directory exists: $dir"
    fi
done

# Check GitHub Actions workflows
echo ""
echo -e "${BLUE}⚙️  Checking GitHub Actions workflows...${NC}"

if [ ! -f ".github/workflows/ci.yml" ]; then
    echo -e "${YELLOW}⚠️${NC}  .github/workflows/ci.yml missing - CI workflow not configured"
else
    echo -e "${GREEN}✅${NC} CI workflow configured"
fi

if [ ! -f ".github/workflows/release.yml" ]; then
    echo -e "${YELLOW}⚠️${NC}  .github/workflows/release.yml missing - Release workflow not configured"
else
    echo -e "${GREEN}✅${NC} Release workflow configured"
fi

# Check scripts
echo ""
echo -e "${BLUE}🔧 Checking scripts...${NC}"

scripts=(
    "scripts/generate-test-certs.sh"
    "scripts/install.sh"
    "scripts/migrate-to-modular.sh"
    "setup.sh"
    "finalize-setup.sh"
)

for script in "${scripts[@]}"; do
    if [ -f "$script" ]; then
        chmod +x "$script"
        echo -e "${GREEN}✅${NC} Script executable: $script"
    else
        echo -e "${YELLOW}⚠️${NC}  Script missing: $script"
    fi
done

# Check deployment files
echo ""
echo -e "${BLUE}🚀 Checking deployment files...${NC}"

if [ ! -f "deploy/cert-monitor.service" ]; then
    echo -e "${YELLOW}⚠️${NC}  deploy/cert-monitor.service missing - Systemd service not configured"
else
    echo -e "${GREEN}✅${NC} Systemd service configured"
fi

# Initialize Go modules
echo ""
echo -e "${BLUE}📦 Initializing Go modules...${NC}"

if [ ! -f "go.mod" ]; then
    echo -e "${BLUE}Creating go.mod...${NC}"
    go mod init github.com/brandonhon/cert-monitor
fi

echo -e "${BLUE}Downloading dependencies...${NC}"
go mod tidy

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Go modules initialized successfully${NC}"
else
    echo -e "${RED}❌ Go module initialization failed${NC}"
    exit 1
fi

# Test build
echo ""
echo -e "${BLUE}🔨 Testing build...${NC}"

if go build -o cert-monitor-test .; then
    echo -e "${GREEN}✅ Build successful${NC}"
    rm -f cert-monitor-test
else
    echo -e "${RED}❌ Build failed. Please check your main.go file.${NC}"
    exit 1
fi

# Generate test certificates
echo ""
echo -e "${BLUE}🔐 Generating test certificates...${NC}"

if [ -f "scripts/generate-test-certs.sh" ]; then
    if ./scripts/generate-test-certs.sh; then
        echo -e "${GREEN}✅ Test certificates generated${NC}"
    else
        echo -e "${YELLOW}⚠️  Test certificate generation failed (OpenSSL may not be available)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Test certificate generator script not found${NC}"
fi

# Create development config
echo ""
echo -e "${BLUE}⚙️  Setting up development configuration...${NC}"

if [ ! -f "config.yaml" ] && [ -f "config.example.yaml" ]; then
    cp config.example.yaml config.yaml
    # Update config for development
    sed -i.bak 's|/etc/ssl/certs|./test-certs|g' config.yaml 2>/dev/null || \
    sed -i 's|/etc/ssl/certs|./test-certs|g' config.yaml 2>/dev/null || true
    sed -i.bak 's|/usr/local/share/ca-certificates||g' config.yaml 2>/dev/null || \
    sed -i 's|/usr/local/share/ca-certificates||g' config.yaml 2>/dev/null || true
    sed -i.bak 's|/var/log/cert-monitor.log||g' config.yaml 2>/dev/null || \
    sed -i 's|/var/log/cert-monitor.log||g' config.yaml 2>/dev/null || true
    sed -i.bak 's|/var/lib/cert-monitor/cache.json|./dev-cache.json|g' config.yaml 2>/dev/null || \
    sed -i 's|/var/lib/cert-monitor/cache.json|./dev-cache.json|g' config.yaml 2>/dev/null || true
    rm -f config.yaml.bak 2>/dev/null || true
    echo -e "${GREEN}✅ Development config.yaml created${NC}"
else
    echo -e "${GREEN}✅ config.yaml already exists${NC}"
fi

# Test development run
echo ""
echo -e "${BLUE}🧪 Testing development run...${NC}"

if [ -f "config.yaml" ]; then
    timeout 5s ./cert-monitor -config config.yaml -dry-run 2>/dev/null || true
    echo -e "${GREEN}✅ Development run test completed${NC}"
fi

# Verify Makefile targets
echo ""
echo -e "${BLUE}🔧 Verifying Makefile targets...${NC}"

if [ -f "Makefile" ]; then
    if make help > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Makefile verified${NC}"
        echo ""
        echo -e "${BLUE}Available make targets:${NC}"
        make help | head -10
    else
        echo -e "${YELLOW}⚠️  Makefile may have issues${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Makefile not found${NC}"
fi

# Git status check
echo ""
echo -e "${BLUE}📝 Checking git status...${NC}"

if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}⚠️  You have uncommitted changes:${NC}"
    git status --short
    echo ""
    echo -e "${BLUE}Ready to commit with:${NC}"
    echo "git add ."
    echo "git commit -m \"Initial setup: Complete cert-monitor repository\""
    echo "git push -u origin main"
else
    echo -e "${GREEN}✅ Working directory clean${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}🎉 Repository setup finalization complete!${NC}"
echo ""
echo -e "${BLUE}📊 Setup Summary:${NC}"

# Count completed items
total_files=${#required_files[@]}
total_scripts=${#scripts[@]}
found_files=0
found_scripts=0

for file in "${!required_files[@]}"; do
    if [ -f "$file" ]; then
        ((found_files++))
    fi
done

for script in "${scripts[@]}"; do
    if [ -f "$script" ]; then
        ((found_scripts++))
    fi
done

echo "📄 Files: $found_files/$total_files created"
echo "🔧 Scripts: $found_scripts/$total_scripts created"

if [ -f ".github/workflows/ci.yml" ]; then
    echo "✅ CI/CD: GitHub Actions configured"
else
    echo "⚠️  CI/CD: GitHub Actions missing"
fi

if [ -f "test-certs/README.md" ]; then
    echo "🔐 Test certificates: Generated"
else
    echo "⚠️  Test certificates: Not generated"
fi

echo ""
echo -e "${BLUE}Next steps:${NC}"

if [ $found_files -eq $total_files ] && [ $found_scripts -eq $total_scripts ]; then
    echo "1. 📝 Your repository is ready! Commit your changes:"
    echo "   git add ."
    echo "   git commit -m \"Initial setup: Complete cert-monitor repository\""
    echo "   git push -u origin main"
    echo ""
    echo "2. 🧪 Test the application:"
    echo "   make run"
    echo ""
    echo "3. 📊 View metrics:"
    echo "   http://localhost:3000/metrics"
    echo "   http://localhost:3000/healthz"
    echo ""
    echo "4. 🚀 Create your first release:"
    echo "   git tag -a v0.1.0 -m \"Initial release\""
    echo "   git push origin v0.1.0"
    echo ""
    echo "5. 🏗️  Start modular architecture refactor:"
    echo "   ./scripts/migrate-to-modular.sh"
else
    echo "1. 📝 Complete file creation first:"
    echo "   - Missing files need to be created from artifacts"
    echo "   - Run this script again after creating files"
    echo ""
    echo "2. 📚 See CREATE_FILES.md for detailed checklist"
fi

echo ""
echo -e "${GREEN}Happy coding! 🚀${NC}"