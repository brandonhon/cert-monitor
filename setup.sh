#!/bin/bash
# Setup script for cert-monitor repository

set -e

echo "🚀 Setting up cert-monitor repository..."

# Check if we're in the right directory
if [ ! -d ".git" ]; then
    echo "❌ This doesn't appear to be a git repository. Please run from the cert-monitor directory."
    exit 1
fi

# Verify remote origin
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ "$REMOTE_URL" != *"brandonhon/cert-monitor"* ]]; then
    echo "❌ Remote origin doesn't match expected repository. Expected: github.com/brandonhon/cert-monitor"
    echo "   Current: $REMOTE_URL"
    exit 1
fi

echo "✅ Repository validated"

# Initialize go modules
echo "📦 Initializing Go modules..."
if [ ! -f "go.mod" ]; then
    go mod init github.com/brandonhon/cert-monitor
else
    echo "   go.mod already exists"
fi

# Download dependencies
echo "📥 Downloading dependencies..."
go mod tidy

# Verify main.go exists
if [ ! -f "main.go" ]; then
    echo "❌ main.go not found. Please copy your main.go file to this directory."
    exit 1
fi

echo "✅ main.go found"

# Test build
echo "🔨 Testing build..."
if go build -o cert-monitor-test .; then
    echo "✅ Build successful"
    rm -f cert-monitor-test
else
    echo "❌ Build failed. Please check your code."
    exit 1
fi

# Run tests if any exist
if ls *_test.go 1> /dev/null 2>&1; then
    echo "🧪 Running tests..."
    go test ./...
else
    echo "ℹ️  No tests found (this is normal for initial setup)"
fi

# Create example test certificates directory
if [ ! -d "test-certs" ]; then
    echo "📁 Creating test certificates directory..."
    mkdir -p test-certs
    echo "   Created test-certs/ - add some test certificates here for development"
fi

# Verify Makefile targets
if [ -f "Makefile" ]; then
    echo "🔧 Verifying Makefile..."
    if make help > /dev/null 2>&1; then
        echo "✅ Makefile verified"
    else
        echo "⚠️  Makefile may have issues"
    fi
fi

# Check if config example exists
if [ -f "config.example.yaml" ]; then
    if [ ! -f "config.yaml" ]; then
        echo "⚙️  Creating config.yaml from example..."
        cp config.example.yaml config.yaml
        echo "   Edit config.yaml to customize your settings"
    fi
fi

echo ""
echo "🎉 Setup complete! Next steps:"
echo ""
echo "1. 📝 Edit config.yaml with your certificate directories"
echo "2. 🧪 Test with: make run"
echo "3. 🔍 Validate config: make validate-config"
echo "4. 📊 View metrics at: http://localhost:3000/metrics"
echo "5. 🏥 Check health at: http://localhost:3000/healthz"
echo ""
echo "Development commands:"
echo "  make build     - Build the binary"
echo "  make test      - Run tests"
echo "  make run       - Run in development mode"
echo "  make help      - Show all available commands"
echo ""
echo "📚 See README.md for detailed documentation"