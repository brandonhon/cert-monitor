#!/bin/bash
# Complete Cache Testing Setup Script
# Creates all cache test files and sets up the testing infrastructure

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Setting up Cache Package Testing${NC}"
echo "Project Root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

# Ensure cache package directory exists
CACHE_DIR="internal/cache"
if [ ! -d "$CACHE_DIR" ]; then
    echo -e "${RED}❌ Cache package directory not found: $CACHE_DIR${NC}"
    echo "Please ensure the cache package has been implemented first."
    exit 1
fi

# Check if test files already exist
TEST_FILES=(
    "$CACHE_DIR/manager_test.go"
    "$CACHE_DIR/storage_test.go"
    "$CACHE_DIR/cache_test.go"
)

echo -e "${BLUE}📋 Checking for existing test files...${NC}"
for file in "${TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${YELLOW}⚠️  Test file already exists: $file${NC}"
        echo "   This script will backup and replace it."
    else
        echo -e "${GREEN}✨ Will create: $file${NC}"
    fi
done

read -p "Continue with cache test setup? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Create backups of existing files
echo -e "${BLUE}💾 Creating backups...${NC}"
for file in "${TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$file.backup.$(date +%Y%m%d_%H%M%S)"
        echo -e "${GREEN}✅ Backed up: $file${NC}"
    fi
done

# Create manager_test.go
echo -e "${BLUE}📝 Creating manager_test.go...${NC}"
cat > "$CACHE_DIR/manager_test.go" << 'EOF'
package cache

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Test helper functions
func createTestManager(enableStats bool) *DefaultManager {
	config := Config{
		FilePath:      "",
		AutoSave:      false,
		SaveInterval:  time.Minute,
		PruneInterval: time.Hour,
		MaxEntries:    100,
		EnableStats:   enableStats,
	}
	return NewManager(config).(*DefaultManager)
}

func createTestEntry() (string, [32]byte, *FileInfo) {
	path := "/test/cert.pem"
	fingerprint := sha256.Sum256([]byte("test-certificate-data"))
	info := &FileInfo{
		ModTime: time.Now(),
		Size:    1024,
	}
	return path, fingerprint, info
}

func createTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "cache-test-*.tmp")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	if content != "" {
		if _, err := tmpFile.WriteString(content); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}
	}

	return tmpFile.Name()
}

// TestManagerCreation tests cache manager creation
func TestManagerCreation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default_config",
			config: Config{
				FilePath:     "/tmp/cache.json",
				EnableStats:  true,
				MaxEntries:   100,
				SaveInterval: time.Minute,
			},
		},
		{
			name: "minimal_config",
			config: Config{
				FilePath:    "/tmp/minimal.json",
				EnableStats: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(tt.config)
			if manager == nil {
				t.Error("Expected non-nil manager")
			}

			defaultManager := manager.(*DefaultManager)
			if defaultManager.config.FilePath != tt.config.FilePath {
				t.Errorf("Expected FilePath %s, got %s", tt.config.FilePath, defaultManager.config.FilePath)
			}

			if defaultManager.Size() != 0 {
				t.Errorf("Expected empty cache, got size %d", defaultManager.Size())
			}
		})
	}
}

// TestSetAndGet tests basic Set and Get operations
func TestSetAndGet(t *testing.T) {
	manager := createTestManager(true)
	path, fingerprint, info := createTestEntry()

	// Create actual test file for Get operation
	tmpFile := createTempFile(t, "test content")
	defer os.Remove(tmpFile)

	// Test Set operation
	manager.Set(tmpFile, fingerprint, info)

	// Test Get operation
	entry, fileInfo, found, err := manager.Get(tmpFile)
	if err != nil {
		t.Fatalf("Get operation failed: %v", err)
	}

	if !found {
		t.Error("Expected to find cache entry")
	}

	if entry.Fingerprint != fingerprint {
		t.Errorf("Expected fingerprint %x, got %x", fingerprint, entry.Fingerprint)
	}

	if fileInfo == nil {
		t.Error("Expected non-nil FileInfo")
	}

	// Verify statistics were updated
	stats := manager.Stats()
	if stats.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.CacheHits)
	}
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	manager := createTestManager(true)
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Create test files
	testFiles := make([]string, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		testFiles[i] = createTempFile(t, "test content")
		defer os.Remove(testFiles[i])
	}

	// Launch concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(fileIndex int) {
			defer wg.Done()
			
			path := testFiles[fileIndex]
			_, fingerprint, info := createTestEntry()

			for j := 0; j < numOperations; j++ {
				// Set operation
				manager.Set(path, fingerprint, info)

				// Get operation
				_, _, _, err := manager.Get(path)
				if err != nil {
					errors <- err
					return
				}

				// Delete operation (every 10th iteration)
				if j%10 == 0 {
					manager.Delete(path)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}

	// Verify cache is in consistent state
	stats := manager.Stats()
	if stats.TotalEntries < 0 {
		t.Error("Cache statistics are inconsistent")
	}
}

// BenchmarkSet benchmarks Set operations
func BenchmarkSet(b *testing.B) {
	manager := createTestManager(false)
	path, fingerprint, info := createTestEntry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Set(path, fingerprint, info)
	}
}

// BenchmarkGet benchmarks Get operations with cache hits
func BenchmarkGet(b *testing.B) {
	manager := createTestManager(false)
	tmpFile := createTempFile(b, "test content")
	defer os.Remove(tmpFile)

	path, fingerprint, info := createTestEntry()
	manager.Set(tmpFile, fingerprint, info)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Get(tmpFile)
	}
}
EOF

echo -e "${GREEN}✅ Created manager_test.go${NC}"

# Create storage_test.go
echo -e "${BLUE}📝 Creating storage_test.go...${NC}"
cat > "$CACHE_DIR/storage_test.go" << 'EOF'
package cache

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadSave tests cache loading and saving to file
func TestLoadSave(t *testing.T) {
	manager := createTestManager(false)
	
	// Create temporary cache file
	tmpDir, err := os.MkdirTemp("", "cache-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheFile := filepath.Join(tmpDir, "test-cache.json")
	
	// Add some entries
	testData := map[string]struct {
		path        string
		fingerprint [32]byte
		info        *FileInfo
	}{
		"entry1": {
			path:        "/test/cert1.pem",
			fingerprint: sha256.Sum256([]byte("cert1-data")),
			info: &FileInfo{
				ModTime: time.Now().Add(-time.Hour),
				Size:    1024,
			},
		},
		"entry2": {
			path:        "/test/cert2.pem",
			fingerprint: sha256.Sum256([]byte("cert2-data")),
			info: &FileInfo{
				ModTime: time.Now().Add(-time.Minute),
				Size:    2048,
			},
		},
	}

	// Set entries in cache
	for _, data := range testData {
		manager.Set(data.path, data.fingerprint, data.info)
	}

	originalSize := manager.Size()
	if originalSize != len(testData) {
		t.Errorf("Expected cache size %d, got %d", len(testData), originalSize)
	}

	// Save cache to file
	if err := manager.Save(cacheFile); err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("Cache file was not created: %v", err)
	}

	// Clear cache and reload
	manager.Clear()
	if manager.Size() != 0 {
		t.Error("Expected empty cache after clear")
	}

	// Load cache from file
	if err := manager.Load(cacheFile); err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	// Verify cache was restored
	if manager.Size() != originalSize {
		t.Errorf("Expected cache size %d after load, got %d", originalSize, manager.Size())
	}
}

// TestSerializeDeserialize tests JSON serialization/deserialization
func TestSerializeDeserialize(t *testing.T) {
	testCache := map[string]Entry{
		"/test/cert1.pem": {
			Fingerprint: sha256.Sum256([]byte("cert1")),
			ModTime:     time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			Size:        1024,
		},
		"/test/cert2.pem": {
			Fingerprint: sha256.Sum256([]byte("cert2")),
			ModTime:     time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC),
			Size:        2048,
		},
	}

	// Serialize
	data, err := serializeCache(testCache)
	if err != nil {
		t.Fatalf("Failed to serialize cache: %v", err)
	}

	// Verify JSON structure
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		t.Fatalf("Serialized data is not valid JSON: %v", err)
	}

	// Deserialize
	deserializedCache := make(map[string]Entry)
	deserializedCache, err = deserializeCache(data, deserializedCache)
	if err != nil {
		t.Fatalf("Failed to deserialize cache: %v", err)
	}

	// Verify deserialized data
	if len(deserializedCache) != len(testCache) {
		t.Errorf("Expected %d entries, got %d", len(testCache), len(deserializedCache))
	}

	for path, originalEntry := range testCache {
		deserializedEntry, found := deserializedCache[path]
		if !found {
			t.Errorf("Entry %s not found after deserialization", path)
			continue
		}

		if deserializedEntry.Fingerprint != originalEntry.Fingerprint {
			t.Errorf("Fingerprint mismatch for %s", path)
		}

		if deserializedEntry.Size != originalEntry.Size {
			t.Errorf("Size mismatch for %s: expected %d, got %d", path, originalEntry.Size, deserializedEntry.Size)
		}
	}
}

// BenchmarkSerializeCache benchmarks cache serialization
func BenchmarkSerializeCache(b *testing.B) {
	// Create test cache with many entries
	testCache := make(map[string]Entry)
	for i := 0; i < 1000; i++ {
		path := filepath.Join("/test", "certs", "cert"+string(rune(i))+".pem")
		testCache[path] = Entry{
			Fingerprint: sha256.Sum256([]byte("cert-data-" + string(rune(i)))),
			ModTime:     time.Now(),
			Size:        int64(1024 + i),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := serializeCache(testCache)
		if err != nil {
			b.Fatalf("Serialization failed: %v", err)
		}
	}
}
EOF

echo -e "${GREEN}✅ Created storage_test.go${NC}"

# Create integration test file
echo -e "${BLUE}📝 Creating cache_test.go (integration tests)...${NC}"
cat > "$CACHE_DIR/cache_test.go" << 'EOF'
package cache

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCacheIntegration tests complete cache workflow
func TestCacheIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheFile := filepath.Join(tmpDir, "integration-cache.json")

	// Create manager with realistic configuration
	config := Config{
		FilePath:      cacheFile,
		AutoSave:      false,
		SaveInterval:  time.Minute,
		PruneInterval: time.Hour,
		MaxEntries:    50,
		EnableStats:   true,
	}
	manager := NewManager(config)

	// Test 1: Initial state
	if manager.Size() != 0 {
		t.Error("Expected empty cache initially")
	}

	stats := manager.Stats()
	if stats.TotalEntries != 0 || stats.CacheHits != 0 || stats.CacheMisses != 0 {
		t.Error("Expected zero initial statistics")
	}

	// Test 2: Add multiple entries
	testFiles := make([]string, 10)
	expectedEntries := make(map[string]Entry)

	for i := 0; i < 10; i++ {
		// Create actual test files
		testFiles[i] = createTempFile(t, "certificate data "+string(rune(i)))
		defer os.Remove(testFiles[i])

		fingerprint := sha256.Sum256([]byte("cert-data-" + string(rune(i))))
		info := &FileInfo{
			ModTime: time.Now().Add(-time.Duration(i) * time.Minute),
			Size:    int64(1024 + i*100),
		}

		manager.Set(testFiles[i], fingerprint, info)
		expectedEntries[testFiles[i]] = Entry{
			Fingerprint: fingerprint,
			ModTime:     info.ModTime,
			Size:        info.Size,
		}
	}

	if manager.Size() != 10 {
		t.Errorf("Expected cache size 10, got %d", manager.Size())
	}

	// Test 3: Save and reload
	if err := manager.Save(cacheFile); err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Clear and reload
	manager.Clear()
	if manager.Size() != 0 {
		t.Error("Expected empty cache after clear")
	}

	if err := manager.Load(cacheFile); err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if manager.Size() != 10 {
		t.Errorf("Expected cache size 10 after reload, got %d", manager.Size())
	}

	// Test 4: Statistics verification
	stats = manager.Stats()
	if stats.TotalEntries != 10 {
		t.Errorf("Expected 10 total entries, got %d", stats.TotalEntries)
	}

	t.Logf("Cache integration test completed successfully")
}

// TestCachePerformance tests cache performance characteristics
func TestCachePerformance(t *testing.T) {
	manager := createTestManager(true)
	const numEntries = 1000

	// Create test files
	testFiles := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		testFiles[i] = createTempFile(t, "performance test data "+string(rune(i)))
		defer os.Remove(testFiles[i])
	}

	// Measure Set performance
	start := time.Now()
	for i := 0; i < numEntries; i++ {
		fingerprint := sha256.Sum256([]byte("perf-test-" + string(rune(i))))
		info := &FileInfo{
			ModTime: time.Now(),
			Size:    int64(1024 + i),
		}
		manager.Set(testFiles[i], fingerprint, info)
	}
	setDuration := time.Since(start)

	t.Logf("Set %d entries in %v (%.2f entries/sec)", numEntries, setDuration, float64(numEntries)/setDuration.Seconds())

	// Measure Get performance (cache hits)
	start = time.Now()
	for i := 0; i < numEntries; i++ {
		_, _, _, err := manager.Get(testFiles[i])
		if err != nil {
			t.Fatalf("Get operation failed for entry %d: %v", i, err)
		}
	}
	getDuration := time.Since(start)

	t.Logf("Get %d entries in %v (%.2f entries/sec)", numEntries, getDuration, float64(numEntries)/getDuration.Seconds())

	// Verify all operations were cache hits
	stats := manager.Stats()
	if stats.CacheHits != int64(numEntries) {
		t.Errorf("Expected %d cache hits, got %d", numEntries, stats.CacheHits)
	}

	// Test performance limits
	if setDuration > 5*time.Second {
		t.Errorf("Set operations too slow: %v (should be < 5s)", setDuration)
	}

	if getDuration > 2*time.Second {
		t.Errorf("Get operations too slow: %v (should be < 2s)", getDuration)
	}
}
EOF

echo -e "${GREEN}✅ Created cache_test.go${NC}"

# Update basic_test.go to remove the placeholder cache test
echo -e "${BLUE}📝 Updating basic_test.go...${NC}"
if [ -f "test/basic_test.go" ]; then
    # Create backup
    cp "test/basic_test.go" "test/basic_test.go.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Remove the placeholder TestCachePerformance function
    sed '/^\/\/ TestCachePerformance tests certificate caching functionality$/,/^}$/d' "test/basic_test.go" > "test/basic_test.go.tmp"
    mv "test/basic_test.go.tmp" "test/basic_test.go"
    
    echo -e "${GREEN}✅ Updated basic_test.go (removed placeholder cache test)${NC}"
else
    echo -e "${YELLOW}⚠️  basic_test.go not found, skipping update${NC}"
fi

# Create scripts directory if it doesn't exist
SCRIPTS_DIR="scripts"
mkdir -p "$SCRIPTS_DIR"

# Create test-cache.sh script
echo -e "${BLUE}📝 Creating test-cache.sh script...${NC}"
cat > "$SCRIPTS_DIR/test-cache.sh" << 'EOF'
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
EOF

chmod +x "$SCRIPTS_DIR/test-cache.sh"
echo -e "${GREEN}✅ Created test-cache.sh script${NC}"

# Test compilation
echo -e "${BLUE}🔧 Testing compilation...${NC}"
if go build ./internal/cache/...; then
    echo -e "${GREEN}✅ Cache package compiles successfully${NC}"
else
    echo -e "${RED}❌ Cache package compilation failed${NC}"
    echo "Please check the cache package implementation."
    exit 1
fi

# Run basic test
echo -e "${BLUE}🧪 Running basic cache test...${NC}"
if go test ./internal/cache/... -run TestManagerCreation; then
    echo -e "${GREEN}✅ Basic cache test passed${NC}"
else
    echo -e "${YELLOW}⚠️  Basic cache test failed - this is expected if cache implementation is incomplete${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Cache Testing Setup Complete!${NC}"
echo ""
echo -e "${BLUE}📋 Created Files:${NC}"
echo "  ✅ $CACHE_DIR/manager_test.go"
echo "  ✅ $CACHE_DIR/storage_test.go"
echo "  ✅ $CACHE_DIR/cache_test.go"
echo "  ✅ $SCRIPTS_DIR/test-cache.sh"
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "1. Run cache tests: make test-cache"
echo "2. Run with coverage: make test-cache-coverage"
echo "3. Run comprehensive tests: ./scripts/test-cache.sh"
echo "4. Check coverage report: open coverage-cache.html"
echo ""
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "  make test-cache              # Basic cache tests"
echo "  make test-cache-race         # Race detection tests"
echo "  make test-cache-coverage     # Coverage analysis"
echo "  make test-cache-benchmark    # Performance benchmarks"
echo "  ./scripts/test-cache.sh      # Comprehensive test runner"
echo ""
echo -e "${GREEN}✅ Cache package testing is ready!${NC}"
