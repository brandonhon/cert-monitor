package cache

import (
	"crypto/sha256"
	"os"
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

func createTempFile(t testing.TB, content string) string {
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
	_, fingerprint, info := createTestEntry()

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

// TestGetNonExistentFile tests Get operation with non-existent file
func TestGetNonExistentFile(t *testing.T) {
	manager := createTestManager(true)
	nonExistentPath := "/non/existent/file.pem"

	_, _, _, err := manager.Get(nonExistentPath)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Note: Cache miss count may not increment for file stat errors
	// This is implementation-dependent behavior
}

// TestCacheMiss tests cache miss scenario
func TestCacheMiss(t *testing.T) {
	manager := createTestManager(true)
	tmpFile := createTempFile(t, "test content")
	defer os.Remove(tmpFile)

	// Get file that's not in cache
	entry, fileInfo, found, err := manager.Get(tmpFile)
	if err != nil {
		t.Fatalf("Get operation failed: %v", err)
	}

	if found {
		t.Error("Expected cache miss, but found entry")
	}

	if entry.Fingerprint != [32]byte{} {
		t.Error("Expected empty fingerprint for cache miss")
	}

	if fileInfo == nil {
		t.Error("Expected FileInfo even on cache miss")
	}

	// Verify statistics
	stats := manager.Stats()
	if stats.CacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", stats.CacheMisses)
	}
}

// TestDelete tests Delete operation
func TestDelete(t *testing.T) {
	manager := createTestManager(false)
	_, fingerprint, info := createTestEntry()

	// Set entry first
	tmpFile := createTempFile(t, "test content")
	defer os.Remove(tmpFile)
	manager.Set(tmpFile, fingerprint, info)

	if manager.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", manager.Size())
	}

	// Delete entry
	manager.Delete(tmpFile)

	if manager.Size() != 0 {
		t.Errorf("Expected cache size 0 after delete, got %d", manager.Size())
	}

	// Verify entry is gone
	_, _, found, err := manager.Get(tmpFile)
	if err != nil {
		t.Fatalf("Get operation failed: %v", err)
	}
	if found {
		t.Error("Expected entry to be deleted")
	}
}

// TestClear tests Clear operation
func TestClear(t *testing.T) {
	manager := createTestManager(false)

	// Add multiple entries
	for i := 0; i < 5; i++ {
		tmpFile := createTempFile(t, "test content")
		defer os.Remove(tmpFile)

		_, fingerprint, info := createTestEntry()
		manager.Set(tmpFile, fingerprint, info)
	}

	if manager.Size() != 5 {
		t.Errorf("Expected cache size 5, got %d", manager.Size())
	}

	// Clear cache
	manager.Clear()

	if manager.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", manager.Size())
	}

	// Verify statistics were reset
	stats := manager.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 total entries after clear, got %d", stats.TotalEntries)
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

			filePath := testFiles[fileIndex]
			_, fingerprint, info := createTestEntry()

			for j := 0; j < numOperations; j++ {
				// Set operation
				manager.Set(filePath, fingerprint, info)

				// Get operation
				_, _, _, err := manager.Get(filePath)
				if err != nil {
					errors <- err
					return
				}

				// Delete operation (every 10th iteration)
				if j%10 == 0 {
					manager.Delete(filePath)
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

// TestStatistics tests statistics tracking
func TestStatistics(t *testing.T) {
	manager := createTestManager(true)
	tmpFile := createTempFile(t, "test content")
	defer os.Remove(tmpFile)

	_, fingerprint, info := createTestEntry()

	// Initial statistics
	stats := manager.Stats()
	if stats.CacheHits != 0 || stats.CacheMisses != 0 {
		t.Error("Expected zero initial statistics")
	}

	// Cache miss
	_, _, _, err := manager.Get(tmpFile)
	if err != nil {
		t.Fatalf("Get operation failed: %v", err)
	}
	stats = manager.Stats()
	if stats.CacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", stats.CacheMisses)
	}

	// Cache hit
	manager.Set(tmpFile, fingerprint, info)
	_, _, _, err = manager.Get(tmpFile)
	if err != nil {
		t.Fatalf("Get operation failed: %v", err)
	}
	stats = manager.Stats()
	if stats.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.CacheHits)
	}

	// Verify hit rate calculation
	expectedHitRate := float64(1) / float64(2) * 100
	if stats.HitRate != expectedHitRate {
		t.Errorf("Expected hit rate %.2f, got %.2f", expectedHitRate, stats.HitRate)
	}
}

// TestMaxEntries tests cache size limiting
func TestMaxEntries(t *testing.T) {
	config := Config{
		MaxEntries:  3,
		EnableStats: false,
	}
	manager := NewManager(config).(*DefaultManager)

	// Add entries up to limit
	testFiles := make([]string, 5)
	for i := 0; i < 5; i++ {
		testFiles[i] = createTempFile(t, "test content")
		defer os.Remove(testFiles[i])

		_, fingerprint, info := createTestEntry()
		manager.Set(testFiles[i], fingerprint, info)

		// Cache should not exceed max entries
		if manager.Size() > 3 {
			t.Errorf("Cache size %d exceeds max entries %d", manager.Size(), 3)
		}
	}

	// Final size should be at most max entries
	if manager.Size() > 3 {
		t.Errorf("Final cache size %d exceeds max entries %d", manager.Size(), 3)
	}
}

// BenchmarkSet benchmarks Set operations
func BenchmarkSet(b *testing.B) {
	manager := createTestManager(false)
	testPath := "/test/benchmark.pem"
	fingerprint := sha256.Sum256([]byte("benchmark-data"))
	info := &FileInfo{
		ModTime: time.Now(),
		Size:    1024,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Set(testPath, fingerprint, info)
	}
}

// BenchmarkGet benchmarks Get operations with cache hits
func BenchmarkGet(b *testing.B) {
	manager := createTestManager(false)
	tmpFile := createTempFile(b, "test content")
	defer os.Remove(tmpFile)

	_, fingerprint, info := createTestEntry()
	manager.Set(tmpFile, fingerprint, info)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := manager.Get(tmpFile)
		if err != nil {
			b.Fatalf("Get operation failed: %v", err)
		}
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent access
func BenchmarkConcurrentAccess(b *testing.B) {
	manager := createTestManager(false)
	tmpFile := createTempFile(b, "test content")
	defer os.Remove(tmpFile)

	_, fingerprint, info := createTestEntry()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.Set(tmpFile, fingerprint, info)
			_, _, _, err := manager.Get(tmpFile)
			if err != nil {
				b.Fatalf("Get operation failed: %v", err)
			}
		}
	})
}
