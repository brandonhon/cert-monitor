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

	// Create actual test files and add entries
	testFiles := make([]string, 2)
	testData := make([]struct {
		path        string
		fingerprint [32]byte
		info        *FileInfo
	}, 2)

	for i := 0; i < 2; i++ {
		// Create real files
		testFiles[i] = createTempFile(t, "certificate content "+string(rune(i)))
		defer os.Remove(testFiles[i])

		testData[i] = struct {
			path        string
			fingerprint [32]byte
			info        *FileInfo
		}{
			path:        testFiles[i],
			fingerprint: sha256.Sum256([]byte("cert-data-" + string(rune(i)))),
			info: &FileInfo{
				ModTime: time.Now().Add(-time.Duration(i) * time.Hour),
				Size:    int64(1024 * (i + 1)),
			},
		}
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

	// Verify entries are correct by checking with real files
	for _, data := range testData {
		entry, fileInfo, found, err := manager.Get(data.path)
		if err != nil {
			t.Errorf("Failed to get entry for %s: %v", data.path, err)
			continue
		}

		if !found {
			t.Errorf("Entry not found after load: %s", data.path)
			continue
		}

		if entry.Fingerprint != data.fingerprint {
			t.Errorf("Entry fingerprint mismatch for %s", data.path)
		}

		if entry.Size != data.info.Size {
			t.Errorf("Entry size mismatch for %s: expected %d, got %d", data.path, data.info.Size, entry.Size)
		}

		if fileInfo == nil {
			t.Errorf("FileInfo is nil for %s", data.path)
		}
	}
}

// TestLoadNonExistentFile tests loading from non-existent file
func TestLoadNonExistentFile(t *testing.T) {
	manager := createTestManager(false)
	nonExistentFile := "/non/existent/cache.json"

	// Should not error on non-existent file
	if err := manager.Load(nonExistentFile); err != nil {
		t.Errorf("Expected no error for non-existent file, got: %v", err)
	}

	// Cache should remain empty
	if manager.Size() != 0 {
		t.Errorf("Expected empty cache, got size %d", manager.Size())
	}
}

// TestLoadInvalidJSON tests loading from invalid JSON file
func TestLoadInvalidJSON(t *testing.T) {
	manager := createTestManager(false)

	// Create temp file with invalid JSON
	tmpFile := createTempFile(t, "invalid json content {")
	defer os.Remove(tmpFile)

	// Should handle invalid JSON gracefully
	err := manager.Load(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid JSON file")
	}

	// Cache should be empty
	if manager.Size() != 0 {
		t.Errorf("Expected empty cache after invalid JSON, got size %d", manager.Size())
	}
}

// TestSaveToInvalidPath tests saving to invalid path
func TestSaveToInvalidPath(t *testing.T) {
	manager := createTestManager(false)
	invalidPath := "/non/existent/directory/cache.json"

	// Should handle invalid path gracefully
	err := manager.Save(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid save path")
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

		// Time comparison with tolerance for JSON marshaling precision
		timeDiff := deserializedEntry.ModTime.Sub(originalEntry.ModTime)
		if timeDiff > time.Second || timeDiff < -time.Second {
			t.Errorf("ModTime mismatch for %s: expected %v, got %v", path, originalEntry.ModTime, deserializedEntry.ModTime)
		}
	}
}

// TestBackupRestore tests backup and restore functionality
func TestBackupRestore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cache-backup-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheFile := filepath.Join(tmpDir, "cache.json")
	backupFile := cacheFile + ".backup"

	// Create test cache data
	testData := map[string]Entry{
		"/test/cert.pem": {
			Fingerprint: sha256.Sum256([]byte("test-cert")),
			ModTime:     time.Now(),
			Size:        1024,
		},
	}

	// Serialize and write cache file
	data, err := serializeCache(testData)
	if err != nil {
		t.Fatalf("Failed to serialize test data: %v", err)
	}

	if err := os.WriteFile(cacheFile, data, 0o644); err != nil {
		t.Fatalf("Failed to write cache file: %v", err)
	}

	// Test backup
	if err := BackupCache(cacheFile); err != nil {
		t.Fatalf("Failed to backup cache: %v", err)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupFile); err != nil {
		t.Fatalf("Backup file was not created: %v", err)
	}

	// Remove original cache file
	if err := os.Remove(cacheFile); err != nil {
		t.Fatalf("Failed to remove original cache: %v", err)
	}

	// Test restore
	if err := RestoreCache(cacheFile); err != nil {
		t.Fatalf("Failed to restore cache: %v", err)
	}

	// Verify restored file exists and has correct content
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("Restored cache file does not exist: %v", err)
	}

	restoredData, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("Failed to read restored cache: %v", err)
	}

	var restoredCache map[string]Entry
	if err := json.Unmarshal(restoredData, &restoredCache); err != nil {
		t.Fatalf("Restored cache is not valid JSON: %v", err)
	}

	if len(restoredCache) != len(testData) {
		t.Errorf("Expected %d entries in restored cache, got %d", len(testData), len(restoredCache))
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

// BenchmarkDeserializeCache benchmarks cache deserialization
func BenchmarkDeserializeCache(b *testing.B) {
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

	// Serialize once
	data, err := serializeCache(testCache)
	if err != nil {
		b.Fatalf("Failed to serialize test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache := make(map[string]Entry)
		_, err := deserializeCache(data, cache)
		if err != nil {
			b.Fatalf("Deserialization failed: %v", err)
		}
	}
}
