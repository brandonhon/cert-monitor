package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatcherManager(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()

	// Create test subdirectory
	testDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Track events
	var eventsMutex sync.Mutex
	var receivedEvents []Event

	config := &Config{
		CertificateDirs: []string{testDir},
		DebounceDelay:   100 * time.Millisecond,
		OnFileChange: func(event Event) {
			eventsMutex.Lock()
			receivedEvents = append(receivedEvents, event)
			eventsMutex.Unlock()
		},
	}

	manager := New(config)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watcher
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := manager.Stop(ctx); err != nil {
			t.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Verify directory is being watched
	if !manager.IsWatching(testDir) {
		t.Error("Test directory should be watched")
	}

	watchedDirs := manager.GetWatchedDirs()
	found := false
	for _, dir := range watchedDirs {
		if dir == testDir {
			found = true
			break
		}
	}
	if !found {
		t.Error("Test directory not found in watched directories list")
	}

	// Create a test file and verify event is received
	testFile := filepath.Join(testDir, "test.pem")
	if err := os.WriteFile(testFile, []byte("test certificate content"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for event processing
	time.Sleep(200 * time.Millisecond)

	// Check if event was received
	eventsMutex.Lock()
	eventCount := len(receivedEvents)
	eventsMutex.Unlock()

	if eventCount == 0 {
		t.Error("Expected to receive file change event")
	}
}

func TestWatcherConfig(t *testing.T) {
	config := DefaultConfig()

	if config.DebounceDelay != 2*time.Second {
		t.Errorf("Expected default debounce delay of 2s, got %v", config.DebounceDelay)
	}

	expectedExcluded := []string{"old", "working", ".git", ".svn"}
	if len(config.ExcludedDirs) != len(expectedExcluded) {
		t.Errorf("Expected %d excluded dirs, got %d", len(expectedExcluded), len(config.ExcludedDirs))
	}

	for i, expected := range expectedExcluded {
		if i < len(config.ExcludedDirs) && config.ExcludedDirs[i] != expected {
			t.Errorf("Expected excluded dir %s, got %s", expected, config.ExcludedDirs[i])
		}
	}
}

func TestWatcherDirectoryManagement(t *testing.T) {
	tmpDir := t.TempDir()

	testDir1 := filepath.Join(tmpDir, "dir1")
	testDir2 := filepath.Join(tmpDir, "dir2")

	if err := os.MkdirAll(testDir1, 0o755); err != nil {
		t.Fatalf("Failed to create test directory 1: %v", err)
	}
	if err := os.MkdirAll(testDir2, 0o755); err != nil {
		t.Fatalf("Failed to create test directory 2: %v", err)
	}

	config := &Config{
		CertificateDirs: []string{testDir1},
		DebounceDelay:   100 * time.Millisecond,
	}

	manager := New(config)
	ctx := context.Background()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := manager.Stop(ctx); err != nil {
			t.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	// Test adding directory
	if err := manager.AddDirectories([]string{testDir2}); err != nil {
		t.Errorf("Failed to add directory: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if !manager.IsWatching(testDir2) {
		t.Error("Directory should be watched after adding")
	}

	// Test removing directory
	if err := manager.RemoveDirectories([]string{testDir1}); err != nil {
		t.Errorf("Failed to remove directory: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if manager.IsWatching(testDir1) {
		t.Error("Directory should not be watched after removal")
	}
}

func TestConfigFileWatching(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	// Create initial config file
	if err := os.WriteFile(configFile, []byte("test: config"), 0o644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	var configChanges int
	var configMutex sync.Mutex

	config := &Config{
		ConfigFilePath: configFile,
		DebounceDelay:  50 * time.Millisecond,
		OnConfigChange: func(path string) {
			configMutex.Lock()
			configChanges++
			configMutex.Unlock()
		},
	}

	manager := New(config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := manager.Stop(ctx); err != nil {
			t.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Modify config file
	if err := os.WriteFile(configFile, []byte("test: modified"), 0o644); err != nil {
		t.Fatalf("Failed to modify config file: %v", err)
	}

	// Wait for debounced event
	time.Sleep(200 * time.Millisecond)

	configMutex.Lock()
	changes := configChanges
	configMutex.Unlock()

	if changes == 0 {
		t.Error("Expected config change event")
	}
}

func TestWatcherShouldSkipDirectory(t *testing.T) {
	config := DefaultConfig()
	manager := &Manager{config: *config}

	tests := []struct {
		name     string
		dirName  string
		expected bool
	}{
		{"normal_dir", "certificates", false},
		{"old_dir", "old", true},
		{"OLD_dir", "OLD", true},
		{"working_dir", "working", true},
		{"WORKING_dir", "WORKING", true},
		{"git_dir", ".git", true},
		{"svn_dir", ".svn", true},
		{"valid_cert_dir", "ssl-certs", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.shouldSkipDirectory(tt.dirName)
			if result != tt.expected {
				t.Errorf("shouldSkipDirectory(%s) = %v, expected %v", tt.dirName, result, tt.expected)
			}
		})
	}
}

func TestWatcherEventTypes(t *testing.T) {
	// Test Event struct
	event := Event{
		Type: EventCertificateChange,
		Path: "/test/path/cert.pem",
	}

	if event.Type != EventCertificateChange {
		t.Errorf("Expected EventCertificateChange, got %v", event.Type)
	}

	if event.Path != "/test/path/cert.pem" {
		t.Errorf("Expected path '/test/path/cert.pem', got %s", event.Path)
	}
}

func TestWatcherStartStop(t *testing.T) {
	tmpDir := t.TempDir()

	config := &Config{
		CertificateDirs: []string{tmpDir},
		DebounceDelay:   100 * time.Millisecond,
	}

	manager := New(config)
	ctx := context.Background()

	// Test start
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Verify it's watching
	if !manager.IsWatching(tmpDir) {
		t.Error("Should be watching directory after start")
	}

	// Test stop
	if err := manager.Stop(ctx); err != nil {
		t.Errorf("Failed to stop watcher: %v", err)
	}

	// Verify cleanup
	watchedDirs := manager.GetWatchedDirs()
	if len(watchedDirs) > 0 {
		t.Error("Should have no watched directories after stop")
	}
}

// Benchmark tests
func BenchmarkWatcherAddDirectory(b *testing.B) {
	tmpDir := b.TempDir()

	config := &Config{
		CertificateDirs: []string{},
		DebounceDelay:   100 * time.Millisecond,
	}

	manager := New(config)
	ctx := context.Background()

	if err := manager.Start(ctx); err != nil {
		b.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := manager.Stop(ctx); err != nil {
			b.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		testDir := filepath.Join(tmpDir, "dir"+string(rune(i)))
		if err := os.MkdirAll(testDir, 0o755); err != nil {
			b.Fatalf("Failed to create test directory: %v", err)
		}

		if err := manager.AddDirectories([]string{testDir}); err != nil {
			b.Errorf("Failed to add directory: %v", err)
		}
	}
}

func BenchmarkWatcherIsWatching(b *testing.B) {
	tmpDir := b.TempDir()

	config := &Config{
		CertificateDirs: []string{tmpDir},
		DebounceDelay:   100 * time.Millisecond,
	}

	manager := New(config)
	ctx := context.Background()

	if err := manager.Start(ctx); err != nil {
		b.Fatalf("Failed to start watcher: %v", err)
	}
	defer func() {
		if err := manager.Stop(ctx); err != nil {
			b.Errorf("Failed to stop watcher: %v", err)
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		manager.IsWatching(tmpDir)
	}
}
