package state

import (
	"sync"
	"testing"
	"time"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
)

// Mock cache manager for testing
type mockCacheManager struct{}

func (m *mockCacheManager) Get(path string) (*cache.Entry, *cache.FileInfo, bool, error) {
	return &cache.Entry{}, &cache.FileInfo{}, false, nil
}
func (m *mockCacheManager) Set(path string, fingerprint [32]byte, info *cache.FileInfo) {}
func (m *mockCacheManager) Delete(path string)                                          {}
func (m *mockCacheManager) Load(filepath string) error                                  { return nil }
func (m *mockCacheManager) Save(filepath string) error                                  { return nil }
func (m *mockCacheManager) Prune() int                                                  { return 0 }
func (m *mockCacheManager) Clear()                                                      {}
func (m *mockCacheManager) Stats() cache.Statistics {
	return cache.Statistics{}
}
func (m *mockCacheManager) Size() int { return 0 }

// Mock metrics registry for testing
type mockMetricsRegistry struct{}

func (m *mockMetricsRegistry) GetCollector() *metrics.DefaultCollector {
	return &metrics.DefaultCollector{}
}
func (m *mockMetricsRegistry) Reset() {}

func createTestStateManager() Manager {
	deps := &Dependencies{
		CacheManager:    &mockCacheManager{},
		MetricsRegistry: &mockMetricsRegistry{},
	}
	return New(nil, deps)
}

func TestStateManagerConfiguration(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	// Test initial state
	if manager.GetConfig() != nil {
		t.Error("Initial config should be nil")
	}

	// Test setting config
	cfg := &config.Config{
		DryRun: true,
		Port:   "8080",
	}
	manager.SetConfig(cfg)

	retrievedConfig := manager.GetConfig()
	if retrievedConfig == nil {
		t.Fatal("Config should not be nil after setting")
	}

	if retrievedConfig.DryRun != true {
		t.Error("DryRun should be true")
	}

	if retrievedConfig.Port != "8080" {
		t.Error("Port should be 8080")
	}
}

func TestStateManagerConfigFilePath(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	// Test initial state
	if manager.GetConfigFilePath() != "" {
		t.Error("Initial config file path should be empty")
	}

	// Test setting config file path
	testPath := "/etc/cert-monitor/config.yaml"
	manager.SetConfigFilePath(testPath)

	if manager.GetConfigFilePath() != testPath {
		t.Errorf("Expected config file path %s, got %s", testPath, manager.GetConfigFilePath())
	}
}

func TestStateManagerReloadTrigger(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	// Test triggering reload
	manager.TriggerReload()

	// Should receive reload signal
	select {
	case <-manager.GetReloadChannel():
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Should have received reload signal")
	}

	// Test multiple triggers - should not block
	manager.TriggerReload()
	manager.TriggerReload()

	// Should still only have one signal queued
	select {
	case <-manager.GetReloadChannel():
		// Success - first signal
	case <-time.After(100 * time.Millisecond):
		t.Error("Should have received first reload signal")
	}

	// Should not have another signal immediately available
	select {
	case <-manager.GetReloadChannel():
		t.Error("Should not have received second reload signal immediately")
	case <-time.After(50 * time.Millisecond):
		// Success - no second signal
	}
}

func TestStateManagerShouldWriteMetrics(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	// Test with nil config
	if manager.ShouldWriteMetrics() {
		t.Error("Should not write metrics with nil config")
	}

	// Test with dry run enabled
	manager.SetConfig(&config.Config{DryRun: true})
	if manager.ShouldWriteMetrics() {
		t.Error("Should not write metrics in dry run mode")
	}

	// Test with dry run disabled
	manager.SetConfig(&config.Config{DryRun: false})
	if !manager.ShouldWriteMetrics() {
		t.Error("Should write metrics when dry run is disabled")
	}
}

func TestStateManagerClose(t *testing.T) {
	manager := createTestStateManager()

	// Test that trigger works before close
	manager.TriggerReload()

	// Should receive signal
	select {
	case <-manager.GetReloadChannel():
		// Success
	case <-time.After(50 * time.Millisecond):
		t.Error("Should have received reload signal")
	}

	// Close the manager
	manager.Close()

	// Test triggering reload after close
	manager.TriggerReload() // Should not panic

	// Test multiple closes don't panic
	manager.Close()
	manager.Close()

	// Test channel is closed
	select {
	case _, ok := <-manager.GetReloadChannel():
		if ok {
			t.Error("Channel should be closed")
		}
	case <-time.After(50 * time.Millisecond):
		t.Error("Should have received close signal")
	}
}

func TestStateManagerConcurrency(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Test concurrent config access
	wg.Add(numGoroutines * 2)

	// Concurrent config setters
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			cfg := &config.Config{
				Port:   "808" + string(rune('0'+id%10)),
				DryRun: id%2 == 0,
			}
			manager.SetConfig(cfg)
		}(i)
	}

	// Concurrent config getters
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			config := manager.GetConfig()
			if config != nil {
				_ = config.Port
				_ = config.DryRun
			}
		}()
	}

	wg.Wait()

	// Should have a valid config at the end
	finalConfig := manager.GetConfig()
	if finalConfig == nil {
		t.Error("Should have a config after concurrent operations")
	}
}

func TestBackoffManager(t *testing.T) {
	bm := NewBackoffManager()

	testDir := "/test/directory"

	// Initially should not skip
	if bm.ShouldSkip(testDir) {
		t.Error("Should not skip directory initially")
	}

	// Register failure
	bm.RegisterFailure(testDir)

	// Now should skip
	if !bm.ShouldSkip(testDir) {
		t.Error("Should skip directory after failure")
	}

	// Check stats
	stats := bm.GetStats()
	if stats["active_backoffs"].(int) != 1 {
		t.Error("Should have 1 active backoff")
	}

	directories := stats["directories"].([]string)
	if len(directories) != 1 || directories[0] != testDir {
		t.Error("Should have correct directory in backoff")
	}
}

func TestBackoffManagerExpiration(t *testing.T) {
	bm := NewBackoffManager()
	testDir := "/test/directory"

	// Register failure
	bm.RegisterFailure(testDir)

	// Should be in backoff
	if !bm.ShouldSkip(testDir) {
		t.Error("Should skip directory after failure")
	}

	// Clear expired (shouldn't clear anything yet)
	bm.ClearExpired()

	// Should still be in backoff
	if !bm.ShouldSkip(testDir) {
		t.Error("Should still skip directory after clearing expired")
	}

	// Manually expire by setting past time
	bm.mutex.Lock()
	bm.backoffs[testDir] = time.Now().Add(-1 * time.Hour)
	bm.mutex.Unlock()

	// Should no longer skip (expired entry gets removed)
	if bm.ShouldSkip(testDir) {
		t.Error("Should not skip directory after expiration")
	}

	// Stats should show no active backoffs
	stats := bm.GetStats()
	if stats["active_backoffs"].(int) != 0 {
		t.Error("Should have 0 active backoffs after expiration")
	}
}

func TestBackoffManagerExponentialDelay(t *testing.T) {
	bm := NewBackoffManager()
	testDir := "/test/directory"

	// First failure
	bm.RegisterFailure(testDir)
	if !bm.ShouldSkip(testDir) {
		t.Error("Should skip after first failure")
	}

	// Get the first backoff time
	bm.mutex.Lock()
	firstBackoff := bm.backoffs[testDir]
	bm.mutex.Unlock()

	// Register second failure (should extend backoff)
	bm.RegisterFailure(testDir)

	// Get the second backoff time
	bm.mutex.Lock()
	secondBackoff := bm.backoffs[testDir]
	bm.mutex.Unlock()

	// Second backoff should be later than first
	if !secondBackoff.After(firstBackoff) {
		t.Error("Second backoff should be later than first (exponential)")
	}
}

func TestBackoffManagerMultipleDirectories(t *testing.T) {
	bm := NewBackoffManager()

	dirs := []string{"/dir1", "/dir2", "/dir3"}

	// Register failures for all directories
	for _, dir := range dirs {
		bm.RegisterFailure(dir)
	}

	// All should be in backoff
	for _, dir := range dirs {
		if !bm.ShouldSkip(dir) {
			t.Errorf("Directory %s should be in backoff", dir)
		}
	}

	// Stats should show all directories
	stats := bm.GetStats()
	if stats["active_backoffs"].(int) != len(dirs) {
		t.Errorf("Should have %d active backoffs", len(dirs))
	}

	// Clear expired (should not clear anything yet)
	bm.ClearExpired()

	// Should still have all directories
	if stats["active_backoffs"].(int) != len(dirs) {
		t.Error("Should still have all directories after clearing expired")
	}
}

func TestStateManagerIntegration(t *testing.T) {
	manager := createTestStateManager()
	defer manager.Close()

	testDir := "/test/integration"

	// Test integrated backoff functionality
	if manager.ShouldSkipScan(testDir) {
		t.Error("Should not skip scan initially")
	}

	manager.RegisterScanFailure(testDir)

	if !manager.ShouldSkipScan(testDir) {
		t.Error("Should skip scan after failure")
	}

	manager.ClearExpiredBackoffs()

	// Should still skip (not expired yet)
	if !manager.ShouldSkipScan(testDir) {
		t.Error("Should still skip scan after clearing expired")
	}
}

// Benchmark tests
func BenchmarkStateManagerGetConfig(b *testing.B) {
	manager := createTestStateManager()
	defer manager.Close()

	cfg := &config.Config{DryRun: false, Port: "8080"}
	manager.SetConfig(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GetConfig()
	}
}

func BenchmarkStateManagerSetConfig(b *testing.B) {
	manager := createTestStateManager()
	defer manager.Close()

	cfg := &config.Config{DryRun: false, Port: "8080"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.SetConfig(cfg)
	}
}

func BenchmarkBackoffManagerShouldSkip(b *testing.B) {
	bm := NewBackoffManager()
	testDir := "/test/benchmark"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bm.ShouldSkip(testDir)
	}
}

func BenchmarkStateManagerConcurrentAccess(b *testing.B) {
	manager := createTestStateManager()
	defer manager.Close()

	cfg := &config.Config{DryRun: false, Port: "8080"}
	manager.SetConfig(cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			manager.GetConfig()
			manager.ShouldWriteMetrics()
		}
	})
}
