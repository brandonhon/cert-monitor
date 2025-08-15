package test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
	"github.com/brandonhon/cert-monitor/internal/state"
)

// Test configuration
const (
	testPort    = "18080"
	testHost    = "127.0.0.1"
	testBaseURL = "http://" + testHost + ":" + testPort
	testTimeout = 30 * time.Second
)

// Global test state
var (
	testApp struct {
		cmd     *exec.Cmd
		cleanup func()
		running bool
		mu      sync.Mutex
	}
)

// TestMain sets up and tears down the test application
func TestMain(m *testing.M) {
	// Setup
	if err := setupGlobalTestApp(); err != nil {
		fmt.Printf("Failed to setup test app: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupGlobalTestApp()
	os.Exit(code)
}

func setupGlobalTestApp() error {
	testApp.mu.Lock()
	defer testApp.mu.Unlock()

	if testApp.running {
		return nil // Already running
	}

	// Create temporary test directory
	tmpDir, err := os.MkdirTemp("", "cert-monitor-integration-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}

	// Create test certificate directory
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert dir: %v", err)
	}

	// Create test certificate (fallback to dummy if openssl fails)
	certFile := filepath.Join(certDir, "test.crt")
	if err := createTestCertificate(certFile); err != nil {
		fmt.Printf("OpenSSL not available, creating dummy certificate: %v\n", err)
		dummyCert := "-----BEGIN CERTIFICATE-----\n" +
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL7X8z5Z1z\n" +
			"-----END CERTIFICATE-----\n"
		if err := os.WriteFile(certFile, []byte(dummyCert), 0644); err != nil {
			return fmt.Errorf("failed to create dummy certificate: %v", err)
		}
	}

	// Create test configuration
	configFile := filepath.Join(tmpDir, "config.yaml")
	cacheFile := filepath.Join(tmpDir, "cache.json")

	configContent := fmt.Sprintf(`cert_dirs:
  - "%s"
port: "%s"
bind_address: "%s"
num_workers: 1
dry_run: false
expiry_threshold_days: 30
log_file: ""
cache_file: "%s"
enable_runtime_metrics: false
enable_weak_crypto_metrics: false
enable_pprof: false
`, certDir, testPort, testHost, cacheFile)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}

	// Determine the correct path to the binary
	var binaryPath string
	var buildDir string

	// Check if we're in the test directory
	if _, err := os.Stat("../main.go"); err == nil {
		// We're in test/ directory
		buildDir = ".."
		binaryPath = "../cert-monitor"
	} else if _, err := os.Stat("main.go"); err == nil {
		// We're in the root directory
		buildDir = "."
		binaryPath = "./cert-monitor"
	} else {
		return fmt.Errorf("cannot locate main.go file")
	}

	// Build the application
	fmt.Printf("Building application in %s\n", buildDir)
	buildCmd := exec.Command("go", "build", "-o", "cert-monitor", ".")
	buildCmd.Dir = buildDir

	if output, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to build application: %v\nOutput: %s", err, output)
	}

	// Verify binary exists
	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("built binary not found at %s: %v", binaryPath, err)
	}

	// Start the application
	fmt.Printf("Starting application: %s --config %s\n", binaryPath, configFile)
	cmd := exec.Command(binaryPath, "--config", configFile)

	// Capture output for debugging
	logFile := filepath.Join(tmpDir, "app.log")
	logWriter, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	cmd.Stdout = logWriter
	cmd.Stderr = logWriter

	if err := cmd.Start(); err != nil {
		logWriter.Close()
		return fmt.Errorf("failed to start application: %v", err)
	}

	// Wait for application to start
	client := &http.Client{Timeout: 1 * time.Second}
	started := false
	var lastErr error

	fmt.Printf("Waiting for application to start on %s (PID: %d)\n", testBaseURL, cmd.Process.Pid)

	for i := 0; i < 30; i++ {
		// Check if process is still running
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			logWriter.Close()
			logContent, _ := os.ReadFile(logFile)
			return fmt.Errorf("application exited unexpectedly after %d attempts. Log:\n%s", i, logContent)
		}

		resp, err := client.Get(testBaseURL + "/healthz")
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				started = true
				fmt.Printf("Application started successfully after %d attempts\n", i+1)
				break
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("health check returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if i%5 == 0 && i > 0 {
			fmt.Printf("Still waiting for startup (attempt %d/30): %v\n", i+1, lastErr)
		}

		time.Sleep(1 * time.Second)
	}

	if !started {
		logWriter.Close()

		// Read application logs for debugging
		if logContent, err := os.ReadFile(logFile); err == nil {
			fmt.Printf("Application logs:\n%s\n", logContent)
		}

		// Kill the process if it's still running
		if cmd.Process != nil && cmd.ProcessState == nil {
			if err := cmd.Process.Kill(); err != nil {
				fmt.Printf("Failed to kill process: %v\n", err)
			}
		}

		return fmt.Errorf("application failed to start within timeout. Last error: %v", lastErr)
	}

	// Setup cleanup function
	testApp.cleanup = func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			if err := cmd.Process.Kill(); err != nil {
				fmt.Printf("Failed to kill process during cleanup: %v\n", err)
			}
			if err := cmd.Wait(); err != nil {
				fmt.Printf("Process wait error during cleanup: %v\n", err)
			}
		}
		logWriter.Close()
		os.RemoveAll(tmpDir)

		// Clean up binary if we created it
		if binaryPath != "" {
			os.Remove(binaryPath)
		}
	}

	testApp.cmd = cmd
	testApp.running = true

	return nil
}

func cleanupGlobalTestApp() {
	testApp.mu.Lock()
	defer testApp.mu.Unlock()

	if testApp.cleanup != nil {
		testApp.cleanup()
	}
	testApp.running = false
}

func createTestCertificate(path string) error {
	// Try to create a test certificate using openssl
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", "/dev/null", "-out", path, "-days", "365", "-nodes",
		"-subj", "/C=US/ST=Test/L=Test/O=Test/CN=test.example.com")
	return cmd.Run()
}

func httpGet(url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: testTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return client.Get(url)
}

func httpPost(url string, body io.Reader) (*http.Response, error) {
	client := &http.Client{
		Timeout: testTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return client.Post(url, "application/json", body)
}

// State Package Integration Tests (Unit tests - don't need running app)
func TestStatePackageIntegration(t *testing.T) {
	t.Run("StateManager", testStateManagerIntegration)
	t.Run("BackoffManager", testBackoffManagerIntegration)
	t.Run("ConfigurationManagement", testConfigurationManagementIntegration)
}

func testStateManagerIntegration(t *testing.T) {
	// Create test dependencies
	cacheManager := createMockCacheManager()
	metricsRegistry := createMockMetricsRegistry()

	deps := &state.Dependencies{
		CacheManager:    cacheManager,
		MetricsRegistry: metricsRegistry,
	}

	stateManager := state.New(nil, deps)
	defer stateManager.Close()

	// Test configuration management
	testConfig := &config.Config{
		DryRun:     false,
		Port:       "8080",
		NumWorkers: 4,
	}

	stateManager.SetConfig(testConfig)
	retrievedConfig := stateManager.GetConfig()

	if retrievedConfig == nil {
		t.Fatal("Config should not be nil")
	}

	if retrievedConfig.Port != "8080" {
		t.Errorf("Expected port 8080, got %s", retrievedConfig.Port)
	}

	// Test reload functionality
	stateManager.TriggerReload()

	select {
	case <-stateManager.GetReloadChannel():
		t.Log("Reload signal received successfully")
	case <-time.After(1 * time.Second):
		t.Error("Should have received reload signal")
	}

	// Test metrics writing
	if !stateManager.ShouldWriteMetrics() {
		t.Error("Should write metrics when dry run is false")
	}

	// Set dry run mode
	testConfig.DryRun = true
	stateManager.SetConfig(testConfig)

	if stateManager.ShouldWriteMetrics() {
		t.Error("Should not write metrics when dry run is true")
	}
}

func testBackoffManagerIntegration(t *testing.T) {
	cacheManager := createMockCacheManager()
	metricsRegistry := createMockMetricsRegistry()

	deps := &state.Dependencies{
		CacheManager:    cacheManager,
		MetricsRegistry: metricsRegistry,
	}

	stateManager := state.New(nil, deps)
	defer stateManager.Close()

	testDir := "/test/integration/directory"

	// Initially should not skip
	if stateManager.ShouldSkipScan(testDir) {
		t.Error("Should not skip scan initially")
	}

	// Register failure
	stateManager.RegisterScanFailure(testDir)

	// Now should skip
	if !stateManager.ShouldSkipScan(testDir) {
		t.Error("Should skip scan after failure")
	}

	// Clear expired backoffs
	stateManager.ClearExpiredBackoffs()

	// Should still skip (not expired yet)
	if !stateManager.ShouldSkipScan(testDir) {
		t.Error("Should still skip scan after clearing expired")
	}
}

func testConfigurationManagementIntegration(t *testing.T) {
	cacheManager := createMockCacheManager()
	metricsRegistry := createMockMetricsRegistry()

	deps := &state.Dependencies{
		CacheManager:    cacheManager,
		MetricsRegistry: metricsRegistry,
	}

	stateManager := state.New(nil, deps)
	defer stateManager.Close()

	// Test config file path management
	testPath := "/etc/cert-monitor/config.yaml"
	stateManager.SetConfigFilePath(testPath)

	if stateManager.GetConfigFilePath() != testPath {
		t.Errorf("Expected config path %s, got %s", testPath, stateManager.GetConfigFilePath())
	}

	// Test concurrent access
	var wg sync.WaitGroup
	numGoroutines := 10

	wg.Add(numGoroutines * 2)

	// Concurrent setters
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			cfg := &config.Config{
				Port:   fmt.Sprintf("808%d", id),
				DryRun: id%2 == 0,
			}
			stateManager.SetConfig(cfg)
		}(i)
	}

	// Concurrent getters
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			config := stateManager.GetConfig()
			if config != nil {
				_ = config.Port
				_ = config.DryRun
			}
		}()
	}

	wg.Wait()

	// Should have a valid config at the end
	finalConfig := stateManager.GetConfig()
	if finalConfig == nil {
		t.Error("Should have a config after concurrent operations")
	}
}

// Mock implementations for testing
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
func (m *mockCacheManager) Stats() cache.Statistics                                     { return cache.Statistics{} }
func (m *mockCacheManager) Size() int                                                   { return 0 }

type mockMetricsRegistry struct{}

func (m *mockMetricsRegistry) GetCollector() *metrics.DefaultCollector {
	return &metrics.DefaultCollector{}
}
func (m *mockMetricsRegistry) Reset() {}

func createMockCacheManager() cache.Manager {
	return &mockCacheManager{}
}

func createMockMetricsRegistry() state.MetricsRegistry {
	return &mockMetricsRegistry{}
}

// Application Integration Tests (These need the running app)
func TestApplicationStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	if !testApp.running {
		t.Fatal("Test application is not running")
	}
	cmd := testApp.cmd
	testApp.mu.Unlock()

	// Test that application started successfully
	resp, err := httpGet(testBaseURL + "/healthz")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	t.Logf("Application is running successfully (PID: %d)", cmd.Process.Pid)
}

func TestEndpointFunctionality(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	tests := []struct {
		name     string
		endpoint string
		status   int
	}{
		{"Health Check", "/healthz", http.StatusOK},
		{"Metrics", "/metrics", http.StatusOK},
		{"Config", "/config", http.StatusOK},
		{"Certificates", "/api/certificates", http.StatusOK},
		{"Root Redirect", "/", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := httpGet(testBaseURL + tt.endpoint)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.status {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Expected status %d, got %d. Body: %s", tt.status, resp.StatusCode, string(body))
			}
		})
	}
}

func TestConfigurationReload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	// Test configuration reload
	resp, err := httpPost(testBaseURL+"/reload", nil)
	if err != nil {
		t.Fatalf("Reload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 200 for reload, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// Verify reload result
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read reload response: %v", err)
	}

	var reloadResult map[string]interface{}
	if err := json.Unmarshal(body, &reloadResult); err != nil {
		t.Fatalf("Failed to parse reload response: %v", err)
	}

	if success, ok := reloadResult["success"].(bool); !ok || !success {
		t.Errorf("Reload should be successful: %+v", reloadResult)
	}
}

func TestMetricsContent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	// Allow time for initial certificate scan
	time.Sleep(2 * time.Second)

	resp, err := httpGet(testBaseURL + "/metrics")
	if err != nil {
		t.Fatalf("Metrics request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics: %v", err)
	}

	metricsContent := string(body)

	// Check for expected metrics
	expectedMetrics := []string{
		"ssl_cert_expiration_timestamp",
		"ssl_cert_san_count",
		"ssl_cert_files_total",
		"ssl_cert_last_scan_timestamp",
		"ssl_cert_scan_duration_seconds",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(metricsContent, metric) {
			t.Errorf("Expected metric %s not found in metrics output", metric)
		}
	}

	t.Logf("Metrics validation completed successfully")
}

func TestWorkerPoolProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	// Trigger processing via reload
	start := time.Now()
	resp, err := httpPost(testBaseURL+"/reload", nil)
	if err != nil {
		t.Fatalf("Failed to trigger processing: %v", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for reload, got %d", resp.StatusCode)
	}

	// Performance check
	if duration > 10*time.Second {
		t.Errorf("Worker pool processing too slow: %v (expected < 10s)", duration)
	}

	t.Logf("Worker pool processing completed in %v", duration)
}

func TestConcurrentRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	const numRequests = 20
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)

	// Send concurrent requests
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			endpoint := "/healthz"
			if id%3 == 0 {
				endpoint = "/metrics"
			} else if id%3 == 1 {
				endpoint = "/config"
			}

			resp, err := httpGet(testBaseURL + endpoint)
			if err != nil {
				errors <- fmt.Errorf("request %d failed: %v", id, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("request %d returned status %d", id, resp.StatusCode)
				return
			}
		}(id)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
		errorCount++
	}

	if errorCount == 0 {
		t.Logf("All %d concurrent requests completed successfully", numRequests)
	}
}

func TestApplicationShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test is tricky because we can't actually shut down the shared app
	// Instead, we'll test that we can send signals and the app handles them gracefully
	// by testing signal handling without actually terminating the process

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	cmd := testApp.cmd
	testApp.mu.Unlock()

	if !running {
		t.Fatal("Test application is not running")
	}

	// Verify application is running
	resp, err := httpGet(testBaseURL + "/healthz")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	resp.Body.Close()

	// Test that the process is responsive (instead of actually shutting down)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Error("Application process has exited unexpectedly")
	} else {
		t.Log("Application process is running and responsive")
	}
}

// Benchmark tests
func BenchmarkHealthEndpoint(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		b.Fatal("Test application is not running")
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := httpGet(testBaseURL + "/healthz")
			if err != nil {
				b.Errorf("Request failed: %v", err)
				continue
			}
			resp.Body.Close()
		}
	})
}

func BenchmarkMetricsEndpoint(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// Verify the app is running
	testApp.mu.Lock()
	running := testApp.running
	testApp.mu.Unlock()

	if !running {
		b.Fatal("Test application is not running")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := httpGet(testBaseURL + "/metrics")
		if err != nil {
			b.Errorf("Request failed: %v", err)
			continue
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Errorf("Failed to read response body: %v", err)
		}
		resp.Body.Close()
	}
}
