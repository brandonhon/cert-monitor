package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
)

// Mock implementations for testing
type mockCacheManager struct {
	stats cache.Statistics
}

func (m *mockCacheManager) Get(path string) (*cache.Entry, *cache.FileInfo, bool, error) {
	return nil, nil, false, nil
}

func (m *mockCacheManager) Set(path string, fingerprint [32]byte, info *cache.FileInfo) {}

func (m *mockCacheManager) Delete(path string) {}

func (m *mockCacheManager) Load(path string) error { return nil }

func (m *mockCacheManager) Save(path string) error { return nil }

func (m *mockCacheManager) Prune() int { return 0 }

func (m *mockCacheManager) Clear() {}

func (m *mockCacheManager) Stats() cache.Statistics {
	return m.stats
}

func (m *mockCacheManager) Size() int {
	return m.stats.TotalEntries
}

// Test helper functions
func createTestDependencies() *Dependencies {
	cfg := &config.Config{
		CertDirs:            []string{"/tmp"}, // Use /tmp which should exist and be accessible
		Port:                "3000",
		BindAddress:         "0.0.0.0",
		NumWorkers:          2,
		ExpiryThresholdDays: 30,
		LogFile:             "", // Empty log file to avoid write issues
		CacheFile:           "/tmp/test-cache.json",
	}

	metricsConfig := metrics.Config{
		EnableRuntimeMetrics:    true,
		EnableWeakCryptoMetrics: true,
		Registry:                nil,
	}
	metricsRegistry := metrics.NewRegistry(metricsConfig)

	cacheManager := &mockCacheManager{
		stats: cache.Statistics{
			TotalEntries:  10,
			CacheHits:     100,
			CacheMisses:   20,
			HitRate:       83.33,
			CacheFilePath: "/tmp/test-cache.json",
		},
	}

	reloadCh := make(chan struct{}, 1)

	return &Dependencies{
		Config:          cfg,
		MetricsRegistry: metricsRegistry,
		CacheManager:    cacheManager,
		ConfigFilePath:  "/tmp/test-config.yaml",
		ReloadChannel:   reloadCh,
	}
}

func createTestServer() *HTTPServer {
	config := &Config{
		Port:            "0", // Use random port for tests
		BindAddress:     "127.0.0.1",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		IdleTimeout:     10 * time.Second,
		ShutdownTimeout: 5 * time.Second,
	}

	deps := createTestDependencies()

	return &HTTPServer{
		config: *config,
		deps:   deps,
	}
}

// Test Server Configuration
func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "valid_config",
			config: Config{
				Port:            "3000",
				BindAddress:     "127.0.0.1",
				ReadTimeout:     30 * time.Second,
				WriteTimeout:    30 * time.Second,
				IdleTimeout:     60 * time.Second,
				ShutdownTimeout: 10 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty_port",
			config: Config{
				Port:        "",
				BindAddress: "127.0.0.1",
				ReadTimeout: 30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "empty_bind_address",
			config: Config{
				Port:        "3000",
				BindAddress: "",
				ReadTimeout: 30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "invalid_timeouts",
			config: Config{
				Port:        "3000",
				BindAddress: "127.0.0.1",
				ReadTimeout: 0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

// Test Health Handler
func TestHealthHandler(t *testing.T) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handlers.HealthHandler(w, req)

	// Debug: Print the response if it's not OK
	if w.Code != http.StatusOK {
		t.Logf("Health handler response code: %d", w.Code)
		t.Logf("Health handler response body: %s", w.Body.String())
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}

	if response.Status != "ok" {
		t.Errorf("Expected status 'ok', got %s", response.Status)
		t.Logf("Health check details: %+v", response.Checks)
	}

	// Check for expected health check fields
	expectedChecks := []string{
		"cert_scan_status",
		"cert_files_total",
		"certs_parsed_total",
		"cache_entries_total",
		"cache_hit_rate",
		"worker_pool_size",
		"certificate_directories",
	}

	for _, expected := range expectedChecks {
		if _, exists := response.Checks[expected]; !exists {
			t.Errorf("Missing expected health check: %s", expected)
		}
	}
}

// Test Certificates Handler
func TestCertsHandler(t *testing.T) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	req := httptest.NewRequest("GET", "/certs", nil)
	w := httptest.NewRecorder()

	handlers.CertsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Should return a valid JSON array (even if empty)
	var certificates []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &certificates); err != nil {
		t.Fatalf("Failed to decode certificates response: %v", err)
	}
}

// Test Reload Handler
func TestReloadHandler(t *testing.T) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	tests := []struct {
		name           string
		method         string
		expectStatus   int
		expectResponse bool
	}{
		{
			name:           "valid_post_request",
			method:         "POST",
			expectStatus:   http.StatusOK,
			expectResponse: true,
		},
		{
			name:         "invalid_get_request",
			method:       "GET",
			expectStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/reload", nil)
			w := httptest.NewRecorder()

			handlers.ReloadHandler(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, w.Code)
			}

			if tt.expectResponse {
				var response config.ReloadResult
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to decode reload response: %v", err)
				}

				if !response.Success {
					t.Error("Expected successful reload response")
				}
			}
		})
	}
}

// Test Config Status Handler
func TestConfigStatusHandler(t *testing.T) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	handlers.ConfigStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ConfigStatus
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to decode config status response: %v", err)
	}

	// Verify config values
	if response.Port != "3000" {
		t.Errorf("Expected port 3000, got %s", response.Port)
	}

	if response.NumWorkers != 2 {
		t.Errorf("Expected 2 workers, got %d", response.NumWorkers)
	}

	if response.ExpiryThresholdDays != 30 {
		t.Errorf("Expected 30 expiry threshold days, got %d", response.ExpiryThresholdDays)
	}

	// Check cache stats
	if response.CacheStats.TotalEntries != 10 {
		t.Errorf("Expected 10 cache entries, got %d", response.CacheStats.TotalEntries)
	}
}

// Test Server Start/Stop
func TestServerStartStop(t *testing.T) {
	server := createTestServer()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test server start
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Test server stop
	if err := server.Stop(ctx); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}
}

// Test Handler Registration
func TestHandlerRegistration(t *testing.T) {
	server := createTestServer()

	customHandlers := map[string]http.HandlerFunc{
		"/test": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		},
	}

	server.RegisterHandlers(customHandlers)

	// This test verifies the registration doesn't panic
	// In a real test environment, we'd verify the handler works
}

// Test Default Config
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Port != "3000" {
		t.Errorf("Expected default port 3000, got %s", config.Port)
	}

	if config.BindAddress != "0.0.0.0" {
		t.Errorf("Expected default bind address 0.0.0.0, got %s", config.BindAddress)
	}

	if config.ReadTimeout != 30*time.Second {
		t.Errorf("Expected default read timeout 30s, got %v", config.ReadTimeout)
	}

	if config.WriteTimeout != 30*time.Second {
		t.Errorf("Expected default write timeout 30s, got %v", config.WriteTimeout)
	}

	if config.IdleTimeout != 60*time.Second {
		t.Errorf("Expected default idle timeout 60s, got %v", config.IdleTimeout)
	}

	if config.ShutdownTimeout != 10*time.Second {
		t.Errorf("Expected default shutdown timeout 10s, got %v", config.ShutdownTimeout)
	}
}

// Test Server Info
func TestGetServerInfo(t *testing.T) {
	server := createTestServer()

	info := server.GetServerInfo()

	expectedFields := []string{
		"bind_address",
		"port",
		"tls_enabled",
		"pprof_enabled",
		"read_timeout",
		"write_timeout",
		"idle_timeout",
		"shutdown_timeout",
		"running",
	}

	for _, field := range expectedFields {
		if _, exists := info[field]; !exists {
			t.Errorf("Missing expected server info field: %s", field)
		}
	}

	// Check specific values
	if info["bind_address"] != "127.0.0.1" {
		t.Errorf("Expected bind_address 127.0.0.1, got %v", info["bind_address"])
	}

	if info["tls_enabled"] != false {
		t.Errorf("Expected tls_enabled false, got %v", info["tls_enabled"])
	}

	if info["running"] != false {
		t.Errorf("Expected running false, got %v", info["running"])
	}
}

// Test Root Handler
func TestRootHandler(t *testing.T) {
	server := createTestServer()

	tests := []struct {
		name         string
		path         string
		expectStatus int
		expectBody   string
	}{
		{
			name:         "root_path",
			path:         "/",
			expectStatus: http.StatusOK,
			expectBody:   "SSL Certificate Monitor",
		},
		{
			name:         "not_found_path",
			path:         "/nonexistent",
			expectStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			server.rootHandler(w, req)

			if w.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, w.Code)
			}

			if tt.expectBody != "" && !strings.Contains(w.Body.String(), tt.expectBody) {
				t.Errorf("Expected body to contain '%s', got '%s'", tt.expectBody, w.Body.String())
			}
		})
	}
}

// Benchmark tests
func BenchmarkHealthHandler(b *testing.B) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/healthz", nil)
		w := httptest.NewRecorder()
		handlers.HealthHandler(w, req)
	}
}

func BenchmarkCertsHandler(b *testing.B) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/certs", nil)
		w := httptest.NewRecorder()
		handlers.CertsHandler(w, req)
	}
}

// Test with TLS Configuration
func TestTLSConfiguration(t *testing.T) {
	config := &Config{
		Port:            "0",
		BindAddress:     "127.0.0.1",
		TLSCertFile:     "/path/to/cert.pem",
		TLSKeyFile:      "/path/to/key.pem",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Valid TLS config should not fail validation: %v", err)
	}

	// Test mismatched TLS config
	config.TLSKeyFile = ""
	if err := config.Validate(); err == nil {
		t.Error("Mismatched TLS config should fail validation")
	}
}

// Test Concurrent Access
func TestConcurrentHandlers(t *testing.T) {
	deps := createTestDependencies()
	handlers := NewHandlerSet(deps)

	const numRequests = 10
	done := make(chan bool, numRequests)

	// Launch concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/healthz", nil)
			w := httptest.NewRecorder()
			handlers.HealthHandler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Concurrent request failed with status %d", w.Code)
			}
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
}
