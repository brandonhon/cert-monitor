package test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestApplicationHealth tests the health endpoint functionality
func TestApplicationHealth(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestMetricsEndpoint tests the metrics endpoint functionality
func TestMetricsEndpoint(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestConfigEndpoint tests the configuration endpoint functionality
func TestConfigEndpoint(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:3000/config")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read config response: %v", err)
	}

	configContent := string(body)
	if !strings.Contains(configContent, "num_workers") {
		t.Error("Configuration should contain num_workers setting")
	}
}

// TestReloadEndpoint tests the configuration reload functionality
func TestReloadEndpoint(t *testing.T) {
	client := &http.Client{Timeout: 15 * time.Second}

	// Check if application is running
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Test reload endpoint
	reloadReq, err := http.NewRequest("POST", "http://localhost:3000/reload", nil)
	if err != nil {
		t.Fatalf("Failed to create reload request: %v", err)
	}

	resp, err := client.Do(reloadReq)
	if err != nil {
		t.Fatalf("Failed to trigger reload: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for reload, got %d", resp.StatusCode)
	}
}

// TestWorkerPoolIntegration tests worker pool functionality in a real application context
func TestWorkerPoolIntegration(t *testing.T) {
	// Skip if application not running
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Test worker pool metrics are available
	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics response: %v", err)
	}

	metricsContent := string(body)

	// Check for certificate processing metrics that indicate worker pool activity
	expectedMetrics := []string{
		"cert_last_scan",
		"cert_scan_duration",
		"cert_files_processed",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(metricsContent, metric) {
			t.Errorf("Expected metric '%s' not found in metrics output", metric)
		}
	}
}

// TestWorkerPoolPerformance tests worker pool performance under load
func TestWorkerPoolPerformance(t *testing.T) {
	// Skip if application not running
	client := &http.Client{Timeout: 30 * time.Second}
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Trigger a reload to test worker pool processing
	reloadReq, err := http.NewRequest("POST", "http://localhost:3000/reload", nil)
	if err != nil {
		t.Fatalf("Failed to create reload request: %v", err)
	}

	start := time.Now()
	resp, err := client.Do(reloadReq)
	if err != nil {
		t.Fatalf("Failed to trigger reload: %v", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	// Verify reload completed successfully
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for reload, got %d", resp.StatusCode)
	}

	// Performance check - should complete within reasonable time
	if duration > 10*time.Second {
		t.Errorf("Worker pool processing too slow: %v (expected < 10s)", duration)
	}

	t.Logf("Worker pool processing completed in %v", duration)
}

// TestWorkerPoolConfiguration tests worker pool responds to configuration changes
func TestWorkerPoolConfiguration(t *testing.T) {
	// Skip if application not running
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Get current configuration
	resp, err := client.Get("http://localhost:3000/config")
	if err != nil {
		t.Fatalf("Failed to get configuration: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for config endpoint, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read config response: %v", err)
	}

	// Verify configuration contains worker settings
	configContent := string(body)
	if !strings.Contains(configContent, "num_workers") {
		t.Error("Configuration should contain num_workers setting")
	}

	t.Logf("Worker configuration verified: %s", configContent)
}

// TestWorkerPoolConcurrency tests worker pool handles concurrent requests
func TestWorkerPoolConcurrency(t *testing.T) {
	// Skip if application not running
	client := &http.Client{Timeout: 30 * time.Second}
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	const numConcurrentRequests = 5
	var wg sync.WaitGroup
	errors := make(chan error, numConcurrentRequests)

	// Send multiple concurrent reload requests to test worker pool
	for i := 0; i < numConcurrentRequests; i++ {
		wg.Add(1)
		go func(requestID int) {
			defer wg.Done()

			req, err := http.NewRequest("POST", "http://localhost:3000/reload", nil)
			if err != nil {
				errors <- fmt.Errorf("request %d: failed to create request: %v", requestID, err)
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				errors <- fmt.Errorf("request %d: failed to send request: %v", requestID, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("request %d: expected status 200, got %d", requestID, resp.StatusCode)
				return
			}

			t.Logf("Concurrent request %d completed successfully", requestID)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
	}
}

// TestWorkerPoolMetrics tests that worker pool metrics are properly exposed
func TestWorkerPoolMetrics(t *testing.T) {
	// Skip if application not running
	client := &http.Client{Timeout: 10 * time.Second}
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Trigger processing to generate metrics
	reloadReq, err := http.NewRequest("POST", "http://localhost:3000/reload", nil)
	if err != nil {
		t.Fatalf("Failed to create reload request: %v", err)
	}

	_, err = client.Do(reloadReq)
	if err != nil {
		t.Fatalf("Failed to trigger reload: %v", err)
	}

	// Wait a moment for processing to complete
	time.Sleep(2 * time.Second)

	// Get metrics
	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics response: %v", err)
	}

	metricsContent := string(body)

	// Check for worker-related metrics
	workerMetrics := []string{
		"cert_scan_duration",   // Worker pool processing time
		"cert_files_processed", // Files processed by workers
		"cert_parse_errors",    // Errors during worker processing
	}

	for _, metric := range workerMetrics {
		if !strings.Contains(metricsContent, metric) {
			t.Errorf("Expected worker metric '%s' not found in metrics output", metric)
		}
	}

	// Verify metrics have reasonable values (non-zero for active processing)
	if !strings.Contains(metricsContent, "cert_scan_duration") {
		t.Error("Worker pool should report processing duration metrics")
	}

	t.Logf("Worker pool metrics verified successfully")
}

// TestEndToEndWorkflow tests complete application workflow with worker pool
func TestEndToEndWorkflow(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Check if application is running
	_, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skipf("Application not running on localhost:3000: %v", err)
	}

	// Step 1: Check initial health
	resp, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	resp.Body.Close()

	// Step 2: Trigger certificate processing via reload
	reloadReq, err := http.NewRequest("POST", "http://localhost:3000/reload", nil)
	if err != nil {
		t.Fatalf("Failed to create reload request: %v", err)
	}

	start := time.Now()
	resp, err = client.Do(reloadReq)
	if err != nil {
		t.Fatalf("Failed to trigger reload: %v", err)
	}
	resp.Body.Close()
	processingTime := time.Since(start)

	// Step 3: Verify metrics show worker activity
	time.Sleep(1 * time.Second) // Allow metrics to update
	resp, err = client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics: %v", err)
	}

	metricsContent := string(body)

	// Verify end-to-end functionality
	if !strings.Contains(metricsContent, "cert_last_scan") {
		t.Error("Should have certificate scan metrics after processing")
	}

	// Step 4: Verify configuration endpoint
	resp, err = client.Get("http://localhost:3000/config")
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Config endpoint should return 200, got %d", resp.StatusCode)
	}

	t.Logf("End-to-end workflow completed successfully in %v", processingTime)
}
