package test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ExpectedMetric represents a metric that should be present
type ExpectedMetric struct {
	Name        string
	Type        string // gauge, counter, histogram
	Description string
	Required    bool // true if metric must be present, false if optional
}

// MetricValue represents a parsed metric value
type MetricValue struct {
	Name   string
	Labels map[string]string
	Value  float64
	Type   string
}

// expectedMetrics defines all metrics that should be present in the application
var expectedMetrics = []ExpectedMetric{
	// Core certificate metrics
	{
		Name:        "ssl_cert_expiration_timestamp",
		Type:        "gauge",
		Description: "Expiration time of SSL cert (Unix timestamp)",
		Required:    true,
	},
	{
		Name:        "ssl_cert_san_count",
		Type:        "gauge",
		Description: "Number of SAN entries in cert",
		Required:    true,
	},
	{
		Name:        "ssl_cert_info",
		Type:        "gauge",
		Description: "Static info for cert including CN and SANs",
		Required:    true,
	},
	{
		Name:        "ssl_cert_duplicate_count",
		Type:        "gauge",
		Description: "Number of times a cert appears",
		Required:    true,
	},
	{
		Name:        "ssl_cert_issuer_code",
		Type:        "gauge",
		Description: "Numeric code based on certificate issuer",
		Required:    true,
	},

	// Processing metrics
	{
		Name:        "ssl_cert_parse_errors_total",
		Type:        "counter",
		Description: "Number of cert parse errors",
		Required:    true,
	},
	{
		Name:        "ssl_cert_files_total",
		Type:        "counter",
		Description: "Total number of certificate files processed",
		Required:    true,
	},
	{
		Name:        "ssl_certs_parsed_total",
		Type:        "counter",
		Description: "Total number of individual certificates successfully parsed",
		Required:    true,
	},
	{
		Name:        "ssl_cert_last_scan_timestamp",
		Type:        "gauge",
		Description: "Unix timestamp of the last successful scan",
		Required:    true,
	},
	{
		Name:        "ssl_cert_scan_duration_seconds",
		Type:        "histogram",
		Description: "Duration of certificate directory scans in seconds",
		Required:    true,
	},

	// Security metrics
	{
		Name:        "ssl_cert_weak_key_total",
		Type:        "counter",
		Description: "Total number of certificates detected with weak keys",
		Required:    false, // Optional, depends on EnableWeakCryptoMetrics
	},
	{
		Name:        "ssl_cert_deprecated_sigalg_total",
		Type:        "counter",
		Description: "Total number of certificates with deprecated signature algorithms",
		Required:    false, // Optional, depends on EnableWeakCryptoMetrics
	},

	// Application metrics
	{
		Name:        "ssl_cert_last_reload_timestamp",
		Type:        "gauge",
		Description: "Unix timestamp of the last successful configuration reload",
		Required:    true,
	},
	{
		Name:        "ssl_monitor_heap_alloc_bytes",
		Type:        "gauge",
		Description: "Heap memory allocated (bytes)",
		Required:    false, // Optional, depends on EnableRuntimeMetrics
	},
}

// TestBasicFunctionality tests basic certificate monitoring functionality
func TestBasicFunctionality(t *testing.T) {
	// Skip if no test certificates are available
	testCertsDir := "../test-certs"
	if _, err := os.Stat(testCertsDir); os.IsNotExist(err) {
		t.Skip("Test certificates not found. Run scripts/generate-test-certs.sh first")
	}

	// This test would require the application to be running
	// For now, it's a placeholder for integration tests
	t.Log("Basic functionality test placeholder")
}

// TestAllMetricsPresent tests that all expected metrics are present and properly formatted
func TestAllMetricsPresent(t *testing.T) {
	// Test assumes the application is running on localhost:3000
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Skip("Application not running on localhost:3000, skipping metrics test")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Parse metrics response
	metrics, err := parsePrometheusMetrics(resp)
	if err != nil {
		t.Fatalf("Failed to parse metrics: %v", err)
	}

	t.Logf("Parsed %d total metrics", len(metrics))

	// Check each expected metric
	foundMetrics := make(map[string]bool)
	var missingRequired []string
	var foundOptional []string

	for _, expected := range expectedMetrics {
		found := false
		for _, metric := range metrics {
			if strings.HasPrefix(metric.Name, expected.Name) {
				found = true
				foundMetrics[expected.Name] = true

				// Validate metric type if we can determine it
				if expected.Type == "counter" && !strings.HasSuffix(metric.Name, "_total") && !strings.Contains(metric.Name, "_bucket") {
					t.Logf("Warning: Counter metric %s doesn't end with _total", metric.Name)
				}

				// Log some details about the metric
				if len(metric.Labels) > 0 {
					t.Logf("Found metric %s with labels: %v, value: %f", metric.Name, metric.Labels, metric.Value)
				} else {
					t.Logf("Found metric %s with value: %f", metric.Name, metric.Value)
				}
				break
			}
		}

		if !found {
			if expected.Required {
				missingRequired = append(missingRequired, expected.Name)
			} else {
				t.Logf("Optional metric %s not found (may be disabled)", expected.Name)
			}
		} else if !expected.Required {
			foundOptional = append(foundOptional, expected.Name)
		}
	}

	// Report results
	if len(missingRequired) > 0 {
		t.Errorf("Missing required metrics: %v", missingRequired)
	}

	if len(foundOptional) > 0 {
		t.Logf("Found optional metrics: %v", foundOptional)
	}

	t.Logf("Metrics validation summary:")
	t.Logf("- Required metrics found: %d/%d", len(foundMetrics)-len(foundOptional), countRequiredMetrics())
	t.Logf("- Optional metrics found: %d", len(foundOptional))
	t.Logf("- Missing required: %d", len(missingRequired))
}

// TestMetricValues tests that metrics have reasonable values
func TestMetricValues(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Skip("Application not running on localhost:3000, skipping metric values test")
		return
	}
	defer resp.Body.Close()

	metrics, err := parsePrometheusMetrics(resp)
	if err != nil {
		t.Fatalf("Failed to parse metrics: %v", err)
	}

	// Test specific metric value constraints
	for _, metric := range metrics {
		switch {
		case strings.HasPrefix(metric.Name, "ssl_cert_expiration_timestamp"):
			// Should be a Unix timestamp in the future (or reasonable past)
			now := time.Now().Unix()
			if metric.Value < float64(now-86400*365*10) || metric.Value > float64(now+86400*365*10) {
				t.Errorf("Suspicious expiration timestamp for %s: %f (current: %d)", metric.Name, metric.Value, now)
			}

		case strings.HasPrefix(metric.Name, "ssl_cert_san_count"):
			// SAN count should be reasonable (0-100)
			if metric.Value < 0 || metric.Value > 100 {
				t.Errorf("Suspicious SAN count for %s: %f", metric.Name, metric.Value)
			}

		case strings.HasPrefix(metric.Name, "ssl_cert_duplicate_count"):
			// Duplicate count should be positive
			if metric.Value < 1 {
				t.Errorf("Invalid duplicate count for %s: %f", metric.Name, metric.Value)
			}

		case strings.HasPrefix(metric.Name, "ssl_cert_issuer_code"):
			// Issuer codes should be in known range (30-33)
			if metric.Value < 30 || metric.Value > 33 {
				t.Logf("Note: Unusual issuer code for %s: %f", metric.Name, metric.Value)
			}

		case strings.HasSuffix(metric.Name, "_total"):
			// Counters should be non-negative
			if metric.Value < 0 {
				t.Errorf("Negative counter value for %s: %f", metric.Name, metric.Value)
			}

		case strings.HasPrefix(metric.Name, "ssl_cert_last_scan_timestamp"):
			// Last scan should be recent (within last hour)
			now := time.Now().Unix()
			if metric.Value > 0 && metric.Value < float64(now-3600) {
				t.Logf("Note: Last scan timestamp seems old for %s: %f (current: %d)", metric.Name, metric.Value, now)
			}
		}
	}
}

// TestMetricLabels tests that metrics have expected labels
func TestMetricLabels(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Skip("Application not running on localhost:3000, skipping metric labels test")
		return
	}
	defer resp.Body.Close()

	metrics, err := parsePrometheusMetrics(resp)
	if err != nil {
		t.Fatalf("Failed to parse metrics: %v", err)
	}

	// Define expected labels for each metric type
	expectedLabels := map[string][]string{
		"ssl_cert_expiration_timestamp":    {"common_name", "filename"},
		"ssl_cert_san_count":               {"common_name", "filename"},
		"ssl_cert_info":                    {"common_name", "filename", "sans"},
		"ssl_cert_duplicate_count":         {"common_name", "filename"},
		"ssl_cert_issuer_code":             {"common_name", "filename"},
		"ssl_cert_parse_errors_total":      {"filename"},
		"ssl_cert_files_total":             {"dir"},
		"ssl_certs_parsed_total":           {"dir"},
		"ssl_cert_last_scan_timestamp":     {"dir"},
		"ssl_cert_scan_duration_seconds":   {"dir"},
		"ssl_cert_weak_key_total":          {"common_name", "filename"},
		"ssl_cert_deprecated_sigalg_total": {"common_name", "filename"},
	}

	// Check labels for each metric
	for _, metric := range metrics {
		for metricPrefix, requiredLabels := range expectedLabels {
			if strings.HasPrefix(metric.Name, metricPrefix) {
				// Check that required labels are present
				for _, requiredLabel := range requiredLabels {
					if _, exists := metric.Labels[requiredLabel]; !exists {
						t.Errorf("Metric %s missing required label: %s", metric.Name, requiredLabel)
					}
				}

				// Log label information for debugging
				if len(metric.Labels) > 0 {
					t.Logf("Metric %s has labels: %v", metric.Name, metric.Labels)
				}
				break
			}
		}
	}
}

// TestMetricsEndpoint tests the metrics endpoint availability
func TestMetricsEndpoint(t *testing.T) {
	// This test assumes the application is running on localhost:3000
	// In a real test environment, you'd start the application in the test
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:3000/metrics")
	if err != nil {
		t.Skip("Application not running on localhost:3000, skipping endpoint test")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Logf("Content-Type: %s (may vary based on Prometheus version)", contentType)
	}

	// Check that we got some metrics
	scanner := bufio.NewScanner(resp.Body)
	lineCount := 0
	metricCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Count actual metric lines (not comments or empty lines)
		if line != "" && !strings.HasPrefix(line, "#") {
			metricCount++
		}
	}

	t.Logf("Metrics endpoint returned %d lines with %d actual metrics", lineCount, metricCount)

	if metricCount == 0 {
		t.Error("No metrics found in response")
	}
}

// TestHealthEndpoint tests the health check endpoint
func TestHealthEndpoint(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("http://localhost:3000/healthz")
	if err != nil {
		t.Skip("Application not running on localhost:3000, skipping health test")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Parse health response
	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Errorf("Failed to decode health response: %v", err)
		return
	}

	// Check required fields
	if status, ok := health["status"].(string); !ok || status != "ok" {
		t.Errorf("Expected status 'ok', got %v", health["status"])
	}

	if checks, ok := health["checks"].(map[string]interface{}); ok {
		t.Logf("Health checks: %v", checks)

		// Check for expected health check fields
		expectedChecks := []string{
			"cert_scan_status",
			"cert_files_total",
			"certs_parsed_total",
			"cache_entries_total",
			"cache_hit_rate",
		}

		for _, expected := range expectedChecks {
			if _, exists := checks[expected]; !exists {
				t.Errorf("Missing expected health check: %s", expected)
			}
		}
	}
}

// parsePrometheusMetrics parses Prometheus metrics format
func parsePrometheusMetrics(resp *http.Response) ([]MetricValue, error) {
	var metrics []MetricValue
	scanner := bufio.NewScanner(resp.Body)

	// Regular expressions for parsing metrics
	metricRegex := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*?)(\{[^}]*\})?\s+([+-]?[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?)`)
	labelRegex := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse metric line
		matches := metricRegex.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		metricName := matches[1]
		labelsStr := matches[2]
		valueStr := matches[3]

		// Parse value
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}

		// Parse labels
		labels := make(map[string]string)
		if labelsStr != "" {
			labelMatches := labelRegex.FindAllStringSubmatch(labelsStr, -1)
			for _, labelMatch := range labelMatches {
				if len(labelMatch) >= 3 {
					labels[labelMatch[1]] = labelMatch[2]
				}
			}
		}

		metrics = append(metrics, MetricValue{
			Name:   metricName,
			Labels: labels,
			Value:  value,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading metrics: %w", err)
	}

	return metrics, nil
}

// countRequiredMetrics counts how many metrics are marked as required
func countRequiredMetrics() int {
	count := 0
	for _, metric := range expectedMetrics {
		if metric.Required {
			count++
		}
	}
	return count
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
	}{
		{
			name: "valid_config",
			config: map[string]interface{}{
				"cert_dirs":             []string{"/tmp"},
				"port":                  "3000",
				"bind_address":          "0.0.0.0",
				"num_workers":           4,
				"expiry_threshold_days": 30,
			},
			expectError: false,
		},
		{
			name: "invalid_port",
			config: map[string]interface{}{
				"cert_dirs":    []string{"/tmp"},
				"port":         "invalid",
				"bind_address": "0.0.0.0",
				"num_workers":  4,
			},
			expectError: true,
		},
		{
			name: "empty_cert_dirs",
			config: map[string]interface{}{
				"cert_dirs":    []string{},
				"port":         "3000",
				"bind_address": "0.0.0.0",
				"num_workers":  4,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would test the actual config validation logic
			// Placeholder for config validation tests
			t.Logf("Testing config: %v", tt.config)
		})
	}
}

// TestCertificateFormats tests different certificate file formats
func TestCertificateFormats(t *testing.T) {
	testCases := []struct {
		filename string
		format   string
	}{
		{"test.pem", "PEM"},
		{"test.crt", "CRT"},
		{"test.cer", "CER"},
		{"test.der", "DER"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("format_%s", tc.format), func(t *testing.T) {
			// Test certificate format detection
			ext := filepath.Ext(tc.filename)
			t.Logf("Testing format %s with extension %s", tc.format, ext)

			// This would test the actual format detection logic
			// Placeholder for format detection tests
		})
	}
}

// BenchmarkCertificateProcessing benchmarks certificate processing performance
func BenchmarkCertificateProcessing(b *testing.B) {
	// Skip if no test certificates
	testCertsDir := "../test-certs"
	if _, err := os.Stat(testCertsDir); os.IsNotExist(err) {
		b.Skip("Test certificates not found")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Benchmark certificate processing
		// This would test the actual certificate processing logic
		b.Logf("Benchmark iteration %d", i)
	}
}

// TestCachePerformance tests certificate caching functionality
func TestCachePerformance(t *testing.T) {
	// Test cache hit/miss ratios
	// This would test the actual caching logic
	t.Log("Cache performance test placeholder")
}

// TestErrorHandling tests error handling scenarios
func TestErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		scenario    string
		expectError bool
	}{
		{
			name:        "nonexistent_directory",
			scenario:    "Directory does not exist",
			expectError: true,
		},
		{
			name:        "invalid_certificate",
			scenario:    "Invalid certificate file",
			expectError: true,
		},
		{
			name:        "permission_denied",
			scenario:    "Permission denied on directory",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing error scenario: %s", tc.scenario)
			// This would test actual error handling logic
		})
	}
}
