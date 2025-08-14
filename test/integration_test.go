package test

import (
	"net/http"
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
