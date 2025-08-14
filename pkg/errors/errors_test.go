package errors

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    interface{}
		reason   string
		expected string
	}{
		{
			name:     "string_value",
			field:    "port",
			value:    "invalid",
			reason:   "must be a number",
			expected: "validation failed for field 'port': must be a number (value: invalid)",
		},
		{
			name:     "numeric_value",
			field:    "num_workers",
			value:    -1,
			reason:   "must be positive",
			expected: "validation failed for field 'num_workers': must be positive (value: -1)",
		},
		{
			name:     "nil_value",
			field:    "cert_dirs",
			value:    nil,
			reason:   "cannot be nil",
			expected: "validation failed for field 'cert_dirs': cannot be nil (value: <nil>)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewValidationError(tt.field, tt.value, tt.reason)
			if err.Error() != tt.expected {
				t.Errorf("Expected: %s, Got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestProcessingError(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		operation string
		cause     error
		expected  string
	}{
		{
			name:      "file_not_found",
			path:      "/path/to/cert.pem",
			operation: "parse",
			cause:     fmt.Errorf("file not found"),
			expected:  "parse failed for /path/to/cert.pem: file not found",
		},
		{
			name:      "permission_denied",
			path:      "/etc/ssl/private/key.pem",
			operation: "read",
			cause:     fmt.Errorf("permission denied"),
			expected:  "read failed for /etc/ssl/private/key.pem: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProcessingError(tt.path, tt.operation, tt.cause)
			if err.Error() != tt.expected {
				t.Errorf("Expected: %s, Got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestCacheError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		key       string
		cause     error
		expected  string
	}{
		{
			name:      "get_timeout",
			operation: "get",
			key:       "cert-123",
			cause:     fmt.Errorf("connection timeout"),
			expected:  "cache get failed for key 'cert-123': connection timeout",
		},
		{
			name:      "set_full",
			operation: "set",
			key:       "cert-456",
			cause:     fmt.Errorf("cache full"),
			expected:  "cache set failed for key 'cert-456': cache full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewCacheError(tt.operation, tt.key, tt.cause)
			if err.Error() != tt.expected {
				t.Errorf("Expected: %s, Got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestServerError(t *testing.T) {
	tests := []struct {
		name      string
		component string
		action    string
		cause     error
		expected  string
	}{
		{
			name:      "handler_panic",
			component: "http",
			action:    "request handling",
			cause:     fmt.Errorf("panic: runtime error"),
			expected:  "server http error during request handling: panic: runtime error",
		},
		{
			name:      "tls_setup",
			component: "tls",
			action:    "certificate loading",
			cause:     fmt.Errorf("invalid certificate"),
			expected:  "server tls error during certificate loading: invalid certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewServerError(tt.component, tt.action, tt.cause)
			if err.Error() != tt.expected {
				t.Errorf("Expected: %s, Got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestErrorTypeImplementsError(t *testing.T) {
	// Test that all error types implement the error interface
	var _ error = &ValidationError{}
	var _ error = &ProcessingError{}
	var _ error = &CacheError{}
	var _ error = &ServerError{}
}

func TestErrorFieldAccess(t *testing.T) {
	// Test that we can access fields for programmatic error handling
	valErr := NewValidationError("test_field", "test_value", "test_reason")
	if valErr.Field != "test_field" {
		t.Errorf("Expected field 'test_field', got '%s'", valErr.Field)
	}

	procErr := NewProcessingError("/test/path", "test_op", fmt.Errorf("test"))
	if procErr.Path != "/test/path" {
		t.Errorf("Expected path '/test/path', got '%s'", procErr.Path)
	}

	cacheErr := NewCacheError("test_op", "test_key", fmt.Errorf("test"))
	if cacheErr.Key != "test_key" {
		t.Errorf("Expected key 'test_key', got '%s'", cacheErr.Key)
	}

	servErr := NewServerError("test_comp", "test_action", fmt.Errorf("test"))
	if servErr.Component != "test_comp" {
		t.Errorf("Expected component 'test_comp', got '%s'", servErr.Component)
	}
}

func TestErrorStringFormat(t *testing.T) {
	// Test that errors contain expected key information
	valErr := NewValidationError("port", 99999, "out of range")
	errStr := valErr.Error()

	expectedParts := []string{"validation failed", "port", "out of range", "99999"}
	for _, part := range expectedParts {
		if !strings.Contains(errStr, part) {
			t.Errorf("Error string '%s' should contain '%s'", errStr, part)
		}
	}
}
