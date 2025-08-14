package errors

import "fmt"

// ValidationError represents configuration or input validation failures
type ValidationError struct {
	Field  string
	Value  interface{}
	Reason string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s (value: %v)",
		e.Field, e.Reason, e.Value)
}

// ProcessingError represents certificate processing failures
type ProcessingError struct {
	Path      string
	Operation string
	Cause     error
}

func (e ProcessingError) Error() string {
	return fmt.Sprintf("%s failed for %s: %v", e.Operation, e.Path, e.Cause)
}

// CacheError represents cache operation failures
type CacheError struct {
	Operation string
	Key       string
	Cause     error
}

func (e CacheError) Error() string {
	return fmt.Sprintf("cache %s failed for key '%s': %v", e.Operation, e.Key, e.Cause)
}

// ServerError represents HTTP server operation failures
type ServerError struct {
	Component string
	Action    string
	Cause     error
}

func (e ServerError) Error() string {
	return fmt.Sprintf("server %s error during %s: %v", e.Component, e.Action, e.Cause)
}

// NewValidationError creates a new validation error
func NewValidationError(field string, value interface{}, reason string) *ValidationError {
	return &ValidationError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}
}

// NewProcessingError creates a new processing error
func NewProcessingError(path, operation string, cause error) *ProcessingError {
	return &ProcessingError{
		Path:      path,
		Operation: operation,
		Cause:     cause,
	}
}

// NewCacheError creates a new cache error
func NewCacheError(operation, key string, cause error) *CacheError {
	return &CacheError{
		Operation: operation,
		Key:       key,
		Cause:     cause,
	}
}

// NewServerError creates a new server error
func NewServerError(component, action string, cause error) *ServerError {
	return &ServerError{
		Component: component,
		Action:    action,
		Cause:     cause,
	}
}
