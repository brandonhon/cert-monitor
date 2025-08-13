package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// setupRoutes configures HTTP endpoints for the server
func (s *HTTPServer) setupRoutes() {
	handlers := NewHandlerSet(s.deps)

	// Core API endpoints
	http.Handle("/metrics", s.deps.MetricsRegistry.Handler())
	http.HandleFunc("/healthz", handlers.HealthHandler)
	http.HandleFunc("/certs", handlers.CertsHandler)
	http.HandleFunc("/reload", handlers.ReloadHandler)
	http.HandleFunc("/config", handlers.ConfigStatusHandler)

	// Add root handler for basic info
	http.HandleFunc("/", s.rootHandler)

	// Enable pprof endpoints if configured
	if s.config.EnablePprof {
		log.Info("pprof debug endpoints enabled at /debug/pprof/")
		// pprof endpoints are automatically registered via the import in main.go
	}

	log.WithFields(log.Fields{
		"endpoints": []string{"/metrics", "/healthz", "/certs", "/reload", "/config", "/"},
		"pprof":     s.config.EnablePprof,
	}).Info("HTTP routes configured successfully")
}

// rootHandler provides basic application information
func (s *HTTPServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	response := `SSL Certificate Monitor

Available endpoints:
- GET  /healthz  - Health check
- GET  /metrics  - Prometheus metrics
- GET  /certs    - Certificate information (JSON)
- GET  /config   - Configuration status
- POST /reload   - Trigger configuration reload

Documentation: https://github.com/brandonhon/cert-monitor
`

	if s.config.EnablePprof {
		response += `
Debug endpoints (pprof enabled):
- GET /debug/pprof/ - Profiling index
`
	}

	if _, err := w.Write([]byte(response)); err != nil {
		log.WithError(err).Error("Failed to write root handler response")
	}
}

// RegisterCustomHandlers allows registering additional custom handlers
func (s *HTTPServer) RegisterCustomHandlers(handlers map[string]http.HandlerFunc) {
	for path, handler := range handlers {
		http.HandleFunc(path, handler)
		log.WithField("path", path).Info("Registered custom HTTP handler")
	}
}
