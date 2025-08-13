package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// HTTPServer implements the Server interface
type HTTPServer struct {
	server *http.Server
	config Config
	deps   *Dependencies
}

// New creates a new HTTP server with the given configuration and dependencies
func New(config *Config, deps *Dependencies) Server {
	return &HTTPServer{
		config: *config,
		deps:   deps,
	}
}

// Start starts the HTTP server
func (s *HTTPServer) Start(ctx context.Context) error {
	// Setup HTTP routes
	s.setupRoutes()

	// Create HTTP server
	s.server = &http.Server{
		Addr:         s.config.BindAddress + ":" + s.config.Port,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		defer log.Info("HTTP server goroutine shutting down")

		log.WithFields(log.Fields{
			"address":     s.server.Addr,
			"tls_enabled": s.config.TLSCertFile != "" && s.config.TLSKeyFile != "",
		}).Info("Starting HTTP server")

		var err error
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("HTTP server failed")
		}
	}()

	// Wait a moment to ensure server starts
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop gracefully stops the HTTP server
func (s *HTTPServer) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	log.Info("Shutting down HTTP server gracefully")

	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Warn("HTTP server shutdown error")
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	log.Info("HTTP server shut down successfully")
	return nil
}

// Handler returns the HTTP handler (for testing or advanced use)
func (s *HTTPServer) Handler() http.Handler {
	if s.server != nil {
		return s.server.Handler
	}
	return http.DefaultServeMux
}

// RegisterHandlers allows registering additional handlers
func (s *HTTPServer) RegisterHandlers(handlers map[string]http.HandlerFunc) {
	s.RegisterCustomHandlers(handlers)
}

// GetServerInfo returns information about the server
func (s *HTTPServer) GetServerInfo() map[string]interface{} {
	info := map[string]interface{}{
		"bind_address":     s.config.BindAddress,
		"port":             s.config.Port,
		"tls_enabled":      s.config.TLSCertFile != "" && s.config.TLSKeyFile != "",
		"pprof_enabled":    s.config.EnablePprof,
		"read_timeout":     s.config.ReadTimeout.String(),
		"write_timeout":    s.config.WriteTimeout.String(),
		"idle_timeout":     s.config.IdleTimeout.String(),
		"shutdown_timeout": s.config.ShutdownTimeout.String(),
	}

	if s.server != nil {
		info["server_addr"] = s.server.Addr
		info["running"] = true
	} else {
		info["running"] = false
	}

	return info
}

// Validate validates the server configuration
func (c *Config) Validate() error {
	if c.Port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	if c.BindAddress == "" {
		return fmt.Errorf("bind address cannot be empty")
	}

	// Validate TLS configuration
	if (c.TLSCertFile != "") != (c.TLSKeyFile != "") {
		return fmt.Errorf("both TLS certificate and key files must be specified together")
	}

	// Validate timeouts
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}

	if c.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}

	if c.IdleTimeout <= 0 {
		return fmt.Errorf("idle timeout must be positive")
	}

	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}

	return nil
}
