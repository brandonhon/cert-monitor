package server

import (
	"context"
	"net/http"
	"time"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
)

// Server defines the interface for HTTP server management
type Server interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Handler() http.Handler
	RegisterHandlers(handlers map[string]http.HandlerFunc)
}

// Config holds HTTP server configuration
type Config struct {
	Port            string
	BindAddress     string
	TLSCertFile     string
	TLSKeyFile      string
	EnablePprof     bool
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Dependencies holds the server's dependencies
type Dependencies struct {
	Config          *config.Config
	MetricsRegistry *metrics.Registry
	CacheManager    cache.Manager
	ConfigFilePath  string
	ReloadChannel   chan struct{}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// ConfigStatus represents the configuration status response
type ConfigStatus struct {
	ConfigFile          string     `json:"config_file"`
	HotReloadEnabled    bool       `json:"hot_reload_enabled"`
	CertificateDirs     []string   `json:"certificate_dirs"`
	NumWorkers          int        `json:"num_workers"`
	Port                string     `json:"port"`
	BindAddress         string     `json:"bind_address"`
	ExpiryThresholdDays int        `json:"expiry_threshold_days"`
	RuntimeMetrics      bool       `json:"runtime_metrics_enabled"`
	WeakCryptoMetrics   bool       `json:"weak_crypto_metrics_enabled"`
	PprofEnabled        bool       `json:"pprof_enabled"`
	CacheFile           string     `json:"cache_file"`
	ClearCacheOnReload  bool       `json:"clear_cache_on_reload"`
	TLSEnabled          bool       `json:"tls_enabled"`
	LastReloadTime      string     `json:"last_reload_time,omitempty"`
	CacheStats          CacheStats `json:"cache_stats"`
}

// CacheStats represents cache statistics for monitoring
type CacheStats struct {
	TotalEntries  int     `json:"total_entries"`
	CacheFilePath string  `json:"cache_file_path"`
	HitRate       float64 `json:"hit_rate"`
	LastPruneTime string  `json:"last_prune_time,omitempty"`
}

// DefaultConfig returns a default server configuration
func DefaultConfig() Config {
	return Config{
		Port:            "3000",
		BindAddress:     "0.0.0.0",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
}
