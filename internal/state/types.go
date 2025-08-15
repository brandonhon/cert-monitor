package state

import (
	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
)

// Manager defines the interface for application state management
type Manager interface {
	// Configuration management
	GetConfig() *config.Config
	SetConfig(cfg *config.Config)
	SetConfigFilePath(path string)
	GetConfigFilePath() string

	// Reload management
	TriggerReload()
	GetReloadChannel() <-chan struct{}
	Close()

	// Utility methods
	ShouldWriteMetrics() bool

	// Backoff management
	RegisterScanFailure(directory string)
	ShouldSkipScan(directory string) bool
	ClearExpiredBackoffs()
}

// Config holds state manager configuration
type Config struct {
	ReloadChannelSize int
}

// DefaultConfig returns default state manager configuration
func DefaultConfig() *Config {
	return &Config{
		ReloadChannelSize: 1,
	}
}

// Dependencies holds external dependencies for the state manager
type Dependencies struct {
	CacheManager    cache.Manager
	MetricsRegistry MetricsRegistry
}

// MetricsRegistry interface to abstract metrics registry operations
type MetricsRegistry interface {
	GetCollector() *metrics.DefaultCollector
	Reset()
}
