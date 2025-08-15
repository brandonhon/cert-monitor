package state

import (
	"sync"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/config"
	log "github.com/sirupsen/logrus"
)

// manager implements the Manager interface
type manager struct {
	// Configuration management
	config         *config.Config
	configMutex    sync.RWMutex
	configFilePath string

	// Reload management
	reloadCh   chan struct{}
	reloadOnce sync.Once
	closed     bool
	closeMutex sync.Mutex

	// External dependencies
	cacheManager    cache.Manager
	metricsRegistry MetricsRegistry

	// Backoff manager
	backoffManager *BackoffManager
}

// New creates a new state manager
func New(config *Config, deps *Dependencies) Manager {
	if config == nil {
		config = DefaultConfig()
	}

	return &manager{
		reloadCh:        make(chan struct{}, config.ReloadChannelSize),
		cacheManager:    deps.CacheManager,
		metricsRegistry: deps.MetricsRegistry,
		backoffManager:  NewBackoffManager(),
	}
}

// GetConfig safely retrieves the current configuration
func (m *manager) GetConfig() *config.Config {
	m.configMutex.RLock()
	defer m.configMutex.RUnlock()
	return m.config
}

// SetConfig safely updates the configuration
func (m *manager) SetConfig(cfg *config.Config) {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	m.config = cfg

	log.WithField("config_updated", true).Debug("Configuration updated in state manager")
}

// SetConfigFilePath sets the configuration file path
func (m *manager) SetConfigFilePath(path string) {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	m.configFilePath = path
}

// GetConfigFilePath gets the configuration file path
func (m *manager) GetConfigFilePath() string {
	m.configMutex.RLock()
	defer m.configMutex.RUnlock()
	return m.configFilePath
}

// TriggerReload signals a reload request
func (m *manager) TriggerReload() {
	m.closeMutex.Lock()
	if m.closed {
		m.closeMutex.Unlock()
		log.Debug("Cannot trigger reload: state manager is closed")
		return
	}
	m.closeMutex.Unlock()

	select {
	case m.reloadCh <- struct{}{}:
		log.Debug("Certificate rescan triggered via state manager")
	default:
		log.Debug("Certificate rescan already queued, skipping trigger")
	}
}

// GetReloadChannel returns the reload channel for listening
func (m *manager) GetReloadChannel() <-chan struct{} {
	return m.reloadCh
}

// Close properly closes the state manager and its channels
func (m *manager) Close() {
	m.closeMutex.Lock()
	defer m.closeMutex.Unlock()

	if m.closed {
		return
	}

	m.reloadOnce.Do(func() {
		close(m.reloadCh)
		m.closed = true
		log.Debug("State manager closed")
	})
}

// ShouldWriteMetrics determines if metrics should be written based on configuration
func (m *manager) ShouldWriteMetrics() bool {
	cfg := m.GetConfig()
	return cfg != nil && !cfg.DryRun
}

// Backoff management delegation
func (m *manager) RegisterScanFailure(directory string) {
	m.backoffManager.RegisterFailure(directory)
}

func (m *manager) ShouldSkipScan(directory string) bool {
	return m.backoffManager.ShouldSkip(directory)
}

func (m *manager) ClearExpiredBackoffs() {
	m.backoffManager.ClearExpired()
}
