package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brandonhon/cert-monitor/pkg/errors"
	"github.com/brandonhon/cert-monitor/pkg/utils"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

// Manager implements the Watcher interface
type Manager struct {
	config Config

	// Certificate directory watcher
	certWatcher     *fsnotify.Watcher
	watchedDirs     map[string]bool
	watchedDirsLock sync.RWMutex

	// Configuration file watcher
	configWatcher *fsnotify.Watcher

	// Internal channels and state
	stopCh   chan struct{}
	eventsCh chan Event
	errorsCh chan error

	// Debouncing
	debounceTimer  *time.Timer
	debounceMutex  sync.Mutex
	configReloadCh chan struct{}
}

// New creates a new watcher manager
func New(config *Config) Watcher {
	if config.DebounceDelay == 0 {
		config.DebounceDelay = 2 * time.Second
	}

	return &Manager{
		config:         *config,
		watchedDirs:    make(map[string]bool),
		stopCh:         make(chan struct{}),
		eventsCh:       make(chan Event, 100),
		errorsCh:       make(chan error, 10),
		configReloadCh: make(chan struct{}, 1),
	}
}

// Start starts the file system watchers
func (m *Manager) Start(ctx context.Context) error {
	var err error

	// Create certificate directory watcher
	m.certWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return errors.NewServerError("watcher", "create", err)
	}

	// Add certificate directories
	if err := m.AddDirectories(m.config.CertificateDirs); err != nil {
		m.certWatcher.Close()
		return fmt.Errorf("failed to add certificate directories: %w", err)
	}

	// Setup config file watcher if specified
	if m.config.ConfigFilePath != "" {
		if err := m.setupConfigWatcher(); err != nil {
			log.WithError(err).Warn("Failed to setup config file watcher")
		}
	}

	// Start event processing goroutines
	go m.processCertEvents(ctx)
	go m.processConfigEvents(ctx)

	log.WithFields(log.Fields{
		"watched_dirs":    len(m.watchedDirs),
		"config_watching": m.configWatcher != nil,
		"debounce_delay":  m.config.DebounceDelay,
	}).Info("File system watcher started")

	return nil
}

// Stop stops all watchers
func (m *Manager) Stop(ctx context.Context) error {
	close(m.stopCh)

	// Clean up debounce timer
	m.debounceMutex.Lock()
	if m.debounceTimer != nil {
		m.debounceTimer.Stop()
	}
	m.debounceMutex.Unlock()

	// Close watchers
	if m.certWatcher != nil {
		if err := m.certWatcher.Close(); err != nil {
			log.WithError(err).Warn("Error closing certificate watcher")
		}
	}

	if m.configWatcher != nil {
		if err := m.configWatcher.Close(); err != nil {
			log.WithError(err).Warn("Error closing config watcher")
		}
	}

	// Clear watched directories
	m.watchedDirsLock.Lock()
	for path := range m.watchedDirs {
		delete(m.watchedDirs, path)
	}
	m.watchedDirsLock.Unlock()

	log.Info("File system watchers stopped")
	return nil
}

// AddDirectories adds directories to the watcher
func (m *Manager) AddDirectories(dirs []string) error {
	for _, dir := range dirs {
		if err := m.addDirectoryRecursive(dir); err != nil {
			log.WithError(err).WithField("directory", dir).Warn("Failed to watch certificate directory")
		} else {
			log.WithField("directory", dir).Info("Added certificate directory to watcher")
		}
	}
	return nil
}

// RemoveDirectories removes directories from the watcher
func (m *Manager) RemoveDirectories(dirs []string) error {
	for _, dir := range dirs {
		m.removeDirectoryFromWatcher(dir)
	}
	return nil
}

// IsWatching checks if a path is being watched
func (m *Manager) IsWatching(path string) bool {
	m.watchedDirsLock.RLock()
	defer m.watchedDirsLock.RUnlock()
	return m.watchedDirs[path]
}

// GetWatchedDirs returns a list of watched directories
func (m *Manager) GetWatchedDirs() []string {
	m.watchedDirsLock.RLock()
	defer m.watchedDirsLock.RUnlock()

	dirs := make([]string, 0, len(m.watchedDirs))
	for dir := range m.watchedDirs {
		dirs = append(dirs, dir)
	}
	return dirs
}

// addDirectoryRecursive recursively adds directories to the watcher
func (m *Manager) addDirectoryRecursive(dirPath string) error {
	m.cleanupStaleWatchers()

	return filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.WithError(err).WithField("path", path).Warn("Error walking directory for watcher")
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		// Skip excluded directories
		if m.shouldSkipDirectory(d.Name()) {
			log.WithField("directory", path).Debug("Skipping excluded directory from watcher")
			return filepath.SkipDir
		}

		// Check if already watching
		m.watchedDirsLock.Lock()
		if m.watchedDirs[path] {
			m.watchedDirsLock.Unlock()
			return nil
		}

		// Add to watcher
		if err := m.certWatcher.Add(path); err != nil {
			m.watchedDirsLock.Unlock()
			log.WithError(err).WithField("directory", path).Warn("Failed to add directory to watcher")
			return nil
		}

		m.watchedDirs[path] = true
		m.watchedDirsLock.Unlock()

		log.WithField("directory", path).Debug("Added directory to file system watcher")
		return nil
	})
}

// shouldSkipDirectory determines if a directory should be excluded from watching
func (m *Manager) shouldSkipDirectory(dirName string) bool {
	lowerName := strings.ToLower(dirName)

	for _, excluded := range m.config.ExcludedDirs {
		if strings.EqualFold(lowerName, excluded) {
			return true
		}
	}
	return false
}

// cleanupStaleWatchers removes non-existent directories from the watcher
func (m *Manager) cleanupStaleWatchers() {
	m.watchedDirsLock.Lock()
	defer m.watchedDirsLock.Unlock()

	for watchedPath := range m.watchedDirs {
		if _, err := os.Stat(watchedPath); os.IsNotExist(err) {
			if err := m.certWatcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Warn("Failed to remove stale watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed stale directory from watcher")
			}
			delete(m.watchedDirs, watchedPath)
		}
	}
}

// removeDirectoryFromWatcher removes a directory and subdirectories from watcher
func (m *Manager) removeDirectoryFromWatcher(dirPath string) {
	m.watchedDirsLock.Lock()
	defer m.watchedDirsLock.Unlock()

	for watchedPath := range m.watchedDirs {
		if strings.HasPrefix(watchedPath, dirPath) {
			if err := m.certWatcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Debug("Failed to remove directory from watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed directory from watcher")
			}
			delete(m.watchedDirs, watchedPath)
		}
	}
}

// setupConfigWatcher sets up watching for configuration file changes
func (m *Manager) setupConfigWatcher() error {
	var err error
	m.configWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return errors.NewServerError("config-watcher", "create", err)
	}

	if err := m.configWatcher.Add(m.config.ConfigFilePath); err != nil {
		m.configWatcher.Close()
		m.configWatcher = nil
		return errors.NewServerError("config-watcher", "add-file", err)
	}

	log.WithField("config_file", m.config.ConfigFilePath).Info("Configuration file watcher setup")
	return nil
}

// processCertEvents processes certificate directory events
func (m *Manager) processCertEvents(ctx context.Context) {
	defer log.Info("Certificate events processor shutting down")

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event, ok := <-m.certWatcher.Events:
			if !ok {
				log.Info("Certificate watcher events channel closed")
				return
			}
			m.handleCertEvent(event)
		case err, ok := <-m.certWatcher.Errors:
			if !ok {
				log.Info("Certificate watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("Certificate watcher error")
		}
	}
}

// processConfigEvents processes configuration file events
func (m *Manager) processConfigEvents(ctx context.Context) {
	if m.configWatcher == nil {
		return
	}

	defer log.Info("Configuration events processor shutting down")

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event, ok := <-m.configWatcher.Events:
			if !ok {
				log.Info("Configuration watcher events channel closed")
				return
			}
			m.handleConfigEvent(event)
		case err, ok := <-m.configWatcher.Errors:
			if !ok {
				log.Info("Configuration watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("Configuration file watcher error")
		}
	}
}

// handleCertEvent processes individual certificate directory events
func (m *Manager) handleCertEvent(event fsnotify.Event) {
	logger := log.WithFields(log.Fields{
		"event": event.Op.String(),
		"path":  event.Name,
	})

	// Handle directory removal
	if event.Op&fsnotify.Remove != 0 {
		// Handle directory removal for watcher cleanup
		if info, err := os.Stat(event.Name); os.IsNotExist(err) || (err == nil && info.IsDir()) {
			m.removeDirectoryFromWatcher(event.Name)
			logger.WithField("directory", event.Name).Debug("Directory removed from watcher")
		}
	}

	// Trigger reload for certificate-related changes
	if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
		logger.Info("Certificate-related file system change detected")

		if m.config.OnFileChange != nil {
			certEvent := Event{
				Type: EventCertificateChange,
				Path: event.Name,
				Op:   event.Op,
			}

			// Check if it's a certificate file for more specific handling
			if utils.IsCertificateFile(filepath.Base(event.Name)) {
				m.config.OnFileChange(certEvent)
			} else if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
				// Directory change
				certEvent.Type = EventDirectoryChange
				m.config.OnFileChange(certEvent)
			}
		}
	}
}

// handleConfigEvent processes configuration file events with debouncing
func (m *Manager) handleConfigEvent(event fsnotify.Event) {
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
		log.WithField("event", event).Info("Configuration file change detected, debouncing reload")

		m.debounceMutex.Lock()
		defer m.debounceMutex.Unlock()

		// Stop existing timer
		if m.debounceTimer != nil && !m.debounceTimer.Stop() {
			select {
			case <-m.debounceTimer.C:
			default:
			}
		}

		// Start new debounced timer
		m.debounceTimer = time.AfterFunc(m.config.DebounceDelay, func() {
			log.Info("Debounced configuration reload triggered")
			if m.config.OnConfigChange != nil {
				m.config.OnConfigChange(m.config.ConfigFilePath)
			}
		})
	}
}
