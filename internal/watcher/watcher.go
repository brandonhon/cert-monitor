// # internal/watcher/watcher.go
package watcher

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/yourusername/cert-monitor/internal/config"
	"github.com/yourusername/cert-monitor/internal/scanner"
	
	log "github.com/sirupsen/logrus"
)

// Watcher manages file system watching for certificate changes
type Watcher struct {
	config       *config.Config
	scanner      *scanner.Scanner
	watcher      *fsnotify.Watcher
	configWatcher *fsnotify.Watcher
	watchedDirs  map[string]bool
	dirsMutex    sync.Mutex
}

// New creates a new watcher instance
func New(cfg *config.Config, certScanner *scanner.Scanner) *Watcher {
	return &Watcher{
		config:      cfg,
		scanner:     certScanner,
		watchedDirs: make(map[string]bool),
	}
}

// Start starts the file system watcher
func (w *Watcher) Start(ctx context.Context) error {
	// Create main watcher
	var err error
	w.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	
	// Add all certificate directories
	for _, dir := range w.config.CertDirs {
		if err := w.addDirectoryToWatcher(dir); err != nil {
			log.WithError(err).WithField("dir", dir).Warn("Failed to setup watcher for certificate directory")
		} else {
			log.WithField("dir", dir).Info("Successfully added certificate directory tree to watcher")
		}
	}
	
	// Setup config file watcher if config file is specified
	if w.config.ConfigFile != "" {
		w.setupConfigWatcher(ctx)
	}
	
	// Start the watcher goroutine
	go w.watchLoop(ctx)
	
	return nil
}

// Stop stops the file system watcher
func (w *Watcher) Stop() {
	if w.watcher != nil {
		w.watcher.Close()
	}
	
	if w.configWatcher != nil {
		w.configWatcher.Close()
	}
	
	// Clean up tracked directories
	w.dirsMutex.Lock()
	for path := range w.watchedDirs {
		delete(w.watchedDirs, path)
	}
	w.dirsMutex.Unlock()
}

func (w *Watcher) watchLoop(ctx context.Context) {
	defer log.Info("File system watcher goroutine shutting down")
	
	for {
		select {
		case <-ctx.Done():
			log.Info("Watcher goroutine shutting down")
			return
			
		case ev, ok := <-w.watcher.Events:
			if !ok {
				log.Info("File system watcher events channel closed")
				return
			}
			
			// Handle directory removal events
			if ev.Op&fsnotify.Remove != 0 {
				info, err := os.Stat(ev.Name)
				if os.IsNotExist(err) || (err == nil && info.IsDir()) {
					w.removeDirectoryFromWatcher(ev.Name)
				}
			}
			
			// Trigger reload for certificate-related changes
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
				log.WithField("event", ev).Info("Detected FS change, reloading for leaf certificate processing")
				w.scanner.TriggerReload()
			}
			
		case err, ok := <-w.watcher.Errors:
			if !ok {
				log.Info("File system watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("Watcher internal error")
		}
	}
}

func (w *Watcher) setupConfigWatcher(ctx context.Context) {
	var err error
	w.configWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Warn("Unable to start config file watcher")
		return
	}
	
	if err := w.configWatcher.Add(w.config.ConfigFile); err != nil {
		log.WithError(err).WithField("file", w.config.ConfigFile).Warn("Unable to watch config file")
		w.configWatcher.Close()
		w.configWatcher = nil
		return
	}
	
	// Start config watcher goroutine
	go w.watchConfigLoop(ctx)
}

func (w *Watcher) watchConfigLoop(ctx context.Context) {
	defer log.Info("Config watcher goroutine shutting down")
	
	const debounce = 2 * time.Second
	var timer *time.Timer
	
	for {
		select {
		case <-ctx.Done():
			log.Info("Context cancelled, stopping config watcher")
			return
			
		case ev, ok := <-w.configWatcher.Events:
			if !ok {
				log.Info("Config watcher events channel closed")
				return
			}
			
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				log.WithField("event", ev).Info("Config file change detected, debouncing reload")
				
				if timer != nil && !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				
				timer = time.AfterFunc(debounce, func() {
					log.Info("Debounced config reload triggered")
					w.reloadConfig()
				})
			}
			
		case err, ok := <-w.configWatcher.Errors:
			if !ok {
				log.Info("Config watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("Config watcher internal error")
		}
	}
}

func (w *Watcher) reloadConfig() {
	if err := config.Load(w.config.ConfigFile); err != nil {
		log.WithError(err).Warn("Config reload failed")
		return
	}
	
	newCfg := config.Get()
	log.WithFields(log.Fields{
		"cert_dirs": newCfg.CertDirs,
		"port":      newCfg.Port,
		"mode":      "leaf_certificates_only",
	}).Info("Config reloaded successfully")
	
	w.scanner.TriggerReload()
}

func (w *Watcher) addDirectoryToWatcher(dirPath string) error {
	// Clean up stale watchers before adding new ones
	w.cleanupStaleWatchers()
	
	return filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.WithError(err).WithField("path", path).Warn("Error walking directory for watcher")
			return nil // Continue walking despite errors
		}
		
		if !d.IsDir() {
			return nil // Only watch directories
		}
		
		// Check if we're already watching this directory
		w.dirsMutex.Lock()
		if w.watchedDirs[path] {
			w.dirsMutex.Unlock()
			return nil
		}
		
		// Skip excluded subdirectories
		dirName := strings.ToLower(d.Name())
		if dirName == "old" || dirName == "working" {
			w.dirsMutex.Unlock()
			log.WithField("dir", path).Debug("Skipping excluded directory from watcher")
			return filepath.SkipDir
		}
		
		// Add directory to watcher
		if err := w.watcher.Add(path); err != nil {
			w.dirsMutex.Unlock()
			log.WithError(err).WithField("dir", path).Warn("Failed to add directory to watcher")
		} else {
			w.watchedDirs[path] = true
			w.dirsMutex.Unlock()
			log.WithField("dir", path).Debug("Added directory to file system watcher")
		}
		
		return nil
	})
}

func (w *Watcher) removeDirectoryFromWatcher(dirPath string) {
	w.dirsMutex.Lock()
	defer w.dirsMutex.Unlock()
	
	// Remove the specific directory and any subdirectories
	for watchedPath := range w.watchedDirs {
		if strings.HasPrefix(watchedPath, dirPath) {
			if err := w.watcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Debug("Failed to remove directory from watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed directory from watcher")
			}
			delete(w.watchedDirs, watchedPath)
		}
	}
}

func (w *Watcher) cleanupStaleWatchers() {
	w.dirsMutex.Lock()
	defer w.dirsMutex.Unlock()
	
	for watchedPath := range w.watchedDirs {
		if _, err := os.Stat(watchedPath); os.IsNotExist(err) {
			if err := w.watcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Warn("Failed to remove stale watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed stale directory from watcher")
			}
			delete(w.watchedDirs, watchedPath)
		}
	}
}
