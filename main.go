// new.go
// SSL Certificate Monitoring Tool
// -----------------------------------
// This Go application monitors SSL/TLS certificates in specified directories.
// It collects and exposes Prometheus metrics about certificate expiration,
// subject alternative names (SANs), duplication, parsing issues, and cryptographic strength.
//
// Refactored for improved efficiency, readability, and maintainability.

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brandonhon/cert-monitor/internal/cache"
	"github.com/brandonhon/cert-monitor/internal/certificate"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/metrics"
	"github.com/brandonhon/cert-monitor/internal/server"
	"github.com/brandonhon/cert-monitor/pkg/utils"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Version info (injected at build time via -ldflags)
var (
	Version = "dev"
	Commit  = "none"
)

// Global state management
type GlobalState struct {
	config         *config.Config
	configMutex    sync.RWMutex
	configFilePath string
	reloadCh       chan struct{}

	// Scan backoff tracking
	scanBackoff     map[string]time.Time
	scanBackoffLock sync.Mutex

	// File system watcher management
	watchedDirs     map[string]bool
	watchedDirsLock sync.Mutex
	mainWatcher     *fsnotify.Watcher
}

// Global instances
var (
	globalState     *GlobalState
	cacheManager    cache.Manager
	metricsRegistry *metrics.Registry
)

func init() {
	globalState = &GlobalState{
		scanBackoff: make(map[string]time.Time),
		watchedDirs: make(map[string]bool),
	}
}

// Global State Management
// ======================

// getConfig safely retrieves the current configuration
func (gs *GlobalState) getConfig() *config.Config {
	gs.configMutex.RLock()
	defer gs.configMutex.RUnlock()
	return gs.config
}

// setConfig safely updates the global configuration
func (gs *GlobalState) setConfig(cfg *config.Config) {
	gs.configMutex.Lock()
	defer gs.configMutex.Unlock()
	gs.config = cfg
}

// Certificate Processing
// =====================

// processCertificateDirectory scans a directory for certificates and processes them
func processCertificateDirectory(dirPath string, dryRun bool) map[string]int {
	logger := log.WithField("directory", dirPath)

	if !shouldWriteMetrics() {
		logger.Info("Dry-run mode active, metrics writes disabled")
	}

	if shouldSkipScan(dirPath) {
		logger.Warn("Skipping scan due to backoff")
		return nil
	}

	start := time.Now()
	defer func() {
		if !dryRun && shouldWriteMetrics() {
			collector := metricsRegistry.GetCollector()
			collector.CertScanDuration.WithLabelValues(dirPath).Observe(time.Since(start).Seconds())
		}
	}()

	if err := utils.ValidateDirectoryAccess(dirPath); err != nil {
		logger.WithError(err).Warn("Directory validation failed, skipping scan")
		registerScanFailure(dirPath)
		return nil
	}

	defer func() {
		if !dryRun && shouldWriteMetrics() {
			collector := metricsRegistry.GetCollector()
			collector.CertLastScan.WithLabelValues(dirPath).Set(float64(time.Now().Unix()))
		}
	}()

	// Create certificate processor
	processor := certificate.NewProcessor()

	// Create processing options
	options := certificate.ProcessingOptions{
		ExpiryThresholdDays: globalState.getConfig().ExpiryThresholdDays,
		DryRun:              dryRun,
		EnableWeakCrypto:    globalState.getConfig().EnableWeakCryptoMetrics,
	}

	// Process certificates and track duplicates
	stats, duplicates, err := processor.ProcessDirectory(dirPath, options)
	if err != nil {
		logger.WithError(err).Warn("Certificate directory processing failed")
		registerScanFailure(dirPath)
		return nil
	}

	// Process individual certificates for metrics if we have results
	if !dryRun && shouldWriteMetrics() {
		processIndividualCertificatesForMetrics(processor, dirPath, options, duplicates)
	}

	// Update metrics based on processing results
	if !dryRun && shouldWriteMetrics() {
		collector := metricsRegistry.GetCollector()

		// Update directory metrics
		dirMetrics := metrics.CreateDirectoryMetrics(dirPath, stats) // Already returns pointer now
		collector.UpdateDirectory(dirMetrics)
	}

	// Process individual certificates for metrics if we have results
	if !dryRun && shouldWriteMetrics() {
		processIndividualCertificatesForMetrics(processor, dirPath, options, duplicates)
	}

	// Convert DuplicateMap to map[string]int for return compatibility
	seen := make(map[string]int)
	for fingerprint, count := range duplicates {
		seen[fingerprint] = count
	}

	if err != nil {
		logger.WithError(err).Warn("Directory walk failed")
		registerScanFailure(dirPath)
	}

	logger.WithFields(log.Fields{
		"certificates_found": len(seen),
		"scan_duration":      time.Since(start),
	}).Info("Certificate directory scan completed")

	return seen
}

// processIndividualCertificatesForMetrics processes certificates again to update individual metrics
func processIndividualCertificatesForMetrics(processor certificate.Processor, dirPath string, options certificate.ProcessingOptions, duplicates certificate.DuplicateMap) {
	collector := metricsRegistry.GetCollector()

	// We need to scan the directory again to get individual certificate results
	// This is a bit inefficient, but maintains compatibility with existing metrics
	scanner := certificate.NewScanner()
	files, err := scanner.ScanDirectory(dirPath)
	if err != nil {
		log.WithError(err).WithField("directory", dirPath).Warn("Failed to scan directory for metrics processing")
		return
	}

	for _, fileInfo := range files {
		result, err := processor.ProcessFile(fileInfo.Path, options)
		if err != nil {
			collector.RecordParseError(fileInfo.Path)
			continue
		}

		if result.Certificate == nil || result.Info == nil {
			continue
		}

		// Get duplicate count for this certificate
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(result.Certificate.Raw))
		duplicateCount := duplicates[fingerprint]

		// Update individual certificate metrics
		certMetrics := metrics.CreateCertificateMetrics(result.Info, duplicateCount) // Already returns pointer now
		collector.UpdateCertificate(certMetrics)

		log.WithFields(log.Fields{
			"common_name": result.Info.CommonName,
			"issuer":      result.Info.Issuer,
			"not_after":   result.Info.NotAfter,
			"sans":        len(result.Info.SANs),
		}).Debug("Certificate processed successfully for metrics")
	}
}

// Scan Backoff Management
// ======================

// registerScanFailure registers a scan failure and applies exponential backoff
func registerScanFailure(dir string) {
	globalState.scanBackoffLock.Lock()
	defer globalState.scanBackoffLock.Unlock()

	now := time.Now()
	delay := 30 * time.Second

	// Apply exponential backoff if already in backoff
	if lastBackoff, exists := globalState.scanBackoff[dir]; exists && lastBackoff.After(now) {
		delay = lastBackoff.Sub(now) * 2
		if delay < 0 || delay > utils.MaxBackoff {
			delay = utils.MaxBackoff
		}
	}

	// Add jitter to prevent thundering herd
	jitter := time.Duration(rand.Int63n(int64(10 * time.Second)))
	nextScan := now.Add(delay + jitter)
	globalState.scanBackoff[dir] = nextScan

	log.WithFields(log.Fields{
		"directory":     dir,
		"backoff_delay": delay + jitter,
		"retry_after":   nextScan.Format(time.RFC3339),
	}).Warn("Scan failed, applying exponential backoff")
}

// shouldSkipScan checks if a directory should be skipped due to backoff
func shouldSkipScan(dir string) bool {
	globalState.scanBackoffLock.Lock()
	defer globalState.scanBackoffLock.Unlock()

	nextAllowed, exists := globalState.scanBackoff[dir]
	if !exists {
		return false
	}

	now := time.Now()
	if now.Before(nextAllowed) {
		log.WithFields(log.Fields{
			"directory":      dir,
			"backoff_until":  nextAllowed.Format(time.RFC3339),
			"remaining_time": nextAllowed.Sub(now),
		}).Debug("Directory scan skipped due to backoff")
		return true
	}

	// Backoff expired, remove entry
	delete(globalState.scanBackoff, dir)
	log.WithField("directory", dir).Debug("Backoff period expired, allowing scan")
	return false
}

// clearExpiredBackoffs removes expired backoff entries
func clearExpiredBackoffs() {
	globalState.scanBackoffLock.Lock()
	defer globalState.scanBackoffLock.Unlock()

	now := time.Now()
	removed := 0

	for dir, nextAllowed := range globalState.scanBackoff {
		if now.After(nextAllowed) {
			delete(globalState.scanBackoff, dir)
			removed++
		}
	}

	if removed > 0 {
		log.WithFields(log.Fields{
			"removed_entries":   removed,
			"remaining_entries": len(globalState.scanBackoff),
		}).Debug("Cleared expired backoff entries")
	}
}

// Utility Functions
// ================

// shouldWriteMetrics determines if metrics should be written
func shouldWriteMetrics() bool {
	cfg := globalState.getConfig()
	return cfg != nil && !cfg.DryRun
}

// resetMetrics resets all Prometheus metrics
func resetMetrics(clearCache bool) {
	if metricsRegistry != nil {
		if clearCache {
			metricsRegistry.Reset()
		} else {
			metricsRegistry.GetCollector().ResetCounters()
		}
	}

	if clearCache {
		if cacheManager != nil {
			cacheManager.Clear()
			log.Info("Certificate cache cleared via cache manager")
		}
	}
}

// Logging and Initialization
// ==========================

// initLogger initializes structured logging with rotation
func initLogger(logPath string, dryRun bool) {
	logWriter := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    25, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	}

	// Configure output streams
	if dryRun {
		log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
	} else {
		log.SetOutput(logWriter)
	}

	// Configure log format
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: !dryRun, // Colors only for dry-run (stdout)
	})

	log.SetLevel(log.InfoLevel)

	log.WithFields(log.Fields{
		"log_file": logPath,
		"dry_run":  dryRun,
	}).Info("Logger initialized successfully")
}

// File System Watcher Management
// ==============================

// setupFileSystemWatcher configures directory watching for certificate changes
func setupFileSystemWatcher(ctx context.Context, cfg *config.Config) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file system watcher: %w", err)
	}

	globalState.mainWatcher = watcher

	// Add certificate directories to watcher
	for _, dir := range cfg.CertDirs {
		if err := addDirectoryToWatcher(watcher, dir); err != nil {
			log.WithError(err).WithField("directory", dir).Warn("Failed to watch certificate directory")
		} else {
			log.WithField("directory", dir).Info("Added certificate directory to file system watcher")
		}
	}

	return watcher, nil
}

// addDirectoryToWatcher recursively adds directories to the file system watcher
func addDirectoryToWatcher(watcher *fsnotify.Watcher, dirPath string) error {
	cleanupStaleWatchers(watcher)

	return filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.WithError(err).WithField("path", path).Warn("Error walking directory for watcher")
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		// Skip excluded directories
		if shouldSkipDirectory(d.Name()) {
			log.WithField("directory", path).Debug("Skipping excluded directory from watcher")
			return filepath.SkipDir
		}

		// Check if already watching
		globalState.watchedDirsLock.Lock()
		if globalState.watchedDirs[path] {
			globalState.watchedDirsLock.Unlock()
			return nil
		}

		// Add to watcher
		if err := watcher.Add(path); err != nil {
			globalState.watchedDirsLock.Unlock()
			log.WithError(err).WithField("directory", path).Warn("Failed to add directory to watcher")
			return nil
		}

		globalState.watchedDirs[path] = true
		globalState.watchedDirsLock.Unlock()

		log.WithField("directory", path).Debug("Added directory to file system watcher")
		return nil
	})
}

// shouldSkipDirectory determines if a directory should be excluded from watching
func shouldSkipDirectory(dirName string) bool {
	excluded := []string{"old", "working"}
	lowerName := strings.ToLower(dirName)

	for _, skip := range excluded {
		if lowerName == skip {
			return true
		}
	}
	return false
}

// cleanupStaleWatchers removes non-existent directories from the watcher
func cleanupStaleWatchers(watcher *fsnotify.Watcher) {
	globalState.watchedDirsLock.Lock()
	defer globalState.watchedDirsLock.Unlock()

	for watchedPath := range globalState.watchedDirs {
		if _, err := os.Stat(watchedPath); os.IsNotExist(err) {
			if err := watcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Warn("Failed to remove stale watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed stale directory from watcher")
			}
			delete(globalState.watchedDirs, watchedPath)
		}
	}
}

// removeDirectoryFromWatcher removes a directory and subdirectories from watcher
func removeDirectoryFromWatcher(watcher *fsnotify.Watcher, dirPath string) {
	globalState.watchedDirsLock.Lock()
	defer globalState.watchedDirsLock.Unlock()

	for watchedPath := range globalState.watchedDirs {
		if strings.HasPrefix(watchedPath, dirPath) {
			if err := watcher.Remove(watchedPath); err != nil {
				log.WithError(err).WithField("path", watchedPath).Debug("Failed to remove directory from watcher")
			} else {
				log.WithField("path", watchedPath).Debug("Removed directory from watcher")
			}
			delete(globalState.watchedDirs, watchedPath)
		}
	}
}

// Configuration Reload Management
// ===============================

// reloadConfigAndTrigger reloads configuration and triggers certificate rescan
func reloadConfigAndTrigger() {
	if globalState.configFilePath == "" {
		log.Warn("No configuration file path set, skipping reload")
		return
	}

	result := performHotConfigReload(globalState.configFilePath)

	if result.Success {
		log.WithFields(log.Fields{
			"config_file":      globalState.configFilePath,
			"applied_changes":  len(result.AppliedChanges),
			"requires_restart": len(result.RequiresRestart),
		}).Info("Configuration hot-reload completed")

		// Only trigger certificate rescan if certificate-related settings changed
		if shouldTriggerRescan(result.AppliedChanges) {
			triggerReload()
		}
	} else {
		log.WithError(errors.New(result.Error)).Warn("Configuration hot-reload failed")
	}
}

// performHotConfigReload performs hot configuration reload with change detection
func performHotConfigReload(configPath string) config.ReloadResult {
	result := config.ReloadResult{
		ChangedSettings: make(map[string]string),
		AppliedChanges:  make([]string, 0),
		RequiresRestart: make([]string, 0),
	}

	// Get current configuration for comparison
	oldConfig := globalState.getConfig()
	if oldConfig == nil {
		result.Error = "no current configuration available"
		return result
	}

	// Load new configuration
	newConfig := config.Default()
	if err := loadConfigFromFile(configPath); err != nil {
		result.Error = fmt.Sprintf("failed to load new configuration: %v", err)
		return result
	}

	// Detect changes
	diff := detectConfigChanges(oldConfig, newConfig)

	// Apply hot-reloadable changes
	applyHotReloadableChanges(oldConfig, newConfig, diff, &result)

	// Identify changes that require restart
	identifyRestartRequiredChanges(diff, &result)

	// Update global configuration with applied changes
	globalState.setConfig(newConfig)

	result.Success = true
	return result
}

// detectConfigChanges compares old and new configurations to detect differences
func detectConfigChanges(oldCfg, newCfg *config.Config) config.Diff {
	return config.Diff{
		CertDirsChanged:          !equalStringSlices(oldCfg.CertDirs, newCfg.CertDirs),
		LogFileChanged:           oldCfg.LogFile != newCfg.LogFile,
		PortChanged:              oldCfg.Port != newCfg.Port,
		BindAddressChanged:       oldCfg.BindAddress != newCfg.BindAddress,
		NumWorkersChanged:        oldCfg.NumWorkers != newCfg.NumWorkers,
		TLSConfigChanged:         oldCfg.TLSCertFile != newCfg.TLSCertFile || oldCfg.TLSKeyFile != newCfg.TLSKeyFile,
		RuntimeMetricsChanged:    oldCfg.EnableRuntimeMetrics != newCfg.EnableRuntimeMetrics,
		WeakCryptoMetricsChanged: oldCfg.EnableWeakCryptoMetrics != newCfg.EnableWeakCryptoMetrics,
		PprofChanged:             oldCfg.EnablePprof != newCfg.EnablePprof,
		CacheFileChanged:         oldCfg.CacheFile != newCfg.CacheFile,
		ExpiryThresholdChanged:   oldCfg.ExpiryThresholdDays != newCfg.ExpiryThresholdDays,
		ClearCacheChanged:        oldCfg.ClearCacheOnReload != newCfg.ClearCacheOnReload,
	}
}

// applyHotReloadableChanges applies configuration changes that don't require restart
func applyHotReloadableChanges(oldCfg, newCfg *config.Config, diff config.Diff, result *config.ReloadResult) {
	// Certificate directories - can be hot-reloaded
	if diff.CertDirsChanged {
		result.ChangedSettings["cert_dirs"] = fmt.Sprintf("%d -> %d directories", len(oldCfg.CertDirs), len(newCfg.CertDirs))
		result.AppliedChanges = append(result.AppliedChanges, "certificate_directories")

		// Update file system watchers for new directories
		if err := updateFileSystemWatchers(oldCfg.CertDirs, newCfg.CertDirs); err != nil {
			log.WithError(err).Warn("Failed to update file system watchers for new certificate directories")
		}
	}

	// Worker count - can be hot-reloaded (affects next scan cycle)
	if diff.NumWorkersChanged {
		result.ChangedSettings["num_workers"] = fmt.Sprintf("%d -> %d", oldCfg.NumWorkers, newCfg.NumWorkers)
		result.AppliedChanges = append(result.AppliedChanges, "worker_pool_size")
	}

	// Runtime metrics - can be hot-reloaded
	if diff.RuntimeMetricsChanged {
		result.ChangedSettings["runtime_metrics"] = fmt.Sprintf("%t -> %t", oldCfg.EnableRuntimeMetrics, newCfg.EnableRuntimeMetrics)
		result.AppliedChanges = append(result.AppliedChanges, "runtime_metrics")
	}

	// Weak crypto metrics - can be hot-reloaded
	if diff.WeakCryptoMetricsChanged {
		result.ChangedSettings["weak_crypto_metrics"] = fmt.Sprintf("%t -> %t", oldCfg.EnableWeakCryptoMetrics, newCfg.EnableWeakCryptoMetrics)
		result.AppliedChanges = append(result.AppliedChanges, "weak_crypto_metrics")
	}

	// Expiry threshold - can be hot-reloaded
	if diff.ExpiryThresholdChanged {
		result.ChangedSettings["expiry_threshold_days"] = fmt.Sprintf("%d -> %d", oldCfg.ExpiryThresholdDays, newCfg.ExpiryThresholdDays)
		result.AppliedChanges = append(result.AppliedChanges, "expiry_threshold")
	}

	// Clear cache setting - can be hot-reloaded
	if diff.ClearCacheChanged {
		result.ChangedSettings["clear_cache_on_reload"] = fmt.Sprintf("%t -> %t", oldCfg.ClearCacheOnReload, newCfg.ClearCacheOnReload)
		result.AppliedChanges = append(result.AppliedChanges, "cache_clear_policy")

		// If cache clearing was just enabled, ensure it takes effect on next reload
		if !oldCfg.ClearCacheOnReload && newCfg.ClearCacheOnReload {
			log.Info("Cache clearing enabled - will take effect on next certificate rescan")
		} else if oldCfg.ClearCacheOnReload && !newCfg.ClearCacheOnReload {
			log.Info("Cache clearing disabled - cache will be preserved on future reloads")
		}
	}

	// Cache file - can be hot-reloaded with migration
	if diff.CacheFileChanged {
		result.ChangedSettings["cache_file"] = fmt.Sprintf("%s -> %s", oldCfg.CacheFile, newCfg.CacheFile)
		if err := migrateCacheFile(oldCfg.CacheFile, newCfg.CacheFile); err != nil {
			log.WithError(err).Warn("Failed to migrate cache file, starting with empty cache")
		}
		result.AppliedChanges = append(result.AppliedChanges, "cache_file")
	}
}

// identifyRestartRequiredChanges identifies changes that require application restart
func identifyRestartRequiredChanges(diff config.Diff, result *config.ReloadResult) {
	// Network configuration changes require restart
	if diff.PortChanged {
		result.RequiresRestart = append(result.RequiresRestart, "http_port")
		result.ChangedSettings["port"] = "requires restart"
	}

	if diff.BindAddressChanged {
		result.RequiresRestart = append(result.RequiresRestart, "bind_address")
		result.ChangedSettings["bind_address"] = "requires restart"
	}

	// TLS configuration changes require restart
	if diff.TLSConfigChanged {
		result.RequiresRestart = append(result.RequiresRestart, "tls_configuration")
		result.ChangedSettings["tls_config"] = "requires restart"
	}

	// Log file changes require restart (complex to hot-reload)
	if diff.LogFileChanged {
		result.RequiresRestart = append(result.RequiresRestart, "log_file")
		result.ChangedSettings["log_file"] = "requires restart"
	}

	// Pprof changes require restart (affects HTTP mux setup)
	if diff.PprofChanged {
		result.RequiresRestart = append(result.RequiresRestart, "pprof_endpoints")
		result.ChangedSettings["pprof"] = "requires restart"
	}
}

// updateFileSystemWatchers updates file system watchers when certificate directories change
func updateFileSystemWatchers(oldDirs, newDirs []string) error {
	if globalState.mainWatcher == nil {
		return fmt.Errorf("no active file system watcher")
	}

	// Find directories to remove (in old but not in new)
	toRemove := findRemovedDirectories(oldDirs, newDirs)
	for _, dir := range toRemove {
		removeDirectoryFromWatcher(globalState.mainWatcher, dir)
		log.WithField("directory", dir).Info("Removed directory from file system watcher")
	}

	// Find directories to add (in new but not in old)
	toAdd := findAddedDirectories(oldDirs, newDirs)
	for _, dir := range toAdd {
		if err := addDirectoryToWatcher(globalState.mainWatcher, dir); err != nil {
			log.WithError(err).WithField("directory", dir).Warn("Failed to add new directory to watcher")
		} else {
			log.WithField("directory", dir).Info("Added new directory to file system watcher")
		}
	}

	return nil
}

// migrateCacheFile migrates cache from old file to new file location
func migrateCacheFile(oldPath, newPath string) error {
	if oldPath == newPath {
		return nil // No migration needed
	}

	if cacheManager != nil {
		return cache.MigrateCache(oldPath, newPath)
	}

	return nil
}

// shouldTriggerRescan determines if certificate rescan should be triggered based on changes
func shouldTriggerRescan(appliedChanges []string) bool {
	log.WithField("applied_changes", appliedChanges).Debug("Evaluating whether to trigger certificate rescan")

	rescanTriggers := map[string]bool{
		"certificate_directories": true,
		"worker_pool_size":        true,
		"weak_crypto_metrics":     true,
		"expiry_threshold":        true,
		"cache_clear_policy":      true,
		"cache_file":              true,
	}

	// Check each applied change against rescan triggers
	for _, change := range appliedChanges {
		if change == "cache_clear_policy" {
			log.WithFields(log.Fields{
				"change":         change,
				"trigger_rescan": true,
				"reason":         "cache clearing policy changed, ensuring immediate effect",
			}).Info("Cache clear policy change detected")
			return true
		}

		if rescanTriggers[change] {
			log.WithFields(log.Fields{
				"change":         change,
				"trigger_rescan": true,
			}).Debug("Configuration change requires certificate rescan")
			return true
		}
	}

	log.WithField("applied_changes", appliedChanges).Debug("No configuration changes require certificate rescan")
	return false
}

// Utility functions for configuration comparison

// equalStringSlices compares two string slices for equality
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison (order-independent)
	mapA := make(map[string]bool)
	mapB := make(map[string]bool)

	for _, str := range a {
		mapA[str] = true
	}

	for _, str := range b {
		mapB[str] = true
	}

	for str := range mapA {
		if !mapB[str] {
			return false
		}
	}

	return true
}

// findRemovedDirectories finds directories that are in old list but not in new list
func findRemovedDirectories(oldDirs, newDirs []string) []string {
	newDirMap := make(map[string]bool)
	for _, dir := range newDirs {
		newDirMap[dir] = true
	}

	var removed []string
	for _, dir := range oldDirs {
		if !newDirMap[dir] {
			removed = append(removed, dir)
		}
	}

	return removed
}

// findAddedDirectories finds directories that are in new list but not in old list
func findAddedDirectories(oldDirs, newDirs []string) []string {
	oldDirMap := make(map[string]bool)
	for _, dir := range oldDirs {
		oldDirMap[dir] = true
	}

	var added []string
	for _, dir := range newDirs {
		if !oldDirMap[dir] {
			added = append(added, dir)
		}
	}

	return added
}

// triggerReload signals a certificate rescan
func triggerReload() {
	select {
	case globalState.reloadCh <- struct{}{}:
		log.Debug("Certificate rescan triggered")
	default:
		log.Debug("Certificate rescan already queued, skipping trigger")
	}
}

// Main Application Logic
// =====================

// runMainProcessingLoop handles certificate scanning and reloading
func runMainProcessingLoop(ctx context.Context) {
	defer log.Info("Main processing loop shutting down")

	// Start periodic cache maintenance
	cacheMaintenanceTicker := time.NewTicker(5 * time.Minute)
	defer cacheMaintenanceTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Processing loop cancelled by context")
			return
		case <-cacheMaintenanceTicker.C:
			// Periodic cache cleanup to handle any missed deletions
			if cacheManager != nil {
				if removed := cacheManager.Prune(); removed > 0 {
					log.WithField("removed_entries", removed).Debug("Periodic cache maintenance removed stale entries")
					// Save updated cache after cleanup
					if err := cacheManager.Save(cacheManager.Stats().CacheFilePath); err != nil {
						log.WithError(err).Debug("Failed to save cache after periodic maintenance")
					}
				}
			}
		case _, ok := <-globalState.reloadCh:
			if !ok {
				log.Info("Reload channel closed, stopping processing loop")
				return
			}
			processCertificateReload(ctx)
		}
	}
}

// processCertificateReload handles a single certificate reload cycle
func processCertificateReload(ctx context.Context) {
	cfg := globalState.getConfig()

	// Reset metrics
	if cfg.ClearCacheOnReload {
		resetMetrics(true)
	} else {
		resetMetrics(false)
	}

	log.WithField("worker_count", cfg.NumWorkers).Info("Starting certificate processing with worker pool")

	// Process directories using worker pool
	processDirectoriesWithWorkers(ctx, cfg)

	// Cleanup and maintenance
	performPostScanMaintenance()
}

// processDirectoriesWithWorkers processes certificate directories using a worker pool
func processDirectoriesWithWorkers(ctx context.Context, cfg *config.Config) {
	dirJobs := make(chan string, len(cfg.CertDirs))
	var wg sync.WaitGroup

	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	// Start workers
	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		go certificateWorker(workerCtx, &wg, dirJobs, i)
	}

	// Queue directory jobs
	for _, dir := range cfg.CertDirs {
		select {
		case <-workerCtx.Done():
			log.Info("Context cancelled while queuing directory jobs")
			close(dirJobs)
			return
		case dirJobs <- dir:
		}
	}
	close(dirJobs)

	// Wait for completion with timeout handling
	waitForWorkers(&wg, workerCtx, workerCancel)

	log.Info("All certificate processing workers completed")
}

// certificateWorker processes certificate directories from the job queue
func certificateWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, workerID int) {
	defer wg.Done()

	logger := log.WithField("worker_id", workerID)
	logger.Debug("Certificate worker started")

	for dir := range jobs {
		select {
		case <-ctx.Done():
			logger.Info("Worker cancelled, stopping")
			return
		default:
		}

		logger.WithField("directory", dir).Info("Processing certificate directory")
		processCertificateDirectory(dir, false)
	}

	logger.Debug("Certificate worker completed")
}

// waitForWorkers waits for all workers to complete with proper timeout handling
func waitForWorkers(wg *sync.WaitGroup, workerCtx context.Context, workerCancel context.CancelFunc) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-workerCtx.Done():
		log.Warn("Context cancelled while waiting for workers")
		workerCancel()
		return
	case <-done:
		// All workers completed successfully
	}
}

// performPostScanMaintenance performs cleanup tasks after certificate scanning
func performPostScanMaintenance() {
	// Prune stale cache entries
	if cacheManager != nil {
		if removed := cacheManager.Prune(); removed > 0 {
			log.WithField("removed_entries", removed).Info("Pruned stale cache entries after scan")
		}
	}

	// Clear expired backoff entries
	clearExpiredBackoffs()

	// Save cache to disk
	if cacheManager != nil {
		if err := cacheManager.Save(cacheManager.Stats().CacheFilePath); err != nil {
			log.WithError(err).Warn("Failed to save certificate cache after scan")
		} else {
			// Log cache statistics after successful save
			stats := cacheManager.Stats()
			log.WithFields(log.Fields{
				"cache_entries": stats.TotalEntries,
				"cache_hits":    stats.CacheHits,
				"cache_misses":  stats.CacheMisses,
				"hit_rate":      fmt.Sprintf("%.2f%%", stats.HitRate),
			}).Debug("Cache statistics after scan maintenance")
		}
	}

	// Update reload timestamp
	metricsRegistry.GetCollector().UpdateReloadTimestamp()

	// Post-scan metric validation for debugging and consistency checking
	validateMetricConsistency()
}

// validateMetricConsistency performs post-scan validation of metric counts
// This helps ensure that our fixes for weak key and deprecated signature algorithm
// metrics are working correctly and that counts reflect reality
func validateMetricConsistency() {
	// Get current certificate count from cache
	var totalCertsInCache int
	if cacheManager != nil {
		totalCertsInCache = cacheManager.Size()
	}

	log.WithFields(log.Fields{
		"certificates_in_cache": totalCertsInCache,
		"validation":            "post_scan_metrics",
	}).Debug("Post-scan metric consistency check")
}

// Runtime Metrics Collection
// ==========================

// runRuntimeMetricsCollector periodically collects runtime metrics
func runRuntimeMetricsCollector(ctx context.Context) {
	if !globalState.getConfig().EnableRuntimeMetrics {
		log.Info("Runtime metrics collection disabled")
		return
	}

	defer log.Info("Runtime metrics collector shutting down")

	ticker := time.NewTicker(utils.RuntimeMetricsInterval)
	defer ticker.Stop()

	log.Info("Runtime metrics collection enabled")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if shouldWriteMetrics() {
				metricsRegistry.GetCollector().UpdateRuntimeMetrics()
			}
		}
	}
}

// File System Event Processing
// ============================

// runFileSystemWatcher processes file system events for certificate changes
func runFileSystemWatcher(ctx context.Context, watcher *fsnotify.Watcher) {
	defer log.Info("File system watcher shutting down")

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				log.Info("File system watcher events channel closed")
				return
			}
			handleFileSystemEvent(watcher, event)
		case err, ok := <-watcher.Errors:
			if !ok {
				log.Info("File system watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("File system watcher error")
		}
	}
}

// handleFileSystemEvent processes individual file system events
func handleFileSystemEvent(watcher *fsnotify.Watcher, event fsnotify.Event) {
	logger := log.WithFields(log.Fields{
		"event": event.Op.String(),
		"path":  event.Name,
	})

	// Handle directory removal
	if event.Op&fsnotify.Remove != 0 {
		// Immediately remove from cache if it's a certificate file
		if utils.IsCertificateFile(filepath.Base(event.Name)) {
			if cacheManager != nil {
				cacheManager.Delete(event.Name)
				logger.WithField("cache_entry", event.Name).Debug("Removed deleted certificate from cache")
			}
		}

		// Handle directory removal for watcher cleanup
		if info, err := os.Stat(event.Name); os.IsNotExist(err) || (err == nil && info.IsDir()) {
			removeDirectoryFromWatcher(watcher, event.Name)

			// Note: Directory removal cache cleanup will be handled by periodic pruning
			logger.WithField("directory", event.Name).Debug("Directory removed, cache will be pruned on next cycle")
		}
	}

	// Trigger reload for certificate-related changes
	if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
		logger.Info("Certificate-related file system change detected, triggering reload")
		triggerReload()
	}
}

// Configuration File Watcher
// ==========================

// setupConfigWatcher sets up watching for configuration file changes
func setupConfigWatcher(ctx context.Context, configFilePath string) {
	if configFilePath == "" {
		log.Debug("No configuration file specified, skipping config watcher setup")
		return
	}

	configWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Warn("Failed to create configuration file watcher")
		return
	}
	defer configWatcher.Close()

	if err := configWatcher.Add(configFilePath); err != nil {
		log.WithError(err).WithField("config_file", configFilePath).Warn("Failed to watch configuration file")
		return
	}

	log.WithField("config_file", configFilePath).Info("Configuration file watcher started")
	runConfigWatcher(ctx, configWatcher)
}

// runConfigWatcher processes configuration file change events
func runConfigWatcher(ctx context.Context, configWatcher *fsnotify.Watcher) {
	defer log.Info("Configuration file watcher shutting down")

	var debounceTimer *time.Timer

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-configWatcher.Events:
			if !ok {
				log.Info("Configuration watcher events channel closed")
				return
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				log.WithField("event", event).Info("Configuration file change detected, debouncing reload")

				// Debounce rapid changes
				if debounceTimer != nil && !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}

				debounceTimer = time.AfterFunc(utils.WatcherDebounce, func() {
					log.Info("Debounced configuration reload triggered")
					reloadConfigAndTrigger()
				})
			}
		case err, ok := <-configWatcher.Errors:
			if !ok {
				log.Info("Configuration watcher errors channel closed")
				return
			}
			log.WithError(err).Warn("Configuration file watcher error")
		}
	}
}

// Command Line Interface
// =====================

// arrayFlags allows multiple flag values for certificate directories
type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

// parseCommandLineFlags parses and applies command line flags
func parseCommandLineFlags() *config.Config {
	var (
		certDirs    arrayFlags
		logFile     string
		port        string
		bindAddr    string
		numWorkers  int
		configFile  string
		dryRun      bool
		expiryDays  int
		clearCache  bool
		tlsCert     string
		tlsKey      string
		enablePprof bool
		checkConfig bool
	)

	// Define command line flags
	flag.Var(&certDirs, "cert-dir", "Certificate directory (repeatable)")
	flag.StringVar(&logFile, "log-file", "", "Log file path")
	flag.StringVar(&port, "port", "", "Metrics server port")
	flag.StringVar(&bindAddr, "bind-address", "", "Bind address for metrics server")
	flag.IntVar(&numWorkers, "workers", 0, "Number of workers")
	flag.StringVar(&configFile, "config", "", "YAML configuration file path")
	flag.BoolVar(&dryRun, "dry-run", false, "Run once and log only (no metrics)")
	flag.IntVar(&expiryDays, "expiry-threshold-days", utils.DefaultExpiryDays, "Days to consider certificate expiring soon")
	flag.BoolVar(&clearCache, "clear-cache-on-reload", false, "Clear certificate cache on reload")
	flag.StringVar(&tlsCert, "tls-cert-file", "", "TLS certificate file for HTTPS server")
	flag.StringVar(&tlsKey, "tls-key-file", "", "TLS key file for HTTPS server")
	flag.BoolVar(&enablePprof, "enable-pprof", false, "Enable pprof debug endpoints")
	flag.BoolVar(&checkConfig, "check-config", false, "Validate configuration and exit")

	flag.Parse()

	// Store config file path globally
	globalState.configFilePath = configFile

	// Handle config validation mode
	if checkConfig {
		handleConfigValidation(configFile)
	}

	// Load configuration from file
	if err := loadConfigFromFile(configFile); err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	// Apply command line overrides
	cfg := globalState.getConfig()
	if cfg == nil {
		cfg = config.Default()
		globalState.setConfig(cfg)
	}

	applyCommandLineOverrides(cfg, &certDirs, logFile, port, bindAddr, numWorkers,
		dryRun, expiryDays, clearCache, tlsCert, tlsKey, enablePprof)
	applyEnvironmentOverrides(cfg)

	return cfg
}

// handleConfigValidation validates configuration and exits
func handleConfigValidation(configFile string) {
	log.Info("Running configuration validation mode")

	if err := loadConfigFromFile(configFile); err != nil {
		log.WithError(err).Fatal("Configuration validation failed")
	}

	if err := config.Validate(globalState.getConfig()); err != nil {
		log.WithError(err).Fatal("Configuration validation failed")
	}

	log.Info("Configuration validation successful")
	os.Exit(0)
}

// applyCommandLineOverrides applies command line flag overrides to configuration
func applyCommandLineOverrides(cfg *config.Config, certDirs *arrayFlags, logFile, port, bindAddr string,
	numWorkers int, dryRun bool, expiryDays int, clearCache bool, tlsCert, tlsKey string, enablePprof bool) {

	if len(*certDirs) > 0 {
		cfg.CertDirs = *certDirs
	}
	if logFile != "" {
		cfg.LogFile = logFile
	}
	if port != "" {
		cfg.Port = port
	}
	if bindAddr != "" {
		cfg.BindAddress = bindAddr
	}
	if numWorkers > 0 {
		cfg.NumWorkers = numWorkers
	}
	if dryRun {
		cfg.DryRun = true
	}
	if expiryDays > 0 {
		cfg.ExpiryThresholdDays = expiryDays
	}
	if clearCache {
		cfg.ClearCacheOnReload = true
	}
	if tlsCert != "" {
		cfg.TLSCertFile = tlsCert
	}
	if tlsKey != "" {
		cfg.TLSKeyFile = tlsKey
	}
	if enablePprof {
		cfg.EnablePprof = true
	}
}

// applyEnvironmentOverrides applies environment variable overrides to configuration
func applyEnvironmentOverrides(cfg *config.Config) {
	envOverrides := map[string]func(string){
		"CERT_DIRS": func(v string) {
			if v != "" {
				cfg.CertDirs = strings.Split(v, ":")
			}
		},
		"LOG_FILE": func(v string) {
			if v != "" {
				cfg.LogFile = v
			}
		},
		"PORT": func(v string) {
			if v != "" {
				cfg.Port = v
			}
		},
		"BIND_ADDRESS": func(v string) {
			if v != "" {
				cfg.BindAddress = v
			}
		},
		"NUM_WORKERS": func(v string) {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.NumWorkers = n
			}
		},
		"DRY_RUN": func(v string) {
			if strings.EqualFold(v, "true") {
				cfg.DryRun = true
			}
		},
		"EXPIRY_THRESHOLD_DAYS": func(v string) {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.ExpiryThresholdDays = n
			}
		},
		"CLEAR_CACHE_ON_RELOAD": func(v string) {
			if strings.EqualFold(v, "true") {
				cfg.ClearCacheOnReload = true
			}
		},
		"TLS_CERT_FILE": func(v string) {
			if v != "" {
				cfg.TLSCertFile = v
			}
		},
		"TLS_KEY_FILE": func(v string) {
			if v != "" {
				cfg.TLSKeyFile = v
			}
		},
		"ENABLE_PPROF": func(v string) {
			if strings.EqualFold(v, "true") {
				cfg.EnablePprof = true
			}
		},
		"ENABLE_RUNTIME_METRICS": func(v string) {
			if strings.EqualFold(v, "true") {
				cfg.EnableRuntimeMetrics = true
			}
		},
		"ENABLE_WEAK_CRYPTO_METRICS": func(v string) {
			if strings.EqualFold(v, "true") {
				cfg.EnableWeakCryptoMetrics = true
			}
		},
	}

	for envVar, applyFunc := range envOverrides {
		if value := os.Getenv(envVar); value != "" {
			applyFunc(value)
		}
	}
}

// performDryRun executes a dry run scan and exits
func performDryRun(cfg *config.Config) {
	log.Info("Starting dry-run mode - processing leaf certificates only")

	for _, dir := range cfg.CertDirs {
		log.WithField("directory", dir).Info("Processing directory in dry-run mode")
		resetMetrics(true)

		duplicates := processCertificateDirectory(dir, true)

		if len(duplicates) > 0 {
			log.Info("Duplicate leaf certificates found:")
			for fingerprint, count := range duplicates {
				log.WithFields(log.Fields{
					"fingerprint": fingerprint[:16],
					"occurrences": count,
				}).Info("Duplicate certificate")
			}
		} else {
			log.Info("No duplicate certificates found")
		}
	}

	log.Info("Dry-run completed successfully")
}

// Main Function
// =============

func main() {
	// Parse configuration and command line arguments
	cfg := parseCommandLineFlags()

	// Initialize metrics registry
	metricsConfig := metrics.Config{
		EnableRuntimeMetrics:    cfg.EnableRuntimeMetrics,
		EnableWeakCryptoMetrics: cfg.EnableWeakCryptoMetrics,
		Registry:                nil, // Use default registry
	}
	metricsRegistry = metrics.NewRegistry(metricsConfig)
	log.Info("Metrics system initialized")

	// Initialize logging
	initLogger(cfg.LogFile, cfg.DryRun)

	// Initialize cache
	cacheConfig := cache.Config{
		FilePath:    cfg.CacheFile,
		AutoSave:    false,
		MaxEntries:  0, // No limit
		EnableStats: true,
	}
	cacheManager = cache.NewManager(cacheConfig)

	if err := cacheManager.Load(cfg.CacheFile); err != nil {
		log.WithError(err).Warn("Cache loading failed, starting with empty cache")
	}

	// Prune stale cache entries
	if removed := cacheManager.Prune(); removed > 0 {
		log.WithField("removed_entries", removed).Info("Removed stale cache entries during startup")

		if err := cacheManager.Save(cfg.CacheFile); err != nil {
			log.WithError(err).Warn("Failed to save cache after pruning")
		} else {
			log.Info("Cache saved successfully after startup pruning")
		}
	} else {
		log.Info("No stale cache entries found during startup validation")
	}

	// Log initial cache state

	stats := cacheManager.Stats()
	log.WithFields(log.Fields{
		"cache_file":    stats.CacheFilePath,
		"cache_entries": stats.TotalEntries,
		"cache_hits":    stats.CacheHits,
		"cache_misses":  stats.CacheMisses,
	}).Info("Certificate cache initialized for startup")

	// Log startup information
	log.WithFields(log.Fields{
		"version":               Version,
		"commit":                Commit,
		"certificate_dirs":      len(cfg.CertDirs),
		"log_file":              cfg.LogFile,
		"port":                  cfg.Port,
		"bind_address":          cfg.BindAddress,
		"num_workers":           cfg.NumWorkers,
		"dry_run":               cfg.DryRun,
		"expiry_threshold_days": cfg.ExpiryThresholdDays,
		"processing_mode":       "leaf_certificates_only",
		"hot_reload_enabled":    globalState.configFilePath != "",
		"config_file":           globalState.configFilePath,
	}).Info("SSL Certificate Monitor starting")

	// Handle dry-run mode
	if cfg.DryRun {
		performDryRun(cfg)
		return
	}

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Initialize reload channel
	globalState.reloadCh = make(chan struct{}, 1)
	globalState.reloadCh <- struct{}{} // Trigger initial scan

	// Start background services
	go runRuntimeMetricsCollector(ctx)
	go runMainProcessingLoop(ctx)

	// Setup file system watcher
	watcher, err := setupFileSystemWatcher(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to setup file system watcher")
	}
	defer watcher.Close()

	go runFileSystemWatcher(ctx, watcher)

	// Setup configuration file watcher
	go setupConfigWatcher(ctx, globalState.configFilePath)

	// Initialize HTTP server
	serverConfig := &server.Config{
		Port:            cfg.Port,
		BindAddress:     cfg.BindAddress,
		TLSCertFile:     cfg.TLSCertFile,
		TLSKeyFile:      cfg.TLSKeyFile,
		EnablePprof:     cfg.EnablePprof,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}

	serverDeps := &server.Dependencies{
		Config:          cfg,
		MetricsRegistry: metricsRegistry,
		CacheManager:    cacheManager,
		ConfigFilePath:  globalState.configFilePath,
		ReloadChannel:   globalState.reloadCh,
	}

	httpServer := server.New(serverConfig, serverDeps)
	if err := httpServer.Start(ctx); err != nil {
		log.WithError(err).Fatal("Failed to start HTTP server")
	}

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info("Shutdown signal received, beginning graceful shutdown")

	// Perform graceful shutdown
	performGracefulShutdown(httpServer, watcher)

	log.Info("SSL Certificate Monitor stopped successfully")
}

// performGracefulShutdown handles the graceful shutdown process
func performGracefulShutdown(httpServer server.Server, watcher *fsnotify.Watcher) {
	// Close reload channel
	log.Info("Closing reload channel")
	close(globalState.reloadCh)

	// Close file system watcher
	log.Info("Closing file system watcher")
	if err := watcher.Close(); err != nil {
		log.WithError(err).Warn("Error closing file system watcher")
	}

	// Clean up watcher state
	globalState.watchedDirsLock.Lock()
	for path := range globalState.watchedDirs {
		delete(globalState.watchedDirs, path)
	}
	globalState.watchedDirsLock.Unlock()
	globalState.mainWatcher = nil

	if err := httpServer.Stop(context.Background()); err != nil {
		log.WithError(err).Warn("HTTP server shutdown error")
	}

	// Log final cache statistics before shutdown

	if cacheManager != nil {
		stats := cacheManager.Stats()
		log.WithFields(log.Fields{
			"final_cache_entries": stats.TotalEntries,
			"total_cache_hits":    stats.CacheHits,
			"total_cache_misses":  stats.CacheMisses,
			"final_hit_rate":      fmt.Sprintf("%.2f%%", stats.HitRate),
		}).Info("Final cache statistics before shutdown")

		// Save final cache state
		if err := cacheManager.Save(stats.CacheFilePath); err != nil {
			log.WithError(err).Warn("Failed to save cache during shutdown")
		} else {
			log.Info("Certificate cache saved successfully during shutdown")
		}
	}
}

// loadConfigFromFile loads configuration from file using new config package
func loadConfigFromFile(configFile string) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}

	globalState.setConfig(cfg)

	log.WithFields(log.Fields{
		"config_file": configFile,
		"cert_dirs":   len(cfg.CertDirs),
		"port":        cfg.Port,
		"workers":     cfg.NumWorkers,
	}).Info("Configuration loaded successfully")

	return nil
}
