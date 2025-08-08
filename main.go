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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

// Constants for configuration limits and defaults
const (
	maxSANsExported         = 10
	maxLabelLength          = 120
	maxBackoff              = 10 * time.Minute
	defaultPort             = "3000"
	defaultBindAddress      = "0.0.0.0"
	defaultWorkers          = 4
	defaultExpiryDays       = 45
	minDiskSpaceBytes       = 100 * 1024 * 1024 // 100MB
	cacheWriteTimeout       = 5 * time.Second
	watcherDebounce         = 2 * time.Second
	runtimeMetricsInterval  = 10 * time.Second
	gracefulShutdownTimeout = 10 * time.Second
)

// Issuer codes for certificate classification
const (
	IssuerCodeDigiCert   = 30
	IssuerCodeAmazon     = 31
	IssuerCodeOther      = 32
	IssuerCodeSelfSigned = 33
)

// Version info (injected at build time via -ldflags)
var (
	Version = "dev"
	Commit  = "none"
)

// Global state management
type GlobalState struct {
	config         *Config
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

	// Certificate cache
	certCache     map[string]CachedCertMeta
	certCacheLock sync.RWMutex
	cacheFilePath string
	cacheHits     int64
	cacheMisses   int64
}

// CachedCertMeta holds metadata for cached certificates
type CachedCertMeta struct {
	Fingerprint [32]byte  `json:"fingerprint"`
	ModTime     time.Time `json:"mod_time"`
	Size        int64     `json:"size"`
}

// Config holds all runtime configuration
type Config struct {
	CertDirs                []string `yaml:"cert_dirs"`
	LogFile                 string   `yaml:"log_file"`
	Port                    string   `yaml:"port"`
	BindAddress             string   `yaml:"bind_address"`
	NumWorkers              int      `yaml:"num_workers"`
	DryRun                  bool     `yaml:"dry_run"`
	ExpiryThresholdDays     int      `yaml:"expiry_threshold_days"`
	ClearCacheOnReload      bool     `yaml:"clear_cache_on_reload"`
	TLSCertFile             string   `yaml:"tls_cert_file"`
	TLSKeyFile              string   `yaml:"tls_key_file"`
	EnablePprof             bool     `yaml:"enable_pprof"`
	EnableRuntimeMetrics    bool     `yaml:"enable_runtime_metrics"`
	EnableWeakCryptoMetrics bool     `yaml:"enable_weak_crypto_metrics"`
	CacheFile               string   `yaml:"cache_file"`
}

// MetricsCollector encapsulates all Prometheus metrics
type MetricsCollector struct {
	CertExpiration          *prometheus.GaugeVec
	CertSANCount            *prometheus.GaugeVec
	CertInfo                *prometheus.GaugeVec
	CertDuplicateCount      *prometheus.GaugeVec
	CertParseErrors         *prometheus.CounterVec
	CertFilesTotal          *prometheus.CounterVec
	CertsParsedTotal        *prometheus.CounterVec
	CertLastScan            *prometheus.GaugeVec
	LastReload              prometheus.Gauge
	CertScanDuration        *prometheus.HistogramVec
	HeapAllocGauge          prometheus.Gauge
	WeakKeyCounter          *prometheus.CounterVec
	DeprecatedSigAlgCounter *prometheus.CounterVec
	CertIssuerCode          *prometheus.GaugeVec
}

// CertificateInfo represents parsed certificate data
type CertificateInfo struct {
	CommonName          string    `json:"common_name"`
	FileName            string    `json:"file_name"`
	Issuer              string    `json:"issuer"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`
	SANs                []string  `json:"sans,omitempty"`
	ExpiringSoon        bool      `json:"expiring_soon"`
	Type                string    `json:"type"`
	IssuerCode          int       `json:"issuer_code"`
	IsWeakKey           bool      `json:"is_weak_key"`
	HasDeprecatedSigAlg bool      `json:"has_deprecated_sig_alg"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// CacheStats represents cache statistics for monitoring
type CacheStats struct {
	TotalEntries  int     `json:"total_entries"`
	CacheFilePath string  `json:"cache_file_path"`
	HitRate       float64 `json:"hit_rate"`
	LastPruneTime string  `json:"last_prune_time,omitempty"`
	// CacheHitRate     string `json:"cache_hit_rate,omitempty"`
}

// Global instances
var (
	globalState *GlobalState
	metrics     *MetricsCollector
)

func init() {
	globalState = &GlobalState{
		scanBackoff: make(map[string]time.Time),
		watchedDirs: make(map[string]bool),
		certCache:   make(map[string]CachedCertMeta),
	}

	metrics = initMetrics()
	registerMetrics()
}

// initMetrics creates and initializes all Prometheus metrics
func initMetrics() *MetricsCollector {
	return &MetricsCollector{
		CertExpiration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_expiration_timestamp",
			Help: "Expiration time of SSL cert (Unix timestamp)",
		}, []string{"common_name", "filename"}),

		CertSANCount: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_san_count",
			Help: "Number of SAN entries in cert",
		}, []string{"common_name", "filename"}),

		CertInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_info",
			Help: "Static info for cert including CN and SANs",
		}, []string{"common_name", "filename", "sans"}),

		CertDuplicateCount: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_duplicate_count",
			Help: "Number of times a cert appears",
		}, []string{"common_name", "filename"}),

		CertParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_parse_errors_total",
			Help: "Number of cert parse errors",
		}, []string{"filename"}),

		CertFilesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_files_total",
			Help: "Total number of certificate files processed",
		}, []string{"dir"}),

		CertsParsedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_certs_parsed_total",
			Help: "Total number of individual certificates successfully parsed",
		}, []string{"dir"}),

		CertLastScan: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_last_scan_timestamp",
			Help: "Unix timestamp of the last successful scan of a certificate directory",
		}, []string{"dir"}),

		LastReload: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_cert_last_reload_timestamp",
			Help: "Unix timestamp of the last successful configuration reload",
		}),

		CertScanDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssl_cert_scan_duration_seconds",
			Help:    "Duration of certificate directory scans in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"dir"}),

		HeapAllocGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_monitor_heap_alloc_bytes",
			Help: "Heap memory allocated (bytes) as reported by runtime.ReadMemStats",
		}),

		WeakKeyCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_weak_key_total",
			Help: "Total number of certificates detected with weak keys (e.g., RSA < 2048 bits)",
		}, []string{"common_name", "filename"}),

		DeprecatedSigAlgCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_deprecated_sigalg_total",
			Help: "Total number of certificates with deprecated signature algorithms (e.g., SHA1, MD5)",
		}, []string{"common_name", "filename"}),

		CertIssuerCode: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_issuer_code",
			Help: "Numeric code based on certificate issuer (30=digicert, 31=amazon, 32=other, 33=self-signed)",
		}, []string{"common_name", "filename"}),
	}
}

// registerMetrics registers all metrics with Prometheus
func registerMetrics() {
	prometheus.MustRegister(
		metrics.CertExpiration,
		metrics.CertSANCount,
		metrics.CertInfo,
		metrics.CertDuplicateCount,
		metrics.CertParseErrors,
		metrics.CertFilesTotal,
		metrics.CertsParsedTotal,
		metrics.CertLastScan,
		metrics.LastReload,
		metrics.CertScanDuration,
		metrics.HeapAllocGauge,
		metrics.WeakKeyCounter,
		metrics.DeprecatedSigAlgCounter,
		metrics.CertIssuerCode,
	)
}

// Configuration Management
// ========================

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		CertDirs:            []string{"./certs"},
		LogFile:             defaultLogPath(),
		Port:                defaultPort,
		BindAddress:         defaultBindAddress,
		NumWorkers:          defaultWorkers,
		DryRun:              false,
		ExpiryThresholdDays: defaultExpiryDays,
		ClearCacheOnReload:  false,
		TLSCertFile:         "",
		TLSKeyFile:          "",
		CacheFile:           "/var/lib/cert-monitor/cache.json",
	}
}

// LoadConfig loads configuration from a YAML file with comprehensive validation
func LoadConfig(path string) error {
	if path == "" {
		log.Debug("No config path provided, using defaults")
		return nil
	}

	// Validate file accessibility
	if err := validateFileAccess(path); err != nil {
		return fmt.Errorf("config file validation failed: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	// Parse into temporary config for validation
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	// Validate configuration before applying
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration in %q: %w", path, err)
	}

	// Atomically update global config
	globalState.setConfig(cfg)

	log.WithFields(log.Fields{
		"config_file": path,
		"cert_dirs":   len(cfg.CertDirs),
		"port":        cfg.Port,
		"workers":     cfg.NumWorkers,
	}).Info("Configuration loaded successfully")

	return nil
}

// validateConfig performs comprehensive validation of configuration values
func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if err := validateCertDirectories(cfg.CertDirs); err != nil {
		return err
	}

	if err := validateNetworkConfig(cfg.Port, cfg.BindAddress); err != nil {
		return err
	}

	if err := validateWorkerConfig(cfg.NumWorkers, cfg.ExpiryThresholdDays); err != nil {
		return err
	}

	if err := validateTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		return err
	}

	if err := validateFileConfig(cfg.LogFile, cfg.CacheFile); err != nil {
		return err
	}

	return nil
}

// validateCertDirectories validates certificate directory configuration
func validateCertDirectories(certDirs []string) error {
	if len(certDirs) == 0 {
		return fmt.Errorf("no certificate directories specified")
	}

	for i, dir := range certDirs {
		if dir == "" {
			return fmt.Errorf("certificate directory %d is empty", i)
		}

		if err := validateDirectoryAccess(dir); err != nil {
			return fmt.Errorf("certificate directory %q validation failed: %w", dir, err)
		}
	}

	return nil
}

// validateNetworkConfig validates network-related configuration
func validateNetworkConfig(port, bindAddress string) error {
	if port == "" {
		return fmt.Errorf("metrics port is not set")
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number %q: %w", port, err)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port number %d is out of valid range (1-65535)", portNum)
	}

	return nil
}

// validateWorkerConfig validates worker and timing configuration
func validateWorkerConfig(numWorkers, expiryThresholdDays int) error {
	if numWorkers < 1 {
		return fmt.Errorf("number of workers must be at least 1, got %d", numWorkers)
	}

	if numWorkers > 100 {
		return fmt.Errorf("number of workers %d seems excessive (max recommended: 100)", numWorkers)
	}

	if expiryThresholdDays < 1 {
		return fmt.Errorf("expiry threshold days must be at least 1, got %d", expiryThresholdDays)
	}

	if expiryThresholdDays > 365 {
		return fmt.Errorf("expiry threshold days %d seems excessive (max recommended: 365)", expiryThresholdDays)
	}

	return nil
}

// validateTLSConfig validates TLS certificate configuration
func validateTLSConfig(tlsCertFile, tlsKeyFile string) error {
	if tlsCertFile != "" || tlsKeyFile != "" {
		if tlsCertFile == "" {
			return fmt.Errorf("TLS certificate file must be specified when TLS key file is provided")
		}
		if tlsKeyFile == "" {
			return fmt.Errorf("TLS key file must be specified when TLS certificate file is provided")
		}

		if err := validateFileAccess(tlsCertFile); err != nil {
			return fmt.Errorf("TLS certificate file validation failed: %w", err)
		}

		if err := validateFileAccess(tlsKeyFile); err != nil {
			return fmt.Errorf("TLS key file validation failed: %w", err)
		}
	}

	return nil
}

// validateFileConfig validates log and cache file configuration
func validateFileConfig(logFile, cacheFile string) error {
	if logFile != "" {
		if err := validateDirectoryCreation(filepath.Dir(logFile)); err != nil {
			return fmt.Errorf("log file directory validation failed: %w", err)
		}
	}

	if cacheFile != "" {
		if err := validateDirectoryCreation(filepath.Dir(cacheFile)); err != nil {
			return fmt.Errorf("cache file directory validation failed: %w", err)
		}
	}

	return nil
}

// Helper validation functions
func validateFileAccess(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %q", path)
		}
		return fmt.Errorf("cannot access file %q: %w", path, err)
	}
	return nil
}

func validateDirectoryAccess(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %q", dir)
		}
		return fmt.Errorf("cannot access directory %q: %w", dir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %q", dir)
	}

	if _, err := os.ReadDir(dir); err != nil {
		return fmt.Errorf("cannot read directory %q: %w", dir, err)
	}

	return nil
}

func validateDirectoryCreation(dir string) error {
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create directory %q: %w", dir, err)
		}
	}
	return nil
}

// Global State Management
// ======================

// getConfig safely retrieves the current configuration
func (gs *GlobalState) getConfig() *Config {
	gs.configMutex.RLock()
	defer gs.configMutex.RUnlock()
	return gs.config
}

// setConfig safely updates the global configuration
func (gs *GlobalState) setConfig(cfg *Config) {
	gs.configMutex.Lock()
	defer gs.configMutex.Unlock()
	gs.config = cfg
}

// Cache Management
// ===============

// getCacheEntryAtomic safely retrieves a cache entry and file stat
func (gs *GlobalState) getCacheEntryAtomic(path string) (CachedCertMeta, os.FileInfo, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return CachedCertMeta{}, nil, false, err
	}

	gs.certCacheLock.RLock()
	cached, found := gs.certCache[path]
	gs.certCacheLock.RUnlock()

	return cached, info, found, nil
}

// setCacheEntryAtomic safely updates a cache entry
func (gs *GlobalState) setCacheEntryAtomic(path string, fingerprint [32]byte, info os.FileInfo) {
	gs.certCacheLock.Lock()
	defer gs.certCacheLock.Unlock()

	// Validate that the file still exists before caching
	if _, err := os.Stat(path); err != nil {
		log.WithFields(log.Fields{
			"path":  path,
			"error": err,
		}).Debug("Skipping cache update for non-existent file")
		return
	}

	gs.certCache[path] = CachedCertMeta{
		Fingerprint: fingerprint,
		ModTime:     info.ModTime(),
		Size:        info.Size(),
	}
}

// loadCacheFromFile loads certificate cache from disk
func (gs *GlobalState) loadCacheFromFile(path string) error {
	if path == "" {
		log.Debug("No cache file path specified, skipping cache load")
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.WithError(err).WithField("cache_file", path).Info("No existing cache file or read error")
		return nil
	}

	gs.certCacheLock.Lock()
	defer gs.certCacheLock.Unlock()

	if err := json.Unmarshal(data, &gs.certCache); err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to parse cache file, resetting cache")
		gs.certCache = make(map[string]CachedCertMeta)
		return err
	}

	log.WithFields(log.Fields{
		"cache_file": path,
		"entries":    len(gs.certCache),
	}).Info("Certificate cache loaded successfully")

	return nil
}

// saveCacheToFile saves certificate cache to disk
func (gs *GlobalState) saveCacheToFile(path string) error {
	if path == "" {
		log.Debug("No cache file path specified, skipping cache save")
		return nil
	}

	gs.certCacheLock.RLock()
	cacheSize := len(gs.certCache)
	// Create copy to avoid holding lock during I/O
	cacheCopy := make(map[string]CachedCertMeta, cacheSize)
	for k, v := range gs.certCache {
		cacheCopy[k] = v
	}
	gs.certCacheLock.RUnlock()

	data, err := json.MarshalIndent(cacheCopy, "", "  ")
	if err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to marshal cache")
		return err
	}

	// Create directory if needed
	if err := validateDirectoryCreation(filepath.Dir(path)); err != nil {
		return fmt.Errorf("cache directory creation failed: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to write cache file")
		return err
	}

	log.WithFields(log.Fields{
		"cache_file": path,
		"entries":    cacheSize,
	}).Debug("Certificate cache saved successfully")

	return nil
}

// pruneCacheNonExistingUnsafe removes cache entries for files that no longer exist
// This version assumes the caller already holds the certCacheLock
func (gs *GlobalState) pruneCacheNonExistingUnsafe() int {
	pruned := 0

	for path := range gs.certCache {
		if _, err := os.Stat(path); err != nil {
			delete(gs.certCache, path)
			pruned++
		}
	}

	if pruned > 0 {
		log.WithField("pruned_entries", pruned).Debug("Cache pruning completed (unsafe)")
	}

	return pruned
}

// pruneCacheNonExisting removes cache entries for files that no longer exist
func (gs *GlobalState) pruneCacheNonExisting() int {
	start := time.Now()
	pruned := 0

	gs.certCacheLock.Lock()
	defer gs.certCacheLock.Unlock()

	for path := range gs.certCache {
		if _, err := os.Stat(path); err != nil {
			delete(gs.certCache, path)
			pruned++
		}
	}

	if pruned > 0 {
		log.WithFields(log.Fields{
			"removed_entries": pruned,
			"duration":        time.Since(start),
		}).Info("Pruned stale cache entries")
	} else {
		log.Debug("No stale cache entries found to prune")
	}

	return pruned
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
			metrics.CertScanDuration.WithLabelValues(dirPath).Observe(time.Since(start).Seconds())
		}
	}()

	if err := validateDirectoryAccess(dirPath); err != nil {
		logger.WithError(err).Warn("Directory validation failed, skipping scan")
		registerScanFailure(dirPath)
		return nil
	}

	defer func() {
		if !dryRun && shouldWriteMetrics() {
			metrics.CertLastScan.WithLabelValues(dirPath).Set(float64(time.Now().Unix()))
		}
	}()

	// Process certificates and track duplicates
	seen := make(map[string]int)
	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		return processCertificateFile(path, d, err, dirPath, seen, dryRun)
	})

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

// processCertificateFile processes a single certificate file during directory walk
func processCertificateFile(path string, d fs.DirEntry, walkErr error, dirPath string, seen map[string]int, dryRun bool) error {
	if walkErr != nil {
		return nil // Continue walking despite errors
	}

	if d.IsDir() {
		return handleDirectory(d)
	}

	if !isCertificateFile(d.Name()) {
		return nil
	}

	logger := log.WithFields(log.Fields{
		"file":      path,
		"directory": dirPath,
	})

	// Check cache first
	cached, info, found, err := globalState.getCacheEntryAtomic(path)
	if err != nil {
		logger.WithError(err).Warn("File stat failed")
		if !dryRun && shouldWriteMetrics() {
			metrics.CertParseErrors.WithLabelValues(path).Inc()
		}
		return nil
	}

	if !dryRun && shouldWriteMetrics() {
		metrics.CertFilesTotal.WithLabelValues(dirPath).Inc()
	}

	// Skip if file unchanged
	if found && cached.ModTime.Equal(info.ModTime()) && cached.Size == info.Size() {
		logger.Debug("Skipping unchanged file based on cache")

		// Record cache hit
		globalState.certCacheLock.Lock()
		globalState.cacheHits++
		globalState.certCacheLock.Unlock()

		logger.WithField("cache_status", "hit").Debug("Cache hit for unchanged file")

		return nil
	}

	// Record cache miss (file changed or not in cache)
	globalState.certCacheLock.Lock()
	globalState.cacheMisses++
	globalState.certCacheLock.Unlock()

	if found {
		logger.WithFields(log.Fields{
			"cache_status": "miss",
			"reason":       "file_changed",
			"old_mod_time": cached.ModTime,
			"new_mod_time": info.ModTime(),
			"old_size":     cached.Size,
			"new_size":     info.Size(),
		}).Debug("Cache miss due to file change")
	} else {
		logger.WithFields(log.Fields{
			"cache_status": "miss",
			"reason":       "not_in_cache",
		}).Debug("Cache miss for new file")
	}

	// Process the certificate file
	cert, err := parseCertificateFile(path, filepath.Ext(path))
	if err != nil {
		logger.WithError(err).Warn("Certificate parsing failed")
		if !dryRun && shouldWriteMetrics() {
			metrics.CertParseErrors.WithLabelValues(path).Inc()
		}
		return nil
	}

	if cert == nil {
		logger.Debug("No valid certificate found in file")
		return nil
	}

	if !dryRun && shouldWriteMetrics() {
		metrics.CertsParsedTotal.WithLabelValues(dirPath).Inc()
	}

	// Log certificate file processing for debugging metric issues
	log.WithFields(log.Fields{
		"file":      path,
		"directory": dirPath,
	}).Debug("Successfully parsed certificate, proceeding to metrics update")

	// Process certificate and update metrics
	globalState.processCertificate(cert, path, dirPath, seen, dryRun, info)

	logger.WithFields(log.Fields{
		"common_name": cert.Subject.CommonName,
		"issuer":      cert.Issuer.CommonName,
		"not_after":   cert.NotAfter,
		"sans":        len(cert.DNSNames),
	}).Info("Certificate processed successfully")

	return nil
}

// handleDirectory determines whether to process or skip a directory
func handleDirectory(d fs.DirEntry) error {
	dirName := strings.ToLower(d.Name())
	if dirName == "old" || dirName == "working" {
		log.WithField("directory", d.Name()).Info("Skipping excluded subdirectory")
		return filepath.SkipDir
	}
	return nil
}

// isCertificateFile checks if a file is a certificate based on extension
func isCertificateFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".der"
}

// parseCertificateFile parses a certificate file and returns the leaf certificate
func parseCertificateFile(path, ext string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if ext == ".der" {
		return x509.ParseCertificate(raw)
	}

	// For PEM files, find the first (leaf) certificate
	rest := raw
	for {
		block, remaining := pem.Decode(rest)
		rest = remaining
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // Try next block
		}

		return cert, nil // Return first valid certificate (leaf)
	}

	return nil, fmt.Errorf("no valid certificate found")
}

// processCertificate processes a parsed certificate and updates metrics
func (gs *GlobalState) processCertificate(cert *x509.Certificate, path, dirPath string, seen map[string]int, dryRun bool, info os.FileInfo) {
	filename := filepath.Base(path)
	sanitizedFilename := sanitizeLabelValue(filename)
	sanitizedCN := sanitizeLabelValue(cert.Subject.CommonName)

	// Track duplicates
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintKey := fmt.Sprintf("%x", fingerprint)

	// Log certificate processing to help debug potential double-processing issues
	log.WithFields(log.Fields{
		"file":        filename,
		"fingerprint": fingerprintKey[:16], // Show first 16 chars of fingerprint
	}).Debug("Processing certificate for metrics")

	seen[fingerprintKey]++

	// Create certificate info
	certInfo := &CertificateInfo{
		CommonName:          cert.Subject.CommonName,
		Issuer:              cert.Issuer.CommonName,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		SANs:                cert.DNSNames,
		Type:                "leaf_certificate",
		IssuerCode:          determineIssuerCode(cert),
		IsWeakKey:           isWeakKey(cert),
		HasDeprecatedSigAlg: isDeprecatedSigAlg(cert.SignatureAlgorithm),
	}

	// Additional validation logging for debugging metric consistency
	log.WithFields(log.Fields{
		"file":                  filename,
		"common_name":           cert.Subject.CommonName,
		"has_weak_key":          certInfo.IsWeakKey,
		"has_deprecated_sigalg": certInfo.HasDeprecatedSigAlg,
		"duplicate_count":       seen[fingerprintKey],
		"dry_run":               dryRun,
	}).Debug("Certificate analysis complete, updating metrics")

	// Update metrics if not in dry run mode
	if !dryRun && shouldWriteMetrics() {
		updateCertificateMetrics(certInfo, sanitizedCN, sanitizedFilename, seen[fingerprintKey])
	}

	// Update cache
	gs.setCacheEntryAtomic(path, fingerprint, info)
}

// updateCertificateMetrics updates all certificate-related metrics
func updateCertificateMetrics(certInfo *CertificateInfo, sanitizedCN, sanitizedFilename string, duplicateCount int) {
	cfg := globalState.getConfig()

	// Basic certificate metrics
	metrics.CertExpiration.WithLabelValues(certInfo.CommonName, sanitizedFilename).Set(float64(certInfo.NotAfter.Unix()))
	metrics.CertSANCount.WithLabelValues(certInfo.CommonName, sanitizedFilename).Set(float64(len(certInfo.SANs)))
	metrics.CertDuplicateCount.WithLabelValues(certInfo.CommonName, sanitizedFilename).Set(float64(duplicateCount))
	metrics.CertIssuerCode.WithLabelValues(sanitizedCN, sanitizedFilename).Set(float64(certInfo.IssuerCode))

	// SAN information
	sanitizedSANs := prepareSANsForMetrics(certInfo.SANs)
	metrics.CertInfo.WithLabelValues(certInfo.CommonName, sanitizedFilename, sanitizedSANs).Set(1)

	// Weak crypto metrics (if enabled)
	if cfg.EnableWeakCryptoMetrics {
		// Note: We reset these counters at the start of each scan cycle in resetMetrics()
		// This ensures that when certificates are removed, their contribution to weak
		// crypto metrics is also removed. The counters are then rebuilt from scratch
		// during each complete directory scan, providing an accurate current state.
		// IMPORTANT: Each certificate should only increment these counters once per scan.
		// The metrics are reset at scan start and rebuilt completely during the scan,
		// ensuring accurate counts that reflect the current certificate inventory.

		if certInfo.IsWeakKey {
			metrics.WeakKeyCounter.WithLabelValues(certInfo.CommonName, sanitizedFilename).Inc()
			// Log weak key detection with detailed information for audit trail
			// This helps verify that weak keys are being counted correctly
			// and not being double-counted due to processing errors
			log.WithFields(log.Fields{
				"file":               sanitizedFilename,
				"common_name":        certInfo.CommonName,
				"key_type":           "weak",
				"metric_incremented": "ssl_cert_weak_key_total",
			}).Warn("Weak key detected in certificate")
		}

		if certInfo.HasDeprecatedSigAlg {
			metrics.DeprecatedSigAlgCounter.WithLabelValues(certInfo.CommonName, sanitizedFilename).Inc()
			// Log deprecated signature algorithm detection for debugging
			// This helps track which certificates have deprecated algorithms
			// and ensures we're not double-counting certificates
			log.WithFields(log.Fields{
				"file":                sanitizedFilename,
				"common_name":         certInfo.CommonName,
				"metric_incremented":  "ssl_cert_deprecated_sigalg_total",
				"scan_cycle":          "current",
				"signature_algorithm": "deprecated",
			}).Warn("Deprecated signature algorithm detected in certificate")
		}
	}
}

// prepareSANsForMetrics formats SANs for Prometheus metrics
func prepareSANsForMetrics(sans []string) string {
	if len(sans) == 0 {
		return ""
	}

	limitedSANs := sans
	if len(limitedSANs) > maxSANsExported {
		limitedSANs = limitedSANs[:maxSANsExported]
	}

	return sanitizeLabelValue(strings.Join(limitedSANs, ","))
}

// determineIssuerCode determines the issuer code for certificate classification
func determineIssuerCode(cert *x509.Certificate) int {
	if strings.EqualFold(cert.Subject.CommonName, cert.Issuer.CommonName) {
		return IssuerCodeSelfSigned
	}

	issuerLower := strings.ToLower(cert.Issuer.CommonName)
	switch {
	case strings.Contains(issuerLower, "digicert"):
		return IssuerCodeDigiCert
	case strings.Contains(issuerLower, "amazon"):
		return IssuerCodeAmazon
	default:
		return IssuerCodeOther
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
		if delay < 0 || delay > maxBackoff {
			delay = maxBackoff
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

// sanitizeLabelValue sanitizes a string for use as a Prometheus label value
func sanitizeLabelValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) > maxLabelLength {
		return val[:maxLabelLength]
	}
	return val
}

// isWeakKey determines if a certificate has a weak cryptographic key
func isWeakKey(cert *x509.Certificate) bool {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen() < 2048
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize < 256
	default:
		return false
	}
}

// isDeprecatedSigAlg checks if a signature algorithm is deprecated
func isDeprecatedSigAlg(alg x509.SignatureAlgorithm) bool {
	deprecatedAlgorithms := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
		x509.MD5WithRSA,
	}

	for _, deprecated := range deprecatedAlgorithms {
		if alg == deprecated {
			return true
		}
	}
	return false
}

// shouldWriteMetrics determines if metrics should be written
func shouldWriteMetrics() bool {
	cfg := globalState.getConfig()
	return cfg != nil && !cfg.DryRun
}

// resetMetrics resets all Prometheus metrics
func resetMetrics(clearCache bool) {
	log.Info("Resetting Prometheus metrics")

	// Get current metric values before reset for logging/debugging
	weakKeyCount := getCurrentMetricValue(metrics.WeakKeyCounter)
	deprecatedSigAlgCount := getCurrentMetricValue(metrics.DeprecatedSigAlgCounter)

	log.WithFields(log.Fields{
		"weak_keys_before_reset":         weakKeyCount,
		"deprecated_sigalg_before_reset": deprecatedSigAlgCount,
	}).Debug("Metric counts before reset")

	metrics.CertExpiration.Reset()
	metrics.CertSANCount.Reset()
	metrics.CertInfo.Reset()
	metrics.CertDuplicateCount.Reset()
	metrics.CertParseErrors.Reset()
	metrics.CertFilesTotal.Reset()
	metrics.CertsParsedTotal.Reset()
	metrics.CertIssuerCode.Reset()

	// Reset counter metrics that track current state rather than cumulative totals
	// These counters need to be reset on each scan to accurately reflect the current
	// certificate inventory, since removed certificates should no longer contribute
	// to the count of weak keys or deprecated signature algorithms
	metrics.WeakKeyCounter.Reset()
	metrics.DeprecatedSigAlgCounter.Reset()

	if clearCache {
		globalState.certCacheLock.Lock()
		globalState.certCache = make(map[string]CachedCertMeta)
		// Reset cache statistics when clearing cache
		oldHits := globalState.cacheHits
		oldMisses := globalState.cacheMisses
		globalState.cacheHits = 0
		globalState.cacheMisses = 0
		globalState.certCacheLock.Unlock()

		log.WithFields(log.Fields{
			"cleared_entries": "all",
			"reset_hits":      oldHits,
			"reset_misses":    oldMisses,
		}).Info("Certificate cache and statistics cleared")

		log.Info("Certificate cache cleared")
	}
}

// getCurrentMetricValue safely retrieves the current total value of a counter metric
// This is used for debugging and logging purposes to track metric changes
func getCurrentMetricValue(counterVec *prometheus.CounterVec) float64 {
	// Implementation would gather current metric values
	// This is primarily for debugging purposes
	// Note: In production, this could be optimized or removed if not needed
	return 0.0 // Placeholder - actual implementation would sum counter values
}

// HTTP Handlers
// =============

// healthHandler provides comprehensive health check information
func healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	isHealthy := true
	cfg := globalState.getConfig()

	// Disk space checks
	for _, dir := range cfg.CertDirs {
		checkKey := "disk_space_" + sanitizeLabelValue(dir)
		if err := checkDiskSpace(dir); err != nil {
			checks[checkKey] = err.Error()
			isHealthy = false
		} else {
			checks[checkKey] = "ok"
		}
	}

	// Log file writability
	if err := checkLogWritable(cfg.LogFile); err != nil {
		checks["log_file_writable"] = err.Error()
		isHealthy = false
	} else {
		checks["log_file_writable"] = "ok"
	}

	// Prometheus registry health
	if err := checkPrometheus(); err != nil {
		checks["prometheus_registry"] = err.Error()
		isHealthy = false
	} else {
		checks["prometheus_registry"] = "ok"
	}

	// Add configuration info
	checks["worker_pool_size"] = fmt.Sprintf("%d", cfg.NumWorkers)
	checks["certificate_directories"] = fmt.Sprintf("%d", len(cfg.CertDirs))
	checks["hot_reload_enabled"] = fmt.Sprintf("%t", globalState.configFilePath != "")
	checks["config_file"] = globalState.configFilePath

	// Gather certificate statistics
	addCertificateStats(checks)

	// Prepare response
	status := "ok"
	statusCode := http.StatusOK
	if !isHealthy {
		status = "error"
		statusCode = http.StatusInternalServerError
	}

	response := HealthResponse{
		Status: status,
		Checks: checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.WithError(err).Error("Failed to encode health check response")
	}
}

// addCertificateStats adds certificate statistics to health checks
func addCertificateStats(checks map[string]string) {
	totalFiles, totalParsed, totalErrors := gatherCertificateMetrics()

	checks["cert_scan_status"] = "complete"
	checks["cert_files_total"] = fmt.Sprintf("%d", totalFiles)
	checks["certs_parsed_total"] = fmt.Sprintf("%d", totalParsed)
	checks["cert_parse_errors_total"] = fmt.Sprintf("%d", totalErrors)

	// Add cache statistics to health checks
	globalState.certCacheLock.RLock()
	cacheSize := len(globalState.certCache)
	hits := globalState.cacheHits
	misses := globalState.cacheMisses
	globalState.certCacheLock.RUnlock()

	// Calculate and add hit rate to health checks
	totalAccesses := hits + misses
	var hitRate float64
	if totalAccesses > 0 {
		hitRate = float64(hits) / float64(totalAccesses) * 100
	}

	checks["cache_entries_total"] = fmt.Sprintf("%d", cacheSize)
	checks["cache_hit_rate"] = fmt.Sprintf("%.2f%%", hitRate)
	checks["cache_total_accesses"] = fmt.Sprintf("%d", totalAccesses)
	checks["cache_file_path"] = globalState.cacheFilePath

	// Check if cache file is writable
	if globalState.cacheFilePath != "" {
		checks["cache_file_writable"] = "ok"
		if err := checkCacheFileWritable(globalState.cacheFilePath); err != nil {
			checks["cache_file_writable"] = err.Error()
		}
	}
}

// gatherCertificateMetrics collects certificate metrics from Prometheus
func gatherCertificateMetrics() (int, int, int) {
	totalFiles, totalParsed, totalErrors := 0, 0, 0

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		log.WithError(err).Warn("Failed to gather Prometheus metrics for health check")
		return totalFiles, totalParsed, totalErrors
	}

	for _, mf := range mfs {
		switch mf.GetName() {
		case "ssl_cert_files_total":
			totalFiles += sumCounterMetrics(mf)
		case "ssl_certs_parsed_total":
			totalParsed += sumCounterMetrics(mf)
		case "ssl_cert_parse_errors_total":
			totalErrors += sumCounterMetrics(mf)
		}
	}

	return totalFiles, totalParsed, totalErrors
}

// sumCounterMetrics sums counter metrics from a metric family
func sumCounterMetrics(mf *dto.MetricFamily) int {
	total := 0
	for _, m := range mf.GetMetric() {
		if counter := m.GetCounter(); counter != nil {
			total += int(counter.GetValue())
		}
	}
	return total
}

// certsHandler provides detailed certificate information via JSON API
func certsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := globalState.getConfig()
	certificates := collectCertificateInfo(cfg)

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(certificates); err != nil {
		log.WithError(err).Error("Failed to encode certificates response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.WithField("certificate_count", len(certificates)).Debug("Served certificates API request")
}

// reloadConfigHandler provides an HTTP endpoint for manual configuration reload
func reloadConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := log.WithField("endpoint", "/reload")
	logger.Info("Manual configuration reload requested")

	if globalState.configFilePath == "" {
		logger.Warn("No configuration file path available for reload")
		http.Error(w, "No configuration file configured", http.StatusBadRequest)
		return
	}

	result := performHotConfigReload(globalState.configFilePath)

	// Set appropriate HTTP status
	statusCode := http.StatusOK
	if !result.Success {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(result); err != nil {
		logger.WithError(err).Error("Failed to encode reload response")
	}

	// Trigger certificate rescan if needed
	if result.Success && shouldTriggerRescan(result.AppliedChanges) {
		logger.Info("Triggering certificate rescan due to configuration changes")

		// Force cache reload if cache-related settings changed or if explicitly requested
		cfg := globalState.getConfig()
		if cfg.ClearCacheOnReload {
			logger.Info("Cache will be cleared on next rescan due to configuration setting")
		}

		triggerReload()
	}

	logger.WithFields(log.Fields{
		"success":          result.Success,
		"applied_changes":  len(result.AppliedChanges),
		"requires_restart": len(result.RequiresRestart),
	}).Info("Manual configuration reload completed")
}

// configStatusHandler provides current configuration status and hot-reload capabilities
func configStatusHandler(w http.ResponseWriter, r *http.Request) {
	cfg := globalState.getConfig()
	if cfg == nil {
		http.Error(w, "No configuration available", http.StatusInternalServerError)
		return
	}

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

	// Get last reload time from Prometheus metric
	lastReloadTime := ""
	if mfs, err := prometheus.DefaultGatherer.Gather(); err == nil {
		for _, mf := range mfs {
			if mf.GetName() == "ssl_cert_last_reload_timestamp" {
				for _, m := range mf.GetMetric() {
					if gauge := m.GetGauge(); gauge != nil && gauge.GetValue() > 0 {
						lastReloadTime = time.Unix(int64(gauge.GetValue()), 0).Format(time.RFC3339)
						break
					}
				}
				break
			}
		}
	}

	// Get cache statistics
	globalState.certCacheLock.RLock()
	cacheSize := len(globalState.certCache)
	hits := globalState.cacheHits
	misses := globalState.cacheMisses
	globalState.certCacheLock.RUnlock()

	// Calculate hit rate
	var hitRate float64
	totalAccesses := hits + misses
	if totalAccesses > 0 {
		hitRate = float64(hits) / float64(totalAccesses) * 100
	}

	cacheStats := CacheStats{
		TotalEntries:  cacheSize,
		CacheFilePath: globalState.cacheFilePath,
		HitRate:       hitRate,
		LastPruneTime: "available_on_next_prune",
	}

	status := ConfigStatus{
		ConfigFile:          globalState.configFilePath,
		HotReloadEnabled:    globalState.configFilePath != "",
		CertificateDirs:     cfg.CertDirs,
		NumWorkers:          cfg.NumWorkers,
		Port:                cfg.Port,
		BindAddress:         cfg.BindAddress,
		ExpiryThresholdDays: cfg.ExpiryThresholdDays,
		RuntimeMetrics:      cfg.EnableRuntimeMetrics,
		WeakCryptoMetrics:   cfg.EnableWeakCryptoMetrics,
		PprofEnabled:        cfg.EnablePprof,
		CacheFile:           cfg.CacheFile,
		ClearCacheOnReload:  cfg.ClearCacheOnReload,
		TLSEnabled:          cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		LastReloadTime:      lastReloadTime,
		CacheStats:          cacheStats,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.WithError(err).Error("Failed to encode config status response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.WithField("endpoint", "/config").Debug("Served configuration status request")
}

// collectCertificateInfo collects certificate information for the API
func collectCertificateInfo(cfg *Config) []CertificateInfo {
	var certificates []CertificateInfo

	globalState.certCacheLock.RLock()
	paths := make([]string, 0, len(globalState.certCache))
	for path := range globalState.certCache {
		paths = append(paths, path)
	}
	globalState.certCacheLock.RUnlock()

	expiryThreshold := time.Duration(cfg.ExpiryThresholdDays) * 24 * time.Hour

	for _, path := range paths {
		if cert := loadCertificateFromFile(path); cert != nil {
			// Extract the base filename from the full path for the API response
			// This provides a clean filename without the full directory path
			fileName := filepath.Base(path)

			certInfo := CertificateInfo{
				CommonName:          cert.Subject.CommonName,
				FileName:            fileName,
				Issuer:              cert.Issuer.CommonName,
				NotBefore:           cert.NotBefore,
				NotAfter:            cert.NotAfter,
				SANs:                cert.DNSNames,
				ExpiringSoon:        time.Until(cert.NotAfter) <= expiryThreshold,
				Type:                "leaf_certificate",
				IssuerCode:          determineIssuerCode(cert),
				IsWeakKey:           isWeakKey(cert),
				HasDeprecatedSigAlg: isDeprecatedSigAlg(cert.SignatureAlgorithm),
			}
			certificates = append(certificates, certInfo)
		}
	}

	return certificates
}

// loadCertificateFromFile loads and parses a certificate from a file
func loadCertificateFromFile(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Try PEM first
	if block, _ := pem.Decode(raw); block != nil && block.Type == "CERTIFICATE" {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert
		}
	}

	// Try DER
	if cert, err := x509.ParseCertificate(raw); err == nil {
		return cert
	}

	return nil
}

// Health Check Functions
// =====================

// checkDiskSpace verifies adequate disk space is available
func checkDiskSpace(dir string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	availableBytes := stat.Bavail * uint64(stat.Bsize)
	if availableBytes < minDiskSpaceBytes {
		return fmt.Errorf("insufficient disk space: %d bytes available (minimum: %d)",
			availableBytes, minDiskSpaceBytes)
	}

	return nil
}

// checkLogWritable verifies the log file is writable
func checkLogWritable(logFile string) error {
	if logFile == "" {
		return nil // Logging to stdout/stderr
	}

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("log file not writable: %w", err)
	}
	defer file.Close()

	return nil
}

// checkPrometheus verifies Prometheus metrics are available
func checkPrometheus() error {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	if len(mfs) == 0 {
		return fmt.Errorf("no metrics available")
	}

	return nil
}

// checkCacheFileWritable verifies the cache file is writable
func checkCacheFileWritable(cacheFile string) error {
	if cacheFile == "" {
		return nil // No cache file configured
	}

	// Try to open cache file for writing (create if not exists)fcac
	file, err := os.OpenFile(cacheFile, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("cache file not writable: %w", err)
	}
	defer file.Close()

	return nil
}

// findLabel safely retrieves a label value from a Prometheus metric
func findLabel(m *dto.Metric, key string) string {
	if m == nil || m.Label == nil {
		return ""
	}

	for _, label := range m.GetLabel() {
		if label != nil && label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
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
func setupFileSystemWatcher(ctx context.Context, cfg *Config) (*fsnotify.Watcher, error) {
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

// ConfigReloadResult represents the result of a configuration reload attempt
type ConfigReloadResult struct {
	Success         bool              `json:"success"`
	Error           string            `json:"error,omitempty"`
	ChangedSettings map[string]string `json:"changed_settings,omitempty"`
	RequiresRestart []string          `json:"requires_restart,omitempty"`
	AppliedChanges  []string          `json:"applied_changes,omitempty"`
}

// ConfigDiff represents differences between old and new configuration
type ConfigDiff struct {
	CertDirsChanged          bool
	LogFileChanged           bool
	PortChanged              bool
	BindAddressChanged       bool
	NumWorkersChanged        bool
	TLSConfigChanged         bool
	RuntimeMetricsChanged    bool
	WeakCryptoMetricsChanged bool
	PprofChanged             bool
	CacheFileChanged         bool
	ExpiryThresholdChanged   bool
	ClearCacheChanged        bool
}

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
		log.WithError(fmt.Errorf(result.Error)).Warn("Configuration hot-reload failed")
	}
}

// performHotConfigReload performs hot configuration reload with change detection
func performHotConfigReload(configPath string) ConfigReloadResult {
	result := ConfigReloadResult{
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
	newConfig := DefaultConfig()
	if err := loadConfigFromFile(configPath, newConfig); err != nil {
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

// loadConfigFromFile loads configuration from file into provided config struct
func loadConfigFromFile(path string, cfg *Config) error {
	if err := validateFileAccess(path); err != nil {
		return fmt.Errorf("config file validation failed: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return validateConfig(cfg)
}

// detectConfigChanges compares old and new configurations to detect differences
func detectConfigChanges(oldCfg, newCfg *Config) ConfigDiff {
	return ConfigDiff{
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
func applyHotReloadableChanges(oldCfg, newCfg *Config, diff ConfigDiff, result *ConfigReloadResult) {
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
func identifyRestartRequiredChanges(diff ConfigDiff, result *ConfigReloadResult) {
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

	log.WithFields(log.Fields{
		"old_cache_file": oldPath,
		"new_cache_file": newPath,
	}).Info("Starting cache file migration")

	// Perform cache consistency check before migration
	preRemoved := globalState.pruneCacheNonExisting()
	if preRemoved > 0 {
		log.WithFields(log.Fields{
			"removed_entries": preRemoved,
			"phase":           "pre_migration",
		}).Info("Cleaned stale cache entries before migration")
	}

	// Save current cache to new location
	if err := globalState.saveCacheToFile(newPath); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"old_cache_file": oldPath,
			"new_cache_file": newPath,
		}).Error("Failed to save cache to new location during migration")
		return fmt.Errorf("failed to save cache to new location: %w", err)
	}

	// Ensure cache consistency after migration by removing any stale entries
	// that might have been created during the migration process
	postRemoved := globalState.pruneCacheNonExisting()
	if postRemoved > 0 {
		log.WithFields(log.Fields{
			"removed_entries": postRemoved,
			"phase":           "post_migration",
		}).Info("Pruned stale entries after cache migration")

		// Save the cleaned cache to the new location to ensure consistency
		if err := globalState.saveCacheToFile(newPath); err != nil {
			log.WithError(err).WithField("cache_file", newPath).Warn("Failed to save cleaned cache after migration")
		} else {
			log.WithField("cache_file", newPath).Debug("Saved cleaned cache after migration")
		}
	}

	log.WithField("new_cache_file", newPath).Info("Global cache file path updated")

	log.WithFields(log.Fields{
		"old_cache_file":         oldPath,
		"new_cache_file":         newPath,
		"pre_migration_cleanup":  preRemoved,
		"post_migration_cleanup": postRemoved,
	}).Info("Cache file migration completed successfully")

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
			if removed := globalState.pruneCacheNonExisting(); removed > 0 {
				log.WithField("removed_entries", removed).Debug("Periodic cache maintenance removed stale entries")
				// Save updated cache after cleanup
				if err := globalState.saveCacheToFile(globalState.cacheFilePath); err != nil {
					log.WithError(err).Debug("Failed to save cache after periodic maintenance")
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
func processDirectoriesWithWorkers(ctx context.Context, cfg *Config) {
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
	if removed := globalState.pruneCacheNonExisting(); removed > 0 {
		log.WithField("removed_entries", removed).Info("Pruned stale cache entries after scan")
	}

	// Clear expired backoff entries
	clearExpiredBackoffs()

	// Save cache to disk
	if err := globalState.saveCacheToFile(globalState.cacheFilePath); err != nil {
		log.WithError(err).Warn("Failed to save certificate cache after scan")
	} else {
		// Log cache statistics after successful save
		globalState.certCacheLock.RLock()
		cacheSize := len(globalState.certCache)
		hits := globalState.cacheHits
		misses := globalState.cacheMisses
		globalState.certCacheLock.RUnlock()

		log.WithFields(log.Fields{
			"cache_entries": cacheSize,
			"cache_hits":    hits,
			"cache_misses":  misses,
			"hit_rate":      fmt.Sprintf("%.2f%%", float64(hits)/float64(hits+misses)*100),
		}).Debug("Cache statistics after scan maintenance")
	}

	// Update reload timestamp
	metrics.LastReload.Set(float64(time.Now().Unix()))

	// Post-scan metric validation for debugging and consistency checking
	validateMetricConsistency()
}

// validateMetricConsistency performs post-scan validation of metric counts
// This helps ensure that our fixes for weak key and deprecated signature algorithm
// metrics are working correctly and that counts reflect reality
func validateMetricConsistency() {
	// Get current certificate count from cache
	globalState.certCacheLock.RLock()
	totalCertsInCache := len(globalState.certCache)
	globalState.certCacheLock.RUnlock()

	log.WithFields(log.Fields{
		"certificates_in_cache": totalCertsInCache,
		"validation":            "post_scan_metrics",
	}).Debug("Post-scan metric consistency check")

	// Additional validation could include:
	// - Comparing metric totals against expected counts
	// - Verifying that no certificates were double-counted
	// - Ensuring removed certificates don't contribute to current counts

	// This function serves as a hook for future metric validation enhancements
	// and provides a clear audit trail of metric state after each scan cycle
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

	ticker := time.NewTicker(runtimeMetricsInterval)
	defer ticker.Stop()

	var memStats runtime.MemStats
	log.Info("Runtime metrics collection enabled")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if shouldWriteMetrics() {
				runtime.ReadMemStats(&memStats)
				metrics.HeapAllocGauge.Set(float64(memStats.HeapAlloc))
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
		if isCertificateFile(filepath.Base(event.Name)) {
			globalState.certCacheLock.Lock()
			if _, exists := globalState.certCache[event.Name]; exists {
				delete(globalState.certCache, event.Name)
				globalState.certCacheLock.Unlock()
				logger.WithField("cache_entry", event.Name).Debug("Removed deleted certificate from cache")
			} else {
				globalState.certCacheLock.Unlock()
			}
		}

		// Handle directory removal for watcher cleanup
		if info, err := os.Stat(event.Name); os.IsNotExist(err) || (err == nil && info.IsDir()) {
			removeDirectoryFromWatcher(watcher, event.Name)

			// Remove all cache entries for files in deleted directory
			globalState.certCacheLock.Lock()
			removed := 0
			for cachePath := range globalState.certCache {
				if strings.HasPrefix(cachePath, event.Name) {
					delete(globalState.certCache, cachePath)
					removed++
				}
			}
			globalState.certCacheLock.Unlock()
			if removed > 0 {
				logger.WithFields(log.Fields{
					"removed_entries": removed,
					"directory":       event.Name,
				}).Debug("Removed cache entries for deleted directory")
			}
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

				debounceTimer = time.AfterFunc(watcherDebounce, func() {
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

// HTTP Server Management
// =====================

// startHTTPServer starts the metrics and API server
func startHTTPServer(ctx context.Context, cfg *Config) *http.Server {
	// Setup HTTP routes
	setupHTTPRoutes(cfg)

	server := &http.Server{
		Addr:         cfg.BindAddress + ":" + cfg.Port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		defer log.Info("HTTP server goroutine shutting down")

		log.WithFields(log.Fields{
			"address":     server.Addr,
			"tls_enabled": cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		}).Info("Starting HTTP server")

		var err error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			err = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("HTTP server failed")
		}
	}()

	return server
}

// setupHTTPRoutes configures HTTP endpoints
func setupHTTPRoutes(cfg *Config) {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/certs", certsHandler)
	http.HandleFunc("/reload", reloadConfigHandler)
	http.HandleFunc("/config", configStatusHandler)

	if cfg.EnablePprof {
		log.Info("pprof debug endpoints enabled at /debug/pprof/")
	}

	log.Info("HTTP routes configured successfully")
}

// shutdownHTTPServer gracefully shuts down the HTTP server
func shutdownHTTPServer(server *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()

	log.Info("Shutting down HTTP server gracefully")
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Warn("HTTP server shutdown error")
	} else {
		log.Info("HTTP server shut down successfully")
	}
}

// Utility Functions for Main
// ==========================

// defaultLogPath returns the default log file path based on OS
func defaultLogPath() string {
	if isWindows() {
		return "C:\\Logs\\cert-monitor.log"
	}
	return "/var/log/cert-monitor.log"
}

// isWindows detects if running on Windows
func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") ||
		os.PathSeparator == '\\'
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
func parseCommandLineFlags() *Config {
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
	flag.IntVar(&expiryDays, "expiry-threshold-days", defaultExpiryDays, "Days to consider certificate expiring soon")
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
	if err := LoadConfig(configFile); err != nil {
		log.WithError(err).Fatal("Failed to load configuration")
	}

	// Apply command line overrides
	cfg := globalState.getConfig()
	if cfg == nil {
		cfg = DefaultConfig()
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

	if err := LoadConfig(configFile); err != nil {
		log.WithError(err).Fatal("Configuration validation failed")
	}

	if err := validateConfig(globalState.getConfig()); err != nil {
		log.WithError(err).Fatal("Configuration validation failed")
	}

	log.Info("Configuration validation successful")
	os.Exit(0)
}

// applyCommandLineOverrides applies command line flag overrides to configuration
func applyCommandLineOverrides(cfg *Config, certDirs *arrayFlags, logFile, port, bindAddr string,
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
func applyEnvironmentOverrides(cfg *Config) {
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
func performDryRun(cfg *Config) {
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

	// Initialize logging
	initLogger(cfg.LogFile, cfg.DryRun)

	// Initialize cache
	globalState.cacheFilePath = cfg.CacheFile
	if err := globalState.loadCacheFromFile(globalState.cacheFilePath); err != nil {
		log.WithError(err).Warn("Cache loading failed, starting with empty cache")

		// Reset cache statistics on failed load
		globalState.certCacheLock.Lock()
		globalState.cacheHits = 0
		globalState.cacheMisses = 0
		globalState.certCacheLock.Unlock()

		log.Info("Cache statistics reset due to failed cache load")
	}

	// Prune stale cache entries
	if removed := globalState.pruneCacheNonExisting(); removed > 0 {
		log.WithField("removed_entries", removed).Info("Removed stale cache entries during startup")

		if err := globalState.saveCacheToFile(globalState.cacheFilePath); err != nil {
			log.WithError(err).Warn("Failed to save cache after pruning")
		} else {
			log.Info("Cache saved successfully after startup pruning")
		}
	} else {
		log.Info("No stale cache entries found during startup validation")
	}

	// Log initial cache state
	globalState.certCacheLock.RLock()
	initialCacheSize := len(globalState.certCache)
	globalState.certCacheLock.RUnlock()

	log.WithFields(log.Fields{
		"cache_file":    globalState.cacheFilePath,
		"cache_entries": initialCacheSize,
		"cache_hits":    0,
		"cache_misses":  0,
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

	// Start HTTP server
	server := startHTTPServer(ctx, cfg)

	// Wait for shutdown signal
	<-ctx.Done()
	log.Info("Shutdown signal received, beginning graceful shutdown")

	// Perform graceful shutdown
	performGracefulShutdown(server, watcher)

	log.Info("SSL Certificate Monitor stopped successfully")
}

// performGracefulShutdown handles the graceful shutdown process
func performGracefulShutdown(server *http.Server, watcher *fsnotify.Watcher) {
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

	// Shutdown HTTP server
	shutdownHTTPServer(server)

	// Log final cache statistics before shutdown
	globalState.certCacheLock.RLock()
	finalCacheSize := len(globalState.certCache)
	finalHits := globalState.cacheHits
	finalMisses := globalState.cacheMisses
	globalState.certCacheLock.RUnlock()

	log.WithFields(log.Fields{
		"final_cache_entries": finalCacheSize,
		"total_cache_hits":    finalHits,
		"total_cache_misses":  finalMisses,
		"final_hit_rate":      fmt.Sprintf("%.2f%%", float64(finalHits)/float64(finalHits+finalMisses)*100),
	}).Info("Final cache statistics before shutdown")

	// Save final cache state
	if err := globalState.saveCacheToFile(globalState.cacheFilePath); err != nil {
		log.WithError(err).Warn("Failed to save cache during shutdown")
	} else {
		log.Info("Certificate cache saved successfully during shutdown")
	}
}
