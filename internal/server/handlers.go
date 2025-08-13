package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/brandonhon/cert-monitor/internal/certificate"
	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// HandlerSet contains all HTTP handlers for the server
type HandlerSet struct {
	deps *Dependencies
}

// NewHandlerSet creates a new set of HTTP handlers
func NewHandlerSet(deps *Dependencies) *HandlerSet {
	return &HandlerSet{deps: deps}
}

// HealthHandler provides comprehensive health check information
func (h *HandlerSet) HealthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	isHealthy := true
	cfg := h.deps.Config

	// Disk space checks
	for _, dir := range cfg.CertDirs {
		checkKey := "disk_space_" + utils.SanitizeLabelValue(dir)
		if err := h.checkDiskSpace(dir); err != nil {
			checks[checkKey] = err.Error()
			isHealthy = false
		} else {
			checks[checkKey] = "ok"
		}
	}

	// Log file writability
	if err := h.checkLogWritable(cfg.LogFile); err != nil {
		checks["log_file_writable"] = err.Error()
		isHealthy = false
	} else {
		checks["log_file_writable"] = "ok"
	}

	// Prometheus registry health
	if err := h.checkPrometheus(); err != nil {
		checks["prometheus_registry"] = err.Error()
		isHealthy = false
	} else {
		checks["prometheus_registry"] = "ok"
	}

	// Add configuration info
	checks["worker_pool_size"] = fmt.Sprintf("%d", cfg.NumWorkers)
	checks["certificate_directories"] = fmt.Sprintf("%d", len(cfg.CertDirs))
	checks["hot_reload_enabled"] = fmt.Sprintf("%t", h.deps.ConfigFilePath != "")
	checks["config_file"] = h.deps.ConfigFilePath

	// Gather certificate statistics
	h.addCertificateStats(checks)

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

// CertsHandler provides detailed certificate information via JSON API
func (h *HandlerSet) CertsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := h.deps.Config
	certificates := h.collectCertificateInfo(cfg)

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(certificates); err != nil {
		log.WithError(err).Error("Failed to encode certificates response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.WithField("certificate_count", len(certificates)).Debug("Served certificates API request")
}

// ReloadHandler provides an HTTP endpoint for manual configuration reload
func (h *HandlerSet) ReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := log.WithField("endpoint", "/reload")
	logger.Info("Manual configuration reload requested")

	if h.deps.ConfigFilePath == "" {
		logger.Warn("No configuration file path available for reload")
		http.Error(w, "No configuration file configured", http.StatusBadRequest)
		return
	}

	// For now, return a basic success response
	// The actual reload logic will be handled by the main application
	result := config.ReloadResult{
		Success: true,
	}

	// Trigger reload via channel
	select {
	case h.deps.ReloadChannel <- struct{}{}:
		logger.Info("Reload signal sent successfully")
	default:
		logger.Warn("Reload channel is full, skipping signal")
		result.Success = false
		result.Error = "reload channel busy"
	}

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

	logger.WithField("success", result.Success).Info("Manual configuration reload completed")
}

// ConfigStatusHandler provides current configuration status
func (h *HandlerSet) ConfigStatusHandler(w http.ResponseWriter, r *http.Request) {
	cfg := h.deps.Config
	if cfg == nil {
		http.Error(w, "No configuration available", http.StatusInternalServerError)
		return
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

	var cacheStats CacheStats
	if h.deps.CacheManager != nil {
		stats := h.deps.CacheManager.Stats()
		cacheStats = CacheStats{
			TotalEntries:  stats.TotalEntries,
			CacheFilePath: stats.CacheFilePath,
			HitRate:       stats.HitRate,
			LastPruneTime: stats.LastPruneTime,
		}
	}

	status := ConfigStatus{
		ConfigFile:          h.deps.ConfigFilePath,
		HotReloadEnabled:    h.deps.ConfigFilePath != "",
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

// Helper methods

func (h *HandlerSet) addCertificateStats(checks map[string]string) {
	totalFiles, totalParsed, totalErrors := h.gatherCertificateMetrics()

	checks["cert_scan_status"] = "complete"
	checks["cert_files_total"] = fmt.Sprintf("%d", totalFiles)
	checks["certs_parsed_total"] = fmt.Sprintf("%d", totalParsed)
	checks["cert_parse_errors_total"] = fmt.Sprintf("%d", totalErrors)

	if h.deps.CacheManager != nil {
		stats := h.deps.CacheManager.Stats()
		checks["cache_entries_total"] = fmt.Sprintf("%d", stats.TotalEntries)
		checks["cache_hit_rate"] = fmt.Sprintf("%.2f%%", stats.HitRate)
		checks["cache_total_accesses"] = fmt.Sprintf("%d", stats.CacheHits+stats.CacheMisses)
		checks["cache_file_path"] = stats.CacheFilePath
	}

	// Check if cache file is writable
	if h.deps.CacheManager != nil && h.deps.CacheManager.Stats().CacheFilePath != "" {
		checks["cache_file_writable"] = "ok"
		if err := h.checkCacheFileWritable(h.deps.CacheManager.Stats().CacheFilePath); err != nil {
			checks["cache_file_writable"] = err.Error()
		}
	}
}

func (h *HandlerSet) gatherCertificateMetrics() (int, int, int) {
	totalFiles, totalParsed, totalErrors := 0, 0, 0

	mfs, err := h.deps.MetricsRegistry.GatherMetrics()
	if err != nil {
		log.WithError(err).Warn("Failed to gather Prometheus metrics for health check")
		return totalFiles, totalParsed, totalErrors
	}

	for _, mf := range mfs {
		switch mf.GetName() {
		case "ssl_cert_files_total":
			totalFiles += h.sumCounterMetrics(mf)
		case "ssl_certs_parsed_total":
			totalParsed += h.sumCounterMetrics(mf)
		case "ssl_cert_parse_errors_total":
			totalErrors += h.sumCounterMetrics(mf)
		}
	}

	return totalFiles, totalParsed, totalErrors
}

func (h *HandlerSet) sumCounterMetrics(mf *dto.MetricFamily) int {
	total := 0
	for _, m := range mf.GetMetric() {
		if counter := m.GetCounter(); counter != nil {
			total += int(counter.GetValue())
		}
	}
	return total
}

func (h *HandlerSet) collectCertificateInfo(cfg *config.Config) []certificate.Info {
	var certificates []certificate.Info

	// Since we don't have direct access to cached paths in the new cache manager,
	// we need to scan directories to collect certificate info
	for _, dir := range cfg.CertDirs {
		processor := certificate.NewProcessor()
		options := certificate.ProcessingOptions{
			ExpiryThresholdDays: cfg.ExpiryThresholdDays,
			DryRun:              false,
			EnableWeakCrypto:    cfg.EnableWeakCryptoMetrics,
		}

		scanner := certificate.NewScanner()
		if files, err := scanner.ScanDirectory(dir); err == nil {
			for _, fileInfo := range files {
				if result, err := processor.ProcessFile(fileInfo.Path, options); err == nil && result.Info != nil {
					certificates = append(certificates, *result.Info)
				}
			}
		}
	}

	return certificates
}

// Health check helper methods

func (h *HandlerSet) checkDiskSpace(dir string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	availableBytes := stat.Bavail * uint64(stat.Bsize)
	if availableBytes < utils.MinDiskSpaceBytes {
		return fmt.Errorf("insufficient disk space: %d bytes available (minimum: %d)",
			availableBytes, utils.MinDiskSpaceBytes)
	}

	return nil
}

func (h *HandlerSet) checkLogWritable(logFile string) error {
	if logFile == "" {
		return nil // Logging to stdout/stderr
	}

	if err := utils.ValidateFileAccess(logFile); err != nil {
		return fmt.Errorf("log file not writable: %w", err)
	}

	return nil
}

func (h *HandlerSet) checkPrometheus() error {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	if len(mfs) == 0 {
		return fmt.Errorf("no metrics available")
	}

	return nil
}

func (h *HandlerSet) checkCacheFileWritable(cacheFile string) error {
	if cacheFile == "" {
		return nil // No cache file configured
	}

	if err := utils.ValidateFileAccess(cacheFile); err != nil {
		return fmt.Errorf("cache file not writable: %w", err)
	}

	return nil
}
