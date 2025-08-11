package metrics

import (
	"runtime"
	"time"

	"github.com/brandonhon/cert-monitor/internal/certificate"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// DefaultCollector implements the metrics collection interface
type DefaultCollector struct {
	*Collector
	config Config
}

// NewCollector creates a new metrics collector
func NewCollector(config Config) *DefaultCollector {
	collector := &DefaultCollector{
		Collector: initializeMetrics(),
		config:    config,
	}

	// Register metrics with Prometheus
	collector.register()

	return collector
}

// initializeMetrics creates and initializes all Prometheus metrics
func initializeMetrics() *Collector {
	return &Collector{
		// Certificate metrics
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

		CertIssuerCode: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_cert_issuer_code",
			Help: "Numeric code based on certificate issuer (30=digicert, 31=amazon, 32=other, 33=self-signed)",
		}, []string{"common_name", "filename"}),

		// Processing metrics
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

		CertScanDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ssl_cert_scan_duration_seconds",
			Help:    "Duration of certificate directory scans in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"dir"}),

		// Security metrics
		WeakKeyCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_weak_key_total",
			Help: "Total number of certificates detected with weak keys (e.g., RSA < 2048 bits)",
		}, []string{"common_name", "filename"}),

		DeprecatedSigAlgCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ssl_cert_deprecated_sigalg_total",
			Help: "Total number of certificates with deprecated signature algorithms (e.g., SHA1, MD5)",
		}, []string{"common_name", "filename"}),

		// Application metrics
		LastReload: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_cert_last_reload_timestamp",
			Help: "Unix timestamp of the last successful configuration reload",
		}),

		HeapAllocGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_monitor_heap_alloc_bytes",
			Help: "Heap memory allocated (bytes) as reported by runtime.ReadMemStats",
		}),
	}
}

// register registers all metrics with the Prometheus registry
func (c *DefaultCollector) register() {
	registry := c.config.Registry
	if registry == nil {
		registry = prometheus.DefaultRegisterer
	}

	// Register all metrics
	registry.MustRegister(
		c.CertExpiration,
		c.CertSANCount,
		c.CertInfo,
		c.CertDuplicateCount,
		c.CertIssuerCode,
		c.CertParseErrors,
		c.CertFilesTotal,
		c.CertsParsedTotal,
		c.CertLastScan,
		c.CertScanDuration,
		c.LastReload,
	)

	// Register security metrics if enabled
	if c.config.EnableWeakCryptoMetrics {
		registry.MustRegister(
			c.WeakKeyCounter,
			c.DeprecatedSigAlgCounter,
		)
		log.Info("Weak crypto metrics enabled and registered")
	}

	// Register runtime metrics if enabled
	if c.config.EnableRuntimeMetrics {
		registry.MustRegister(c.HeapAllocGauge)
		log.Info("Runtime metrics enabled and registered")
	}

	log.WithField("metrics_count", c.getRegisteredMetricsCount()).Info("Metrics registered successfully")
}

// UpdateCertificate updates metrics for a single certificate
func (c *DefaultCollector) UpdateCertificate(certMetrics CertificateMetrics) {
	// Basic certificate metrics
	c.CertExpiration.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Set(certMetrics.ExpirationTimestamp)
	c.CertSANCount.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Set(certMetrics.SANCount)
	c.CertDuplicateCount.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Set(certMetrics.DuplicateCount)
	c.CertIssuerCode.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Set(certMetrics.IssuerCode)

	// Certificate info with SANs
	c.CertInfo.WithLabelValues(certMetrics.CommonName, certMetrics.FileName, certMetrics.SANs).Set(1)

	// Security metrics (if enabled)
	if c.config.EnableWeakCryptoMetrics {
		if certMetrics.IsWeakKey {
			c.WeakKeyCounter.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Inc()
			log.WithFields(log.Fields{
				"file":        certMetrics.FileName,
				"common_name": certMetrics.CommonName,
				"metric":      "ssl_cert_weak_key_total",
			}).Warn("Weak key detected in certificate")
		}

		if certMetrics.HasDeprecatedSigAlg {
			c.DeprecatedSigAlgCounter.WithLabelValues(certMetrics.CommonName, certMetrics.FileName).Inc()
			log.WithFields(log.Fields{
				"file":        certMetrics.FileName,
				"common_name": certMetrics.CommonName,
				"metric":      "ssl_cert_deprecated_sigalg_total",
			}).Warn("Deprecated signature algorithm detected in certificate")
		}
	}
}

// UpdateDirectory updates metrics for directory processing
func (c *DefaultCollector) UpdateDirectory(dirMetrics DirectoryMetrics) {
	c.CertFilesTotal.WithLabelValues(dirMetrics.Directory).Add(dirMetrics.FilesTotal)
	c.CertsParsedTotal.WithLabelValues(dirMetrics.Directory).Add(dirMetrics.CertsParsed)
	c.CertScanDuration.WithLabelValues(dirMetrics.Directory).Observe(dirMetrics.ScanDuration)
	c.CertLastScan.WithLabelValues(dirMetrics.Directory).Set(dirMetrics.LastScanTime)
}

// RecordParseError records a certificate parsing error
func (c *DefaultCollector) RecordParseError(filename string) {
	c.CertParseErrors.WithLabelValues(filename).Inc()
}

// UpdateReloadTimestamp updates the last reload timestamp
func (c *DefaultCollector) UpdateReloadTimestamp() {
	c.LastReload.Set(float64(time.Now().Unix()))
}

// UpdateRuntimeMetrics updates runtime performance metrics
func (c *DefaultCollector) UpdateRuntimeMetrics() {
	if !c.config.EnableRuntimeMetrics {
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	c.HeapAllocGauge.Set(float64(memStats.HeapAlloc))
}

// Reset resets all metrics (useful for testing or reload scenarios)
func (c *DefaultCollector) Reset() {
	log.Info("Resetting all Prometheus metrics")

	// Reset certificate metrics
	c.CertExpiration.Reset()
	c.CertSANCount.Reset()
	c.CertInfo.Reset()
	c.CertDuplicateCount.Reset()
	c.CertIssuerCode.Reset()

	// Reset processing metrics
	c.CertParseErrors.Reset()
	c.CertFilesTotal.Reset()
	c.CertsParsedTotal.Reset()

	// Reset security metrics if they exist
	if c.config.EnableWeakCryptoMetrics {
		c.WeakKeyCounter.Reset()
		c.DeprecatedSigAlgCounter.Reset()
		log.Debug("Security metrics reset")
	}

	log.Info("All metrics reset successfully")
}

// ResetCounters resets only counter metrics (preserves current state gauges)
func (c *DefaultCollector) ResetCounters() {
	log.Info("Resetting counter metrics for fresh scan cycle")

	// Reset processing counters
	c.CertParseErrors.Reset()
	c.CertFilesTotal.Reset()
	c.CertsParsedTotal.Reset()

	// Reset security counters if enabled
	if c.config.EnableWeakCryptoMetrics {
		c.WeakKeyCounter.Reset()
		c.DeprecatedSigAlgCounter.Reset()
		log.Debug("Security counter metrics reset")
	}
}

// CreateCertificateMetrics converts certificate info to metrics format
func CreateCertificateMetrics(certInfo *certificate.Info, duplicateCount int) CertificateMetrics {
	return CertificateMetrics{
		CommonName:          certInfo.CommonName,
		FileName:            certInfo.FileName,
		ExpirationTimestamp: float64(certInfo.NotAfter.Unix()),
		SANCount:            float64(len(certInfo.SANs)),
		DuplicateCount:      float64(duplicateCount),
		IssuerCode:          float64(certInfo.IssuerCode),
		SANs:                certificate.PrepareSANsForMetrics(certInfo.SANs),
		IsWeakKey:           certInfo.IsWeakKey,
		HasDeprecatedSigAlg: certInfo.HasDeprecatedSigAlg,
	}
}

// CreateDirectoryMetrics creates directory metrics from processing stats
func CreateDirectoryMetrics(directory string, stats *certificate.DirectoryStats) DirectoryMetrics {
	return DirectoryMetrics{
		Directory:    directory,
		FilesTotal:   float64(stats.FilesProcessed),
		CertsParsed:  float64(stats.CertsParsed),
		ParseErrors:  float64(stats.ParseErrors),
		ScanDuration: stats.ProcessingTime.Seconds(),
		LastScanTime: float64(stats.LastScanTime.Unix()),
	}
}

// getRegisteredMetricsCount returns the number of registered metrics
func (c *DefaultCollector) getRegisteredMetricsCount() int {
	count := 10 // Base metrics always registered

	if c.config.EnableWeakCryptoMetrics {
		count += 2
	}
	if c.config.EnableRuntimeMetrics {
		count += 1
	}

	return count
}
