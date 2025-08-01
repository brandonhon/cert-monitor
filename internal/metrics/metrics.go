// # internal/metrics/metrics.go
package metrics

import (
	"context"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
)

const (
	MaxSANsExported = 10
	MaxLabelLength  = 120
)

// Prometheus metrics definitions
var (
	CertExpiration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_expiration_timestamp",
		Help: "Expiration time of SSL cert (Unix timestamp)",
	}, []string{"common_name", "filename"})
	
	CertNotBefore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_not_before_timestamp",
		Help: "Not-before time of SSL cert (Unix timestamp)",
	}, []string{"common_name", "filename"})
	
	CertSANCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_san_count",
		Help: "Number of SAN entries in cert",
	}, []string{"common_name", "filename"})
	
	CertInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_info",
		Help: "Static info for cert including CN and SANs",
	}, []string{"common_name", "filename", "sans"})
	
	CertExpiringSoon = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_expiring_within_45d",
		Help: "1 if cert expires within configured threshold",
	}, []string{"common_name", "filename", "node", "duplicate_count"})
	
	CertIssuer = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_issuer_info",
		Help: "Static info for cert issuer",
	}, []string{"issuer_common_name", "common_name", "filename"})
	
	CertDuplicateCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_duplicate_count",
		Help: "Number of times a cert appears",
	}, []string{"common_name", "filename"})
	
	CertParseErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssl_cert_parse_errors_total",
		Help: "Number of cert parse errors",
	}, []string{"filename"})
	
	CertFilesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssl_cert_files_total",
		Help: "Total number of certificate files processed",
	}, []string{"dir"})
	
	CertsParsedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssl_certs_parsed_total",
		Help: "Total number of individual certificates successfully parsed",
	}, []string{"dir"})
	
	CertLastScan = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_last_scan_timestamp",
		Help: "Unix timestamp of the last successful scan of a certificate directory",
	}, []string{"dir"})
	
	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_monitor_build_info",
		Help: "Build and Go version of the SSL Cert Monitor",
	}, []string{"version", "commit", "go_version"})
	
	LastReload = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssl_cert_last_reload_timestamp",
		Help: "Unix timestamp of the last successful configuration reload",
	})
	
	CertScanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ssl_cert_scan_duration_seconds",
		Help:    "Duration of certificate directory scans in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"dir"})
	
	GoroutinesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssl_monitor_goroutines",
		Help: "Number of active goroutines in the SSL monitor",
	})
	
	HeapAllocGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssl_monitor_heap_alloc_bytes",
		Help: "Heap memory allocated (bytes) as reported by runtime.ReadMemStats",
	})
	
	LabelsTruncated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ssl_cert_labels_truncated_total",
		Help: "Number of times a label value was truncated due to exceeding maxLabelLength",
	})
	
	WeakKeyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssl_cert_weak_key_total",
		Help: "Total number of certificates detected with weak keys (e.g., RSA < 2048 bits)",
	}, []string{"common_name", "filename"})
	
	DeprecatedSigAlgCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssl_cert_deprecated_sigalg_total",
		Help: "Total number of certificates with deprecated signature algorithms (e.g., SHA1, MD5)",
	}, []string{"common_name", "filename"})
	
	CertIssuerCode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ssl_cert_issuer_code",
		Help: "Numeric code based on certificate issuer (30=digicert, 31=amazon, 32=other, 33=self-signed)",
	}, []string{"common_name", "filename"})
)

// Initialize registers all metrics with Prometheus
func Initialize(version, commit string) {
	prometheus.MustRegister(
		CertExpiration, CertNotBefore, CertSANCount, CertInfo,
		CertExpiringSoon, CertIssuer, CertDuplicateCount, CertParseErrors,
		CertFilesTotal, CertsParsedTotal, CertLastScan, BuildInfo,
		LastReload, CertScanDuration, GoroutinesGauge, HeapAllocGauge, LabelsTruncated,
		WeakKeyCounter, DeprecatedSigAlgCounter, CertIssuerCode,
	)
	
	// Set build info
	BuildInfo.WithLabelValues(version, commit, runtime.Version()).Set(1)
}

// Reset resets all metrics, optionally including cache
func Reset(clearCache bool) {
	CertExpiration.Reset()
	CertNotBefore.Reset()
	CertSANCount.Reset()
	CertInfo.Reset()
	CertExpiringSoon.Reset()
	CertIssuer.Reset()
	CertDuplicateCount.Reset()
	CertParseErrors.Reset()
	CertFilesTotal.Reset()
	CertsParsedTotal.Reset()
	CertIssuerCode.Reset()
}

// StartRuntimeMetrics starts a goroutine that periodically updates runtime metrics
func StartRuntimeMetrics(ctx context.Context) {
	go func() {
		defer log.Info("Runtime metrics goroutine shutting down")
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		var memStats runtime.MemStats
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				GoroutinesGauge.Set(float64(runtime.NumGoroutine()))
				runtime.ReadMemStats(&memStats)
				HeapAllocGauge.Set(float64(memStats.HeapAlloc))
			}
		}
	}()
	log.Info("Runtime metrics enabled")
}

// FindLabel safely retrieves a label value from a dto.Metric
func FindLabel(m *dto.Metric, key string) string {
	if m == nil {
		log.WithField("key", key).Warn("Attempted to find label on nil metric")
		return ""
	}
	
	if m.Label == nil {
		log.WithFields(log.Fields{
			"key": key,
		}).Debug("Metric has no labels")
		return ""
	}
	
	for _, l := range m.GetLabel() {
		if l == nil {
			continue
		}
		if l.GetName() == key {
			return l.GetValue()
		}
	}
	return ""
}
