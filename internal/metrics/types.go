package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Collector encapsulates all Prometheus metrics and their management
type Collector struct {
	// Certificate metrics
	CertExpiration     *prometheus.GaugeVec
	CertSANCount       *prometheus.GaugeVec
	CertInfo           *prometheus.GaugeVec
	CertDuplicateCount *prometheus.GaugeVec
	CertIssuerCode     *prometheus.GaugeVec

	// Processing metrics
	CertParseErrors  *prometheus.CounterVec
	CertFilesTotal   *prometheus.CounterVec
	CertsParsedTotal *prometheus.CounterVec
	CertLastScan     *prometheus.GaugeVec
	CertScanDuration *prometheus.HistogramVec

	// Security metrics
	WeakKeyCounter          *prometheus.CounterVec
	DeprecatedSigAlgCounter *prometheus.CounterVec

	// Application metrics
	LastReload     prometheus.Gauge
	HeapAllocGauge prometheus.Gauge
}

// Config configures metrics collection behavior
type Config struct {
	EnableRuntimeMetrics    bool
	EnableWeakCryptoMetrics bool
	Registry                prometheus.Registerer
}

// CertificateMetrics represents metrics data for a single certificate
type CertificateMetrics struct {
	CommonName          string
	FileName            string
	ExpirationTimestamp float64
	SANCount            float64
	DuplicateCount      float64
	IssuerCode          float64
	SANs                string
	IsWeakKey           bool
	HasDeprecatedSigAlg bool
}

// DirectoryMetrics represents metrics for directory processing
type DirectoryMetrics struct {
	Directory    string
	FilesTotal   float64
	CertsParsed  float64
	ParseErrors  float64
	ScanDuration float64
	LastScanTime float64
}
