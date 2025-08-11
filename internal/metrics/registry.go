package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
)

// Registry manages the Prometheus metrics registry and HTTP handler
type Registry struct {
	registry  *prometheus.Registry
	gatherer  prometheus.Gatherer
	collector *DefaultCollector
	config    Config
}

// NewRegistry creates a new metrics registry with the specified configuration
func NewRegistry(config Config) *Registry {
	// Create custom registry if none provided
	var registry *prometheus.Registry
	var gatherer prometheus.Gatherer

	if config.Registry == nil {
		registry = prometheus.NewRegistry()
		gatherer = registry
	} else {
		// Use provided registry (likely the default one)
		registry = nil
		gatherer = prometheus.DefaultGatherer
	}

	r := &Registry{
		registry: registry,
		gatherer: gatherer,
		config:   config,
	}

	// Create collector with updated config
	collectorConfig := config
	if registry != nil {
		collectorConfig.Registry = registry
	}

	r.collector = NewCollector(collectorConfig)

	log.WithFields(log.Fields{
		"runtime_metrics":     config.EnableRuntimeMetrics,
		"weak_crypto_metrics": config.EnableWeakCryptoMetrics,
		"custom_registry":     registry != nil,
	}).Info("Metrics registry initialized")

	return r
}

// GetCollector returns the metrics collector
func (r *Registry) GetCollector() *DefaultCollector {
	return r.collector
}

// Handler returns the HTTP handler for the metrics endpoint
func (r *Registry) Handler() http.Handler {
	if r.registry != nil {
		return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		})
	}
	return promhttp.Handler()
}

// GatherMetrics gathers all metrics and returns them
func (r *Registry) GatherMetrics() ([]*dto.MetricFamily, error) {
	return r.gatherer.Gather()
}

// GetMetricValue safely retrieves the current value of a specific metric
func (r *Registry) GetMetricValue(metricName string, labels prometheus.Labels) (float64, error) {
	families, err := r.GatherMetrics()
	if err != nil {
		return 0, fmt.Errorf("failed to gather metrics: %w", err)
	}

	for _, family := range families {
		if family.GetName() == metricName {
			for _, metric := range family.GetMetric() {
				if labelsMatch(metric.GetLabel(), labels) {
					switch family.GetType() {
					case dto.MetricType_GAUGE:
						if gauge := metric.GetGauge(); gauge != nil {
							return gauge.GetValue(), nil
						}
					case dto.MetricType_COUNTER:
						if counter := metric.GetCounter(); counter != nil {
							return counter.GetValue(), nil
						}
					case dto.MetricType_HISTOGRAM:
						if histogram := metric.GetHistogram(); histogram != nil {
							return histogram.GetSampleSum(), nil
						}
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("metric %s with labels %v not found", metricName, labels)
}

// GetMetricCount returns the total number of metrics in the registry
func (r *Registry) GetMetricCount() (int, error) {
	families, err := r.GatherMetrics()
	if err != nil {
		return 0, fmt.Errorf("failed to gather metrics: %w", err)
	}

	count := 0
	for _, family := range families {
		count += len(family.GetMetric())
	}

	return count, nil
}

// GetMetricFamilies returns all metric families with their names
func (r *Registry) GetMetricFamilies() ([]string, error) {
	families, err := r.GatherMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to gather metrics: %w", err)
	}

	names := make([]string, len(families))
	for i, family := range families {
		names[i] = family.GetName()
	}

	return names, nil
}

// ValidateMetrics performs basic validation on the metrics
func (r *Registry) ValidateMetrics() error {
	families, err := r.GatherMetrics()
	if err != nil {
		return fmt.Errorf("failed to gather metrics for validation: %w", err)
	}

	expectedMetrics := []string{
		"ssl_cert_expiration_timestamp",
		"ssl_cert_san_count",
		"ssl_cert_info",
		"ssl_cert_duplicate_count",
		"ssl_cert_issuer_code",
		"ssl_cert_parse_errors_total",
		"ssl_cert_files_total",
		"ssl_certs_parsed_total",
		"ssl_cert_last_scan_timestamp",
		"ssl_cert_scan_duration_seconds",
		"ssl_cert_last_reload_timestamp",
	}

	// Add optional metrics if enabled
	if r.config.EnableWeakCryptoMetrics {
		expectedMetrics = append(expectedMetrics,
			"ssl_cert_weak_key_total",
			"ssl_cert_deprecated_sigalg_total",
		)
	}

	if r.config.EnableRuntimeMetrics {
		expectedMetrics = append(expectedMetrics, "ssl_monitor_heap_alloc_bytes")
	}

	// Check if all expected metrics are present
	familyMap := make(map[string]*dto.MetricFamily)
	for _, family := range families {
		familyMap[family.GetName()] = family
	}

	var missingMetrics []string
	for _, expected := range expectedMetrics {
		if _, exists := familyMap[expected]; !exists {
			missingMetrics = append(missingMetrics, expected)
		}
	}

	if len(missingMetrics) > 0 {
		return fmt.Errorf("missing expected metrics: %v", missingMetrics)
	}

	log.WithFields(log.Fields{
		"expected_metrics": len(expectedMetrics),
		"total_families":   len(families),
		"validation":       "passed",
	}).Debug("Metrics validation completed successfully")

	return nil
}

// Reset resets all metrics in the registry
func (r *Registry) Reset() {
	if r.collector != nil {
		r.collector.Reset()
	}
}

// LogMetricsSummary logs a summary of current metrics
func (r *Registry) LogMetricsSummary() {
	families, err := r.GatherMetrics()
	if err != nil {
		log.WithError(err).Warn("Failed to gather metrics for summary")
		return
	}

	totalMetrics := 0
	familyCount := len(families)

	for _, family := range families {
		totalMetrics += len(family.GetMetric())
	}

	log.WithFields(log.Fields{
		"metric_families": familyCount,
		"total_metrics":   totalMetrics,
		"runtime_enabled": r.config.EnableRuntimeMetrics,
		"crypto_enabled":  r.config.EnableWeakCryptoMetrics,
	}).Info("Metrics registry summary")
}

// labelsMatch checks if metric labels match the provided labels
func labelsMatch(metricLabels []*dto.LabelPair, targetLabels prometheus.Labels) bool {
	if len(metricLabels) != len(targetLabels) {
		return false
	}

	metricLabelMap := make(map[string]string)
	for _, label := range metricLabels {
		metricLabelMap[label.GetName()] = label.GetValue()
	}

	for name, value := range targetLabels {
		if metricValue, exists := metricLabelMap[name]; !exists || metricValue != value {
			return false
		}
	}

	return true
}

// GetCounterValue safely retrieves the current total value of all instances of a counter metric
func (r *Registry) GetCounterTotal(metricName string) (float64, error) {
	families, err := r.GatherMetrics()
	if err != nil {
		return 0, fmt.Errorf("failed to gather metrics: %w", err)
	}

	var total float64
	for _, family := range families {
		if family.GetName() == metricName && family.GetType() == dto.MetricType_COUNTER {
			for _, metric := range family.GetMetric() {
				if counter := metric.GetCounter(); counter != nil {
					total += counter.GetValue()
				}
			}
			return total, nil
		}
	}

	return 0, fmt.Errorf("counter metric %s not found", metricName)
}

// GetHistogramSampleCount returns the total sample count for a histogram metric
func (r *Registry) GetHistogramSampleCount(metricName string) (uint64, error) {
	families, err := r.GatherMetrics()
	if err != nil {
		return 0, fmt.Errorf("failed to gather metrics: %w", err)
	}

	var total uint64
	for _, family := range families {
		if family.GetName() == metricName && family.GetType() == dto.MetricType_HISTOGRAM {
			for _, metric := range family.GetMetric() {
				if histogram := metric.GetHistogram(); histogram != nil {
					total += histogram.GetSampleCount()
				}
			}
			return total, nil
		}
	}

	return 0, fmt.Errorf("histogram metric %s not found", metricName)
}
