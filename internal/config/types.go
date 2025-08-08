package config

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

// ReloadResult represents the result of a configuration reload attempt
type ReloadResult struct {
	Success         bool              `json:"success"`
	Error           string            `json:"error,omitempty"`
	ChangedSettings map[string]string `json:"changed_settings,omitempty"`
	RequiresRestart []string          `json:"requires_restart,omitempty"`
	AppliedChanges  []string          `json:"applied_changes,omitempty"`
}

// Diff represents differences between old and new configuration
type Diff struct {
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

// Constants for configuration defaults
const (
	DefaultPort        = "3000"
	DefaultBindAddress = "0.0.0.0"
	DefaultWorkers     = 4
	DefaultExpiryDays  = 45
	DefaultCacheFile   = "/var/lib/cert-monitor/cache.json"
)
