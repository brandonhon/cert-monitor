package utils

import "time"

// Certificate processing constants
const (
	MaxSANsExported = 10
	MaxLabelLength  = 120
)

// Default configuration values
const (
	DefaultPort        = "3000"
	DefaultBindAddress = "0.0.0.0"
	DefaultWorkers     = 4
	DefaultExpiryDays  = 45
)

// Operational constants
const (
	MaxBackoff              = 10 * time.Minute
	MinDiskSpaceBytes       = 100 * 1024 * 1024 // 100MB
	CacheWriteTimeout       = 5 * time.Second
	WatcherDebounce         = 2 * time.Second
	RuntimeMetricsInterval  = 10 * time.Second
	GracefulShutdownTimeout = 10 * time.Second
)

// Issuer codes for certificate classification
const (
	IssuerCodeDigiCert   = 30
	IssuerCodeAmazon     = 31
	IssuerCodeOther      = 32
	IssuerCodeSelfSigned = 33
)
