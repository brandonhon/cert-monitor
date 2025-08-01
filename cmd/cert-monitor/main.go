// # cmd/cert-monitor/main.go
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yourusername/cert-monitor/internal/cache"
	"github.com/yourusername/cert-monitor/internal/config"
	"github.com/yourusername/cert-monitor/internal/metrics"
	"github.com/yourusername/cert-monitor/internal/scanner"
	"github.com/yourusername/cert-monitor/internal/server"
	"github.com/yourusername/cert-monitor/internal/watcher"
	
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Version info (injected at build time via -ldflags)
var (
	Version = "dev"
	Commit  = "none"
)

func main() {
	cfg, checkOnly := parseFlags()
	
	if err := config.Load(cfg.ConfigFile); err != nil {
		log.Fatalf("Config load error: %v", err)
	}
	
	if checkOnly {
		log.Info("Running configuration validation mode (--check-config)")
		if err := config.Validate(config.Get()); err != nil {
			log.Fatalf("Config validation failed: %v", err)
		}
		log.Info("Configuration is valid")
		os.Exit(0)
	}
	
	// Apply flag overrides and environment variables
	applyOverrides(cfg)
	
	// Initialize logger
	initLogger(cfg.LogFile, cfg.DryRun)
	
	// Initialize metrics
	metrics.Initialize(Version, Commit)
	
	// Initialize cache
	certCache := cache.New(cfg.CacheFile)
	certCache.Load()
	
	// Log startup information
	logStartupInfo(cfg)
	
	// Run in dry-run mode if requested
	if cfg.DryRun {
		runDryRun(cfg, certCache)
		return
	}
	
	// Setup context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	// Initialize components
	certScanner := scanner.New(cfg, certCache)
	fsWatcher := watcher.New(cfg, certScanner)
	httpServer := server.New(cfg, certCache)
	
	// Start components
	if err := fsWatcher.Start(ctx); err != nil {
		log.Fatalf("Failed to start file watcher: %v", err)
	}
	
	if err := httpServer.Start(); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
	
	// Start runtime metrics if enabled
	if cfg.EnableRuntimeMetrics {
		metrics.StartRuntimeMetrics(ctx)
	}
	
	// Initial scan
	certScanner.ScanAll()
	
	// Wait for shutdown
	<-ctx.Done()
	log.Info("Shutdown signal received, stopping gracefully...")
	
	// Cleanup
	fsWatcher.Stop()
	httpServer.Stop(10 * time.Second)
	certCache.Save()
	
	log.Info("Certificate monitor stopped")
}

func parseFlags() (*config.Config, bool) {
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
	
	flag.Var(&certDirs, "cert-dir", "Certificate directory (repeatable)")
	flag.StringVar(&logFile, "log-file", "", "Log file path")
	flag.StringVar(&port, "port", "", "Metrics server port")
	flag.StringVar(&bindAddr, "bind-address", "", "Bind address for metrics server")
	flag.IntVar(&numWorkers, "workers", 0, "Number of workers")
	flag.StringVar(&configFile, "config", "", "Optional YAML config file path")
	flag.BoolVar(&dryRun, "dry-run", false, "Run once, log only")
	flag.IntVar(&expiryDays, "expiry-threshold-days", 45, "Number of days to consider cert expiring soon")
	flag.BoolVar(&clearCache, "clear-cache-on-reload", false, "Clear certificate cache on every reload")
	flag.StringVar(&tlsCert, "tls-cert-file", "", "TLS certificate file for metrics server")
	flag.StringVar(&tlsKey, "tls-key-file", "", "TLS key file for metrics server")
	flag.BoolVar(&enablePprof, "enable-pprof", false, "Enable pprof debug endpoints (/debug/pprof/)")
	flag.BoolVar(&checkConfig, "check-config", false, "Validate configuration file and exit")
	
	flag.Parse()
	
	cfg := &config.Config{
		CertDirs:            certDirs,
		LogFile:             logFile,
		Port:                port,
		BindAddress:         bindAddr,
		NumWorkers:          numWorkers,
		ConfigFile:          configFile,
		DryRun:              dryRun,
		ExpiryThresholdDays: expiryDays,
		ClearCacheOnReload:  clearCache,
		TLSCertFile:         tlsCert,
		TLSKeyFile:          tlsKey,
		EnablePprof:         enablePprof,
	}
	
	return cfg, checkConfig
}

func applyOverrides(cfg *config.Config) {
	// Apply environment variable overrides
	if v := os.Getenv("CERT_DIRS"); v != "" {
		cfg.CertDirs = strings.Split(v, ":")
	}
	if v := os.Getenv("LOG_FILE"); v != "" {
		cfg.LogFile = v
	}
	if v := os.Getenv("PORT"); v != "" {
		cfg.Port = v
	}
	if v := os.Getenv("BIND_ADDRESS"); v != "" {
		cfg.BindAddress = v
	}
	if v := os.Getenv("NUM_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.NumWorkers = n
		}
	}
	if v := os.Getenv("DRY_RUN"); strings.EqualFold(v, "true") {
		cfg.DryRun = true
	}
	if v := os.Getenv("EXPIRY_THRESHOLD_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ExpiryThresholdDays = n
		}
	}
	if v := os.Getenv("CLEAR_CACHE_ON_RELOAD"); strings.EqualFold(v, "true") {
		cfg.ClearCacheOnReload = true
	}
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		cfg.TLSCertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		cfg.TLSKeyFile = v
	}
	if v := os.Getenv("ENABLE_PPROF"); strings.EqualFold(v, "true") {
		cfg.EnablePprof = true
	}
	if v := os.Getenv("ENABLE_RUNTIME_METRICS"); strings.EqualFold(v, "true") {
		cfg.EnableRuntimeMetrics = true
	}
	if v := os.Getenv("ENABLE_WEAK_CRYPTO_METRICS"); strings.EqualFold(v, "true") {
		cfg.EnableWeakCryptoMetrics = true
	}
	
	config.Set(cfg)
}

func initLogger(logPath string, dryRun bool) {
	logWriter := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    25,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	}
	
	if dryRun {
		log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
	} else {
		log.SetOutput(logWriter)
	}
	
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)
}

func logStartupInfo(cfg *config.Config) {
	log.WithFields(log.Fields{
		"cert_dirs":             cfg.CertDirs,
		"log_file":              cfg.LogFile,
		"port":                  cfg.Port,
		"bind_addr":             cfg.BindAddress,
		"num_workers":           cfg.NumWorkers,
		"dry_run":               cfg.DryRun,
		"expiry_threshold_days": cfg.ExpiryThresholdDays,
		"processing_mode":       "leaf_certificates_only",
	}).Info("Certificate monitor starting - processing leaf certificates only")
}

func runDryRun(cfg *config.Config, certCache *cache.Cache) {
	scanner := scanner.New(cfg, certCache)
	for _, dir := range cfg.CertDirs {
		duplicates := scanner.ProcessDirectory(dir, true)
		log.Info("Duplicate leaf certificates:")
		for fp, count := range duplicates {
			log.Infof("Fingerprint %s: %d occurrences", fp[:16], count)
		}
	}
	log.Info("Dry-run complete, exiting.")
}

// arrayFlags allows multiple --cert-dir flags
type arrayFlags []string

func (a *arrayFlags) String() string { return strings.Join(*a, ",") }
func (a *arrayFlags) Set(v string) error {
	*a = append(*a, v)
	return nil
}
