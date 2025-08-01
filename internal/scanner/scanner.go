// # internal/scanner/scanner.go
package scanner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/cert-monitor/internal/cache"
	"github.com/yourusername/cert-monitor/internal/cert"
	"github.com/yourusername/cert-monitor/internal/config"
	"github.com/yourusername/cert-monitor/internal/metrics"
	
	log "github.com/sirupsen/logrus"
)

const MaxBackoff = 10 * time.Minute

// Scanner handles certificate scanning operations
type Scanner struct {
	config       *config.Config
	cache        *cache.Cache
	backoff      map[string]time.Time
	backoffMutex sync.Mutex
	reloadCh     chan struct{}
}

// New creates a new scanner instance
func New(cfg *config.Config, certCache *cache.Cache) *Scanner {
	return &Scanner{
		config:   cfg,
		cache:    certCache,
		backoff:  make(map[string]time.Time),
		reloadCh: make(chan struct{}, 1),
	}
}

// ScanAll scans all configured certificate directories
func (s *Scanner) ScanAll() {
	s.TriggerReload()
}

// TriggerReload triggers a reload of all certificate directories
func (s *Scanner) TriggerReload() {
	select {
	case s.reloadCh <- struct{}{}:
	default:
		// Already queued, skip
	}
}

// Start starts the scanner processing loop
func (s *Scanner) Start(ctx context.Context) {
	go func() {
		defer log.Info("Scanner processing goroutine shutting down")
		
		for {
			select {
			case <-ctx.Done():
				log.Info("Context cancelled, stopping scanner")
				return
			case _, ok := <-s.reloadCh:
				if !ok {
					log.Info("Reload channel closed, stopping scanner")
					return
				}
				
				s.performScan(ctx)
			}
		}
	}()
	
	// Trigger initial scan
	s.TriggerReload()
}

func (s *Scanner) performScan(ctx context.Context) {
	cfg := config.Get()
	
	if cfg.ClearCacheOnReload {
		metrics.Reset(true)
		s.cache.Clear()
	} else {
		metrics.Reset(false)
	}
	
	log.Info("Reload triggered: launching worker pool for leaf certificate processing")
	
	dirJobs := make(chan string, len(cfg.CertDirs))
	var wg sync.WaitGroup
	
	// Create a context for workers that can be cancelled
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	
	// Start workers
	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for dir := range dirJobs {
				// Check if context is cancelled before processing
				select {
				case <-workerCtx.Done():
					log.WithField("worker", workerID).Info("Worker cancelled, stopping")
					return
				default:
				}
				
				log.WithFields(log.Fields{
					"worker": workerID,
					"dir":    dir,
					"mode":   "leaf_only",
				}).Info("Worker processing cert dir for leaf certificates")
				
				s.ProcessDirectory(dir, false)
			}
		}(i)
	}
	
	// Send jobs to workers
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
	
	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-workerCtx.Done():
		log.Warn("Context cancelled while waiting for workers, forcing shutdown")
		workerCancel()
		return
	case <-done:
		// All workers completed normally
	}
	
	log.Info("All workers completed leaf certificate processing")
	
	// Clean up
	if removed := s.cache.PruneNonExisting(); removed > 0 {
		log.WithField("removed_cache_entries", removed).Info("Cache pruned after scan")
	}
	
	s.clearExpiredBackoffs()
	s.cache.Save()
	metrics.LastReload.Set(float64(time.Now().Unix()))
}

// ProcessDirectory processes all certificates in a directory
func (s *Scanner) ProcessDirectory(dirPath string, dryRun bool) map[string]int {
	if !dryRun && !s.shouldWriteMetrics() {
		log.WithField("dir", dirPath).Info("Dry-run mode active, metrics writes are disabled")
	}
	
	if s.shouldSkipScan(dirPath) {
		log.WithField("dir", dirPath).Warn("Skipping scan due to backoff")
		return nil
	}
	
	start := time.Now()
	defer func() {
		metrics.CertScanDuration.WithLabelValues(dirPath).Observe(time.Since(start).Seconds())
	}()
	
	info, err := os.Stat(dirPath)
	if err != nil || !info.IsDir() {
		log.WithField("dir", dirPath).Warn("Skipping non-directory")
		s.registerScanFailure(dirPath)
		return nil
	}
	
	defer func() {
		if !dryRun && s.shouldWriteMetrics() {
			now := float64(time.Now().Unix())
			metrics.CertLastScan.WithLabelValues(dirPath).Set(now)
		}
	}()
	
	// Track duplicates based on leaf certificate fingerprints
	seen := map[string]int{}
	hostname, _ := os.Hostname()
	
	err = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case "old", "working":
				log.WithField("dir", path).Info("Skipping subdirectory")
				return filepath.SkipDir
			default:
				return nil
			}
		}
		
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".pem" && ext != ".crt" && ext != ".cer" && ext != ".der" {
			return nil
		}
		
		// Use atomic cache operations
		cached, info, found, err := s.cache.GetEntryAtomic(path)
		if err != nil {
			log.WithError(err).WithField("file", path).Warn("Stat error")
			metrics.CertParseErrors.WithLabelValues(path).Inc()
			return nil
		}
		
		metrics.CertFilesTotal.WithLabelValues(dirPath).Inc()
		
		if found && cached.ModTime.Equal(info.ModTime()) && cached.Size == info.Size() {
			log.WithField("file", path).Debug("Skipping file with unchanged ModTime and Size")
			return nil
		}
		
		raw, err := os.ReadFile(path)
		if err != nil {
			log.WithError(err).WithField("file", path).Warn("Read error")
			metrics.CertParseErrors.WithLabelValues(path).Inc()
			return nil
		}
		
		// Parse certificates to find the leaf certificate
		leafCert, err := s.parseLeafCertificate(raw, ext, path, dirPath)
		if err != nil {
			log.WithError(err).WithField("file", path).Debug("No valid certificate found in file")
			return nil
		}
		
		// Process the leaf certificate
		s.processCertificate(leafCert, path, dirPath, seen, hostname, dryRun)
		
		// Update cache
		fingerprint := sha256.Sum256(leafCert.Raw)
		s.cache.SetEntryAtomic(path, fingerprint, info)
		
		return nil
	})
	
	if err != nil {
		log.WithError(err).WithField("dir", dirPath).Warn("WalkDir error")
		s.registerScanFailure(dirPath)
	}
	
	return seen
}

func (s *Scanner) parseLeafCertificate(raw []byte, ext string, path string, dirPath string) (*x509.Certificate, error) {
	if ext == ".der" {
		// For DER files, there's only one certificate
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			metrics.CertParseErrors.WithLabelValues(path).Inc()
			return nil, err
		}
		metrics.CertsParsedTotal.WithLabelValues(dirPath).Inc()
		return c, nil
	}
	
	// For PEM files, find the first certificate (leaf certificate)
	rest := raw
	for {
		block, r := pem.Decode(rest)
		rest = r
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).WithField("file", path).Warn("PEM parse error")
			metrics.CertParseErrors.WithLabelValues(path).Inc()
			continue
		}
		// Take the first valid certificate as the leaf certificate
		metrics.CertsParsedTotal.WithLabelValues(dirPath).Inc()
		return c, nil
	}
	
	return nil, fmt.Errorf("no valid certificate found")
}

func (s *Scanner) processCertificate(cert *x509.Certificate, path string, dirPath string, seen map[string]int, hostname string, dryRun bool) {
	file := filepath.Base(path)
	sanitizedFile := s.sanitizeLabelValue(file)
	
	// Generate fingerprint for duplicate detection
	sig := sha256.Sum256(cert.Raw)
	key := fmt.Sprintf("%x", sig)
	seen[key]++
	
	cn := s.sanitizeLabelValue(cert.Subject.CommonName)
	issuer := s.sanitizeLabelValue(cert.Issuer.CommonName)
	
	// Determine issuer code
	issuerCode := cert.DetermineIssuerCode(cert)
	
	// Prepare SAN information
	var sanitizedSANs string
	if len(cert.DNSNames) > 0 {
		limitedSANs := cert.DNSNames
		if len(limitedSANs) > metrics.MaxSANsExported {
			limitedSANs = limitedSANs[:metrics.MaxSANsExported]
		}
		sanitizedSANs = s.sanitizeLabelValue(strings.Join(limitedSANs, ","))
	}
	
	// Export metrics
	if !dryRun && s.shouldWriteMetrics() {
		metrics.CertExpiration.WithLabelValues(cn, sanitizedFile).Set(float64(cert.NotAfter.Unix()))
		metrics.CertNotBefore.WithLabelValues(cn, sanitizedFile).Set(float64(cert.NotBefore.Unix()))
		metrics.CertSANCount.WithLabelValues(cn, sanitizedFile).Set(float64(len(cert.DNSNames)))
		metrics.CertInfo.WithLabelValues(cn, sanitizedFile, sanitizedSANs).Set(1)
		metrics.CertIssuer.WithLabelValues(issuer, cn, sanitizedFile).Set(1)
		metrics.CertDuplicateCount.WithLabelValues(cn, sanitizedFile).Set(float64(seen[key]))
		metrics.CertIssuerCode.WithLabelValues(cn, sanitizedFile).Set(issuerCode)
		
		// Check expiry
		cfg := config.Get()
		if time.Until(cert.NotAfter) <= time.Duration(cfg.ExpiryThresholdDays)*24*time.Hour {
			metrics.CertExpiringSoon.WithLabelValues(cn, sanitizedFile, hostname, fmt.Sprint(seen[key])).Set(1)
			log.WithFields(log.Fields{"file": file, "cn": cert.Subject.CommonName, "exp": cert.NotAfter}).Warn("Leaf certificate expiring soon")
		}
		
		// Weak crypto detection
		if cfg.EnableWeakCryptoMetrics {
			if cert.IsWeakKey(cert) {
				metrics.WeakKeyCounter.WithLabelValues(cn, sanitizedFile).Inc()
				log.WithFields(log.Fields{"file": sanitizedFile, "cn": cn}).Warn("Weak key detected")
			}
			if cert.IsDeprecatedSigAlg(cert.SignatureAlgorithm) {
				metrics.DeprecatedSigAlgCounter.WithLabelValues(cn, sanitizedFile).Inc()
				log.WithFields(log.Fields{"file": sanitizedFile, "cn": cn, "sig_alg": cert.SignatureAlgorithm}).Warn("Deprecated signature algorithm detected")
			}
		}
	}
	
	// Log information
	log.WithFields(log.Fields{
		"file":       file,
		"cn":         cert.Subject.CommonName,
		"issuer":     cert.Issuer.CommonName,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
		"sans":       len(cert.DNSNames),
		"duplicates": seen[key],
		"type":       "leaf_certificate",
	}).Info("Parsed leaf certificate")
}

func (s *Scanner) shouldWriteMetrics() bool {
	cfg := config.Get()
	return cfg != nil && !cfg.DryRun
}

func (s *Scanner) sanitizeLabelValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) > metrics.MaxLabelLength {
		metrics.LabelsTruncated.Inc()
		return val[:metrics.MaxLabelLength]
	}
	return val
}

// Backoff management methods

func (s *Scanner) registerScanFailure(dir string) {
	s.backoffMutex.Lock()
	defer s.backoffMutex.Unlock()
	
	now := time.Now()
	delay := 30 * time.Second
	
	if t, ok := s.backoff[dir]; ok && t.After(now) {
		delay = t.Sub(now) * 2
		if delay < 0 || delay > MaxBackoff {
			delay = MaxBackoff
		}
	}
	
	jitter := time.Duration(rand.Int63n(int64(10 * time.Second)))
	s.backoff[dir] = now.Add(delay + jitter)
	
	log.WithFields(log.Fields{
		"dir":   dir,
		"delay": delay + jitter,
		"until": now.Add(delay + jitter).Format(time.RFC3339),
	}).Warn("Scan failed, applying backoff")
}

func (s *Scanner) shouldSkipScan(dir string) bool {
	s.backoffMutex.Lock()
	defer s.backoffMutex.Unlock()
	
	nextAllowed, ok := s.backoff[dir]
	if !ok {
		return false
	}
	
	now := time.Now()
	if now.Before(nextAllowed) {
		log.WithFields(log.Fields{
			"dir":           dir,
			"backoff_until": nextAllowed.Format(time.RFC3339),
			"remaining":     nextAllowed.Sub(now),
		}).Debug("Directory scan skipped due to backoff")
		return true
	}
	
	delete(s.backoff, dir)
	log.WithField("dir", dir).Debug("Backoff period expired, allowing directory scan")
	return false
}

func (s *Scanner) clearExpiredBackoffs() {
	s.backoffMutex.Lock()
	defer s.backoffMutex.Unlock()
	
	now := time.Now()
	removed := 0
	
	for dir, nextAllowed := range s.backoff {
		if now.After(nextAllowed) {
			delete(s.backoff, dir)
			removed++
		}
	}
	
	if removed > 0 {
		log.WithFields(log.Fields{
			"removed":   removed,
			"remaining": len(s.backoff),
		}).Debug("Cleared expired backoff entries")
	}
}
