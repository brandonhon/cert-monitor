// # internal/server/server.go
package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/yourusername/cert-monitor/internal/cache"
	"github.com/yourusername/cert-monitor/internal/config"
	"github.com/yourusername/cert-monitor/internal/metrics"
	
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Server handles HTTP endpoints
type Server struct {
	config     *config.Config
	cache      *cache.Cache
	httpServer *http.Server
}

// New creates a new server instance
func New(cfg *config.Config, certCache *cache.Cache) *Server {
	return &Server{
		config: cfg,
		cache:  certCache,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Setup routes
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", s.healthHandler)
	http.HandleFunc("/certs", s.certsHandler)
	
	if s.config.EnablePprof {
		log.Info("pprof enabled at /debug/pprof/")
	}
	
	s.httpServer = &http.Server{
		Addr: s.config.BindAddress + ":" + s.config.Port,
	}
	
	go func() {
		log.WithField("addr", s.httpServer.Addr).Info("Starting HTTP server")
		
		var err error
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			err = s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("HTTP server error")
		}
	}()
	
	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(timeout time.Duration) {
	if s.httpServer == nil {
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.WithError(err).Warn("Server shutdown error")
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	ok := true
	
	cfg := config.Get()
	
	// Disk space checks on cert dirs
	for _, dir := range cfg.CertDirs {
		if err := checkDiskSpace(dir); err != nil {
			checks["disk_space_"+dir] = err.Error()
			ok = false
		} else {
			checks["disk_space_"+dir] = "ok"
		}
	}
	
	// Log writable check
	if err := checkLogWritable(cfg.LogFile); err != nil {
		checks["log_file_writable"] = err.Error()
		ok = false
	} else {
		checks["log_file_writable"] = "ok"
	}
	
	// Prometheus registry
	if err := checkPrometheus(); err != nil {
		checks["prometheus_registry"] = err.Error()
		ok = false
	} else {
		checks["prometheus_registry"] = "ok"
	}
	
	checks["worker_pool_count"] = fmt.Sprintf("%d", cfg.NumWorkers)
	
	// Gather totals
	totalFiles := 0
	totalParsed := 0
	totalParseErrors := 0
	
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err == nil {
		for _, mf := range mfs {
			switch mf.GetName() {
			case "ssl_cert_files_total":
				for _, m := range mf.GetMetric() {
					dir := metrics.FindLabel(m, "dir")
					if dir == "" {
						continue
					}
					totalFiles += int(m.GetCounter().GetValue())
				}
			case "ssl_certs_parsed_total":
				for _, m := range mf.GetMetric() {
					dir := metrics.FindLabel(m, "dir")
					if dir == "" {
						continue
					}
					totalParsed += int(m.GetCounter().GetValue())
				}
			case "ssl_cert_parse_errors_total":
				for _, m := range mf.GetMetric() {
					totalParseErrors += int(m.GetCounter().GetValue())
				}
			}
		}
	}
	
	checks["cert_scan"] = "complete"
	checks["cert_files_total"] = fmt.Sprintf("%d", totalFiles)
	checks["certs_parsed_total"] = fmt.Sprintf("%d", totalParsed)
	checks["cert_parse_errors_total"] = fmt.Sprintf("%d", totalParseErrors)
	
	resp := HealthResponse{
		Status: "ok",
		Checks: checks,
	}
	
	if !ok {
		resp.Status = "error"
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CertInfo represents certificate information for the API
type CertInfo struct {
	CommonName   string   `json:"common_name"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SANs         []string `json:"sans,omitempty"`
	ExpiringSoon bool     `json:"expiring_soon"`
	Type         string   `json:"type"`
}

func (s *Server) certsHandler(w http.ResponseWriter, r *http.Request) {
	var certList []CertInfo
	
	cfg := config.Get()
	paths := s.cache.GetPaths()
	
	// Process only the first (leaf) certificate from each file
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		
		// For PEM files, get the first certificate (leaf certificate)
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			// Try DER format if PEM decode fails
			if c, err := x509.ParseCertificate(raw); err == nil {
				expSoon := time.Until(c.NotAfter) <= time.Duration(cfg.ExpiryThresholdDays)*24*time.Hour
				certList = append(certList, CertInfo{
					CommonName:   c.Subject.CommonName,
					Issuer:       c.Issuer.CommonName,
					NotBefore:    c.NotBefore.Format(time.RFC3339),
					NotAfter:     c.NotAfter.Format(time.RFC3339),
					SANs:         c.DNSNames,
					ExpiringSoon: expSoon,
					Type:         "leaf_certificate",
				})
			}
			continue
		}
		
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		
		expSoon := time.Until(c.NotAfter) <= time.Duration(cfg.ExpiryThresholdDays)*24*time.Hour
		certList = append(certList, CertInfo{
			CommonName:   c.Subject.CommonName,
			Issuer:       c.Issuer.CommonName,
			NotBefore:    c.NotBefore.Format(time.RFC3339),
			NotAfter:     c.NotAfter.Format(time.RFC3339),
			SANs:         c.DNSNames,
			ExpiringSoon: expSoon,
			Type:         "leaf_certificate",
		})
	}
	
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(certList)
}

// Helper functions

func checkDiskSpace(dir string) error {
	var stat unix.Statfs_t
	err := unix.Statfs(dir, &stat)
	if err != nil {
		return err
	}
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	if availableBytes < 100*1024*1024 {
		return fmt.Errorf("low disk space: %d bytes available", availableBytes)
	}
	return nil
}

func checkLogWritable(logFile string) error {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func checkPrometheus() error {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return err
	}
	if len(mfs) == 0 {
		return fmt.Errorf("no metrics gathered")
	}
	return nil
}
