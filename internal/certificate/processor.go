package certificate

import (
	"crypto/sha256"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultProcessor implements the Processor interface
type DefaultProcessor struct {
	parser   Parser
	analyzer Analyzer
	scanner  Scanner
}

// NewProcessor creates a new certificate processor with default implementations
func NewProcessor() Processor {
	return &DefaultProcessor{
		parser:   NewParser(),
		analyzer: NewAnalyzer(),
		scanner:  NewScanner(),
	}
}

// NewProcessorWithDeps creates a processor with custom dependencies
func NewProcessorWithDeps(parser Parser, analyzer Analyzer, scanner Scanner) Processor {
	return &DefaultProcessor{
		parser:   parser,
		analyzer: analyzer,
		scanner:  scanner,
	}
}

// ProcessDirectory processes all certificate files in a directory
func (p *DefaultProcessor) ProcessDirectory(path string, options ProcessingOptions) (*DirectoryStats, DuplicateMap, error) {
	start := time.Now()

	logger := log.WithField("directory", path)
	logger.Info("Starting certificate directory processing")

	stats := &DirectoryStats{
		LastScanTime: start,
	}
	duplicates := make(DuplicateMap)

	// Scan directory for certificate files
	files, err := p.scanner.ScanDirectory(path)
	if err != nil {
		return stats, duplicates, fmt.Errorf("failed to scan directory: %w", err)
	}

	stats.FilesProcessed = len(files)
	logger.WithField("files_found", len(files)).Debug("Certificate files discovered")

	// Process each certificate file
	for _, fileInfo := range files {
		result, err := p.ProcessFile(fileInfo.Path, options)
		if err != nil {
			logger.WithError(err).WithField("file", fileInfo.Path).Warn("Failed to process certificate file")
			stats.ParseErrors++
			continue
		}

		if result.Certificate == nil {
			logger.WithField("file", fileInfo.Path).Debug("No certificate found in file")
			continue
		}

		stats.CertsParsed++

		// Track duplicates by fingerprint
		fingerprint := sha256.Sum256(result.Certificate.Raw)
		fingerprintKey := fmt.Sprintf("%x", fingerprint)
		duplicates[fingerprintKey]++

		if duplicates[fingerprintKey] > 1 {
			stats.DuplicatesFound++
		}

		// Log processing details
		logger.WithFields(log.Fields{
			"file":        result.Info.FileName,
			"common_name": result.Info.CommonName,
			"issuer":      result.Info.Issuer,
			"expires":     result.Info.NotAfter,
			"sans":        len(result.Info.SANs),
			"weak_key":    result.Info.IsWeakKey,
			"deprecated":  result.Info.HasDeprecatedSigAlg,
		}).Debug("Certificate processed successfully")
	}

	stats.ProcessingTime = time.Since(start)

	logger.WithFields(log.Fields{
		"files_processed":  stats.FilesProcessed,
		"certs_parsed":     stats.CertsParsed,
		"parse_errors":     stats.ParseErrors,
		"duplicates_found": stats.DuplicatesFound,
		"processing_time":  stats.ProcessingTime,
	}).Info("Certificate directory processing completed")

	return stats, duplicates, nil
}

// ProcessFile processes a single certificate file
func (p *DefaultProcessor) ProcessFile(path string, options ProcessingOptions) (*ScanResult, error) {
	logger := log.WithField("file", path)

	// Parse the certificate
	cert, err := p.parser.ParseFile(path)
	if err != nil {
		return &ScanResult{
			Path:  path,
			Error: fmt.Errorf("parsing failed: %w", err),
		}, err
	}

	// Analyze the certificate
	info := p.analyzer.CreateInfo(cert, path, options)

	logger.WithFields(log.Fields{
		"common_name": info.CommonName,
		"issuer":      info.Issuer,
		"expires":     info.NotAfter,
		"sans":        len(info.SANs),
	}).Debug("Certificate file processed successfully")

	return &ScanResult{
		Certificate: cert,
		Info:        info,
		Path:        path,
		Error:       nil,
	}, nil
}

// ProcessFiles processes multiple certificate files
func (p *DefaultProcessor) ProcessFiles(files []FileInfo, options ProcessingOptions) ([]*ScanResult, error) {
	var results []*ScanResult

	for _, file := range files {
		result, err := p.ProcessFile(file.Path, options)
		if err != nil {
			log.WithError(err).WithField("file", file.Path).Warn("Failed to process certificate file")
			// Include failed results for error tracking
			results = append(results, result)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// GetDuplicatesByFingerprint returns certificates grouped by fingerprint
func GetDuplicatesByFingerprint(results []*ScanResult) map[string][]*ScanResult {
	duplicates := make(map[string][]*ScanResult)

	for _, result := range results {
		if result.Certificate == nil {
			continue
		}

		fingerprint := sha256.Sum256(result.Certificate.Raw)
		fingerprintKey := fmt.Sprintf("%x", fingerprint)
		duplicates[fingerprintKey] = append(duplicates[fingerprintKey], result)
	}

	// Filter to only include actual duplicates (more than 1 instance)
	actualDuplicates := make(map[string][]*ScanResult)
	for fingerprint, certs := range duplicates {
		if len(certs) > 1 {
			actualDuplicates[fingerprint] = certs
		}
	}

	return actualDuplicates
}

// FilterExpiringSoon returns certificates expiring within the threshold
func FilterExpiringSoon(results []*ScanResult, thresholdDays int) []*ScanResult {
	var expiring []*ScanResult
	threshold := time.Duration(thresholdDays) * 24 * time.Hour

	for _, result := range results {
		if result.Info != nil && time.Until(result.Info.NotAfter) <= threshold {
			expiring = append(expiring, result)
		}
	}

	return expiring
}

// FilterWeakSecurity returns certificates with security issues
func FilterWeakSecurity(results []*ScanResult) []*ScanResult {
	var weak []*ScanResult

	for _, result := range results {
		if result.Info != nil && (result.Info.IsWeakKey || result.Info.HasDeprecatedSigAlg) {
			weak = append(weak, result)
		}
	}

	return weak
}
