package certificate

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// DefaultScanner implements the Scanner interface
type DefaultScanner struct{}

// NewScanner creates a new certificate scanner
func NewScanner() Scanner {
	return &DefaultScanner{}
}

// ScanDirectory scans a directory for certificate files
func (s *DefaultScanner) ScanDirectory(path string) ([]FileInfo, error) {
	var certFiles []FileInfo

	err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			log.WithError(err).WithField("path", filePath).Warn("Error accessing file during scan")
			return nil // Continue walking despite errors
		}

		if d.IsDir() {
			return s.handleDirectory(d)
		}

		if !s.IsCertificateFile(d.Name()) {
			return nil
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			log.WithError(err).WithField("path", filePath).Warn("Failed to get file info")
			return nil
		}

		certFiles = append(certFiles, FileInfo{
			Path:     filePath,
			ModTime:  info.ModTime(),
			Size:     info.Size(),
			FileInfo: info,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan directory %q: %w", path, err)
	}

	log.WithFields(log.Fields{
		"directory":         path,
		"certificate_files": len(certFiles),
	}).Debug("Directory scan completed")

	return certFiles, nil
}

// IsCertificateFile checks if a file is a certificate based on extension
func (s *DefaultScanner) IsCertificateFile(filename string) bool {
	return IsCertificateFile(filename)
}

// handleDirectory determines whether to process or skip a directory
func (s *DefaultScanner) handleDirectory(d fs.DirEntry) error {
	dirName := strings.ToLower(d.Name())

	// Skip excluded directories
	excludedDirs := []string{"old", "working", "backup", "archive"}
	for _, excluded := range excludedDirs {
		if dirName == excluded {
			log.WithField("directory", d.Name()).Debug("Skipping excluded subdirectory")
			return filepath.SkipDir
		}
	}

	return nil
}

// GetFileStats returns statistics about files in a directory
func GetFileStats(files []FileInfo) map[string]interface{} {
	stats := make(map[string]interface{})

	stats["total_files"] = len(files)

	if len(files) == 0 {
		return stats
	}

	// Calculate size statistics
	var totalSize int64
	for _, file := range files {
		totalSize += file.Size
	}
	stats["total_size_bytes"] = totalSize
	stats["average_size_bytes"] = totalSize / int64(len(files))

	// Count by extension
	extCounts := make(map[string]int)
	for _, file := range files {
		ext := strings.ToLower(filepath.Ext(file.Path))
		extCounts[ext]++
	}
	stats["extensions"] = extCounts

	return stats
}

// FilterFilesByAge filters files based on modification time
func FilterFilesByAge(files []FileInfo, olderThan string) ([]FileInfo, error) {
	// This could be enhanced to parse duration strings like "30d", "1w", etc.
	// For now, return all files
	return files, nil
}

// SortFilesByModTime sorts files by modification time (newest first)
func SortFilesByModTime(files []FileInfo) {
	// Simple sort implementation - could use sort package for more complex sorting
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].ModTime.Before(files[j].ModTime) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
}
