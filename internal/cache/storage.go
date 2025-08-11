package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// serializeCache serializes the cache to JSON
func serializeCache(cache map[string]Entry) ([]byte, error) {
	return json.MarshalIndent(cache, "", "  ")
}

// deserializeCache deserializes JSON data to cache
func deserializeCache(data []byte, cache map[string]Entry) (map[string]Entry, error) {
	err := json.Unmarshal(data, &cache)
	return cache, err
}

// createCacheDir creates the directory for the cache file if it doesn't exist
func createCacheDir(cacheFilePath string) error {
	dir := filepath.Dir(cacheFilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory %s: %w", dir, err)
	}
	return nil
}

// BackupCache creates a backup of the cache file
func BackupCache(cacheFilePath string) error {
	if cacheFilePath == "" {
		return fmt.Errorf("cache file path is empty")
	}

	// Check if cache file exists
	if _, err := os.Stat(cacheFilePath); os.IsNotExist(err) {
		return nil // No cache file to backup
	}

	backupPath := cacheFilePath + ".backup"

	// Read original cache
	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return fmt.Errorf("failed to read cache file for backup: %w", err)
	}

	// Write backup
	if err := os.WriteFile(backupPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write cache backup: %w", err)
	}

	return nil
}

// RestoreCache restores cache from backup
func RestoreCache(cacheFilePath string) error {
	if cacheFilePath == "" {
		return fmt.Errorf("cache file path is empty")
	}

	backupPath := cacheFilePath + ".backup"

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	// Read backup
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Create directory if needed
	if err := createCacheDir(cacheFilePath); err != nil {
		return err
	}

	// Write restored cache
	if err := os.WriteFile(cacheFilePath, data, 0o644); err != nil {
		return fmt.Errorf("failed to restore cache from backup: %w", err)
	}

	return nil
}

// ValidateCacheFile validates the structure of a cache file
func ValidateCacheFile(cacheFilePath string) error {
	if cacheFilePath == "" {
		return fmt.Errorf("cache file path is empty")
	}

	// Check if file exists
	if _, err := os.Stat(cacheFilePath); os.IsNotExist(err) {
		return nil // No cache file is valid (will be created)
	}

	// Read and parse cache file
	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	// Try to parse as JSON
	var cache map[string]Entry
	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("cache file is not valid JSON: %w", err)
	}

	// Validate each entry
	for path, entry := range cache {
		entryCopy := entry
		if err := ValidateEntry(path, &entryCopy); err != nil {
			return fmt.Errorf("invalid cache entry: %w", err)
		}
	}

	return nil
}

// CleanupCacheFiles removes old cache and backup files
func CleanupCacheFiles(cacheFilePath string, keepBackups bool) error {
	if cacheFilePath == "" {
		return nil
	}

	var errors []error

	// Remove main cache file
	if err := os.Remove(cacheFilePath); err != nil && !os.IsNotExist(err) {
		errors = append(errors, fmt.Errorf("failed to remove cache file: %w", err))
	}

	// Remove backup file if not keeping backups
	if !keepBackups {
		backupPath := cacheFilePath + ".backup"
		if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
			errors = append(errors, fmt.Errorf("failed to remove backup file: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	return nil
}

// GetCacheFileInfo returns information about the cache file
func GetCacheFileInfo(cacheFilePath string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	if cacheFilePath == "" {
		info["exists"] = false
		info["error"] = "no cache file path specified"
		return info, nil
	}

	fileInfo, err := os.Stat(cacheFilePath)
	if os.IsNotExist(err) {
		info["exists"] = false
		return info, nil
	}
	if err != nil {
		info["exists"] = false
		info["error"] = err.Error()
		return info, fmt.Errorf("failed to stat cache file: %w", err)
	}

	info["exists"] = true
	info["size"] = fileInfo.Size()
	info["mod_time"] = fileInfo.ModTime().Format("2006-01-02 15:04:05")
	info["mode"] = fileInfo.Mode().String()

	// Try to get entry count
	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		info["read_error"] = err.Error()
		return info, nil
	}

	var cache map[string]Entry
	if err := json.Unmarshal(data, &cache); err != nil {
		info["parse_error"] = err.Error()
		return info, nil
	}

	info["entry_count"] = len(cache)

	// Check for backup
	backupPath := cacheFilePath + ".backup"
	if _, err := os.Stat(backupPath); err == nil {
		info["has_backup"] = true
	} else {
		info["has_backup"] = false
	}

	return info, nil
}

// MigrateCache migrates cache from old location to new location
func MigrateCache(oldPath, newPath string) error {
	if oldPath == "" || newPath == "" {
		return fmt.Errorf("cache paths cannot be empty")
	}

	if oldPath == newPath {
		return nil // No migration needed
	}

	// Check if old cache exists
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return nil // No old cache to migrate
	}

	// Create backup of old cache
	if err := BackupCache(oldPath); err != nil {
		return fmt.Errorf("failed to backup old cache before migration: %w", err)
	}

	// Read old cache
	data, err := os.ReadFile(oldPath)
	if err != nil {
		return fmt.Errorf("failed to read old cache file: %w", err)
	}

	// Validate old cache structure
	var cache map[string]Entry
	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("old cache file is corrupted: %w", err)
	}

	// Create new cache directory
	if err := createCacheDir(newPath); err != nil {
		return fmt.Errorf("failed to create new cache directory: %w", err)
	}

	// Write to new location
	if err := os.WriteFile(newPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write cache to new location: %w", err)
	}

	// Remove old cache file (but keep backup)
	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("failed to remove old cache file: %w", err)
	}

	return nil
}

// CompactCache removes invalid entries and optimizes the cache file
func CompactCache(cacheFilePath string) (int, error) {
	if cacheFilePath == "" {
		return 0, fmt.Errorf("cache file path is empty")
	}

	// Read current cache
	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache file: %w", err)
	}

	var cache map[string]Entry
	if err := json.Unmarshal(data, &cache); err != nil {
		return 0, fmt.Errorf("failed to parse cache file: %w", err)
	}

	removed := 0

	// Remove entries for non-existent files
	for path := range cache {
		if _, err := os.Stat(path); err != nil {
			delete(cache, path)
			removed++
		}
	}

	// Only write if we removed entries
	if removed > 0 {
		compactedData, err := json.MarshalIndent(cache, "", "  ")
		if err != nil {
			return 0, fmt.Errorf("failed to marshal compacted cache: %w", err)
		}

		if err := os.WriteFile(cacheFilePath, compactedData, 0o644); err != nil {
			return 0, fmt.Errorf("failed to write compacted cache: %w", err)
		}
	}

	return removed, nil
}
