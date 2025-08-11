package cache

import (
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultManager implements the Manager interface
type DefaultManager struct {
	cache      map[string]Entry
	mutex      sync.RWMutex
	config     Config
	stats      Statistics
	statsMutex sync.RWMutex
}

// NewManager creates a new cache manager with the specified configuration
func NewManager(config Config) Manager {
	manager := &DefaultManager{
		cache:  make(map[string]Entry),
		config: config,
		stats: Statistics{
			CacheFilePath: config.FilePath,
		},
	}

	log.WithFields(log.Fields{
		"cache_file":     config.FilePath,
		"auto_save":      config.AutoSave,
		"save_interval":  config.SaveInterval,
		"prune_interval": config.PruneInterval,
		"max_entries":    config.MaxEntries,
	}).Info("Cache manager initialized")

	return manager
}

// Get retrieves a cache entry and file info atomically
func (m *DefaultManager) Get(path string) (*Entry, *FileInfo, bool, error) {
	// Get file info first
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	wrappedInfo := &FileInfo{
		ModTime: fileInfo.ModTime(),
		Size:    fileInfo.Size(),
		Info:    fileInfo,
	}

	// Check cache
	m.mutex.RLock()
	entry, found := m.cache[path]
	m.mutex.RUnlock()

	// Update statistics
	if m.config.EnableStats {
		m.statsMutex.Lock()
		if found {
			m.stats.CacheHits++
		} else {
			m.stats.CacheMisses++
		}
		m.updateHitRate()
		m.statsMutex.Unlock()
	}

	if found {
		log.WithFields(log.Fields{
			"path":      path,
			"cache_hit": true,
			"mod_time":  entry.ModTime,
			"size":      entry.Size,
		}).Debug("Cache entry retrieved")
	} else {
		log.WithFields(log.Fields{
			"path":      path,
			"cache_hit": false,
		}).Debug("Cache miss for file")
	}

	return &entry, wrappedInfo, found, nil
}

// Set stores a cache entry
func (m *DefaultManager) Set(path string, fingerprint [32]byte, info *FileInfo) {
	// Validate that the file still exists before caching
	if _, err := os.Stat(path); err != nil {
		log.WithFields(log.Fields{
			"path":  path,
			"error": err,
		}).Debug("Skipping cache update for non-existent file")
		return
	}

	entry := Entry{
		Fingerprint: fingerprint,
		ModTime:     info.ModTime,
		Size:        info.Size,
	}

	m.mutex.Lock()
	m.cache[path] = entry
	m.mutex.Unlock()

	log.WithFields(log.Fields{
		"path":        path,
		"fingerprint": fmt.Sprintf("%x", fingerprint[:8]), // Show first 8 bytes
		"mod_time":    entry.ModTime,
		"size":        entry.Size,
	}).Debug("Cache entry updated")

	// Check if we need to enforce max entries
	if m.config.MaxEntries > 0 && m.Size() > m.config.MaxEntries {
		log.WithField("max_entries", m.config.MaxEntries).Debug("Cache size limit exceeded, pruning oldest entries")
		m.pruneOldest()
	}
}

// Delete removes a cache entry
func (m *DefaultManager) Delete(path string) {
	m.mutex.Lock()
	delete(m.cache, path)
	m.mutex.Unlock()

	log.WithField("path", path).Debug("Cache entry deleted")
}

// Load loads cache from file
func (m *DefaultManager) Load(path string) error {
	if path == "" {
		log.Debug("No cache file path specified, skipping cache load")
		return nil
	}

	start := time.Now()
	data, err := os.ReadFile(path)
	if err != nil {
		log.WithError(err).WithField("cache_file", path).Info("No existing cache file or read error")
		return nil
	}

	m.mutex.Lock()
	m.cache, err = deserializeCache(data, m.cache)
	if err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to parse cache file, resetting cache")
		m.cache = make(map[string]Entry)
		m.mutex.Unlock()
		return fmt.Errorf("failed to deserialize cache: %w", err)
	}
	cacheSize := len(m.cache)
	m.mutex.Unlock()

	// Update statistics
	if m.config.EnableStats {
		m.statsMutex.Lock()
		m.stats.LastLoadTime = time.Now().Format(time.RFC3339)
		m.stats.TotalEntries = cacheSize
		m.statsMutex.Unlock()
	}

	log.WithFields(log.Fields{
		"cache_file": path,
		"entries":    cacheSize,
		"load_time":  time.Since(start),
	}).Info("Certificate cache loaded successfully")

	return nil
}

// Save saves cache to file
func (m *DefaultManager) Save(path string) error {
	if path == "" {
		log.Debug("No cache file path specified, skipping cache save")
		return nil
	}

	start := time.Now()

	// Create copy to avoid holding lock during I/O
	m.mutex.RLock()
	cacheSize := len(m.cache)
	cacheCopy := make(map[string]Entry, cacheSize)
	for k, v := range m.cache {
		cacheCopy[k] = v
	}
	m.mutex.RUnlock()

	data, err := serializeCache(cacheCopy)
	if err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to marshal cache")
		return fmt.Errorf("failed to serialize cache: %w", err)
	}

	// Create directory if needed
	if err := createCacheDir(path); err != nil {
		return fmt.Errorf("cache directory creation failed: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.WithError(err).WithField("cache_file", path).Warn("Failed to write cache file")
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Update statistics
	if m.config.EnableStats {
		m.statsMutex.Lock()
		m.stats.LastSaveTime = time.Now().Format(time.RFC3339)
		m.stats.TotalEntries = cacheSize
		m.statsMutex.Unlock()
	}

	log.WithFields(log.Fields{
		"cache_file": path,
		"entries":    cacheSize,
		"save_time":  time.Since(start),
	}).Debug("Certificate cache saved successfully")

	return nil
}

// Prune removes cache entries for files that no longer exist
func (m *DefaultManager) Prune() int {
	start := time.Now()
	pruned := 0

	m.mutex.Lock()
	for path := range m.cache {
		if _, err := os.Stat(path); err != nil {
			delete(m.cache, path)
			pruned++
		}
	}
	m.mutex.Unlock()

	// Update statistics
	if m.config.EnableStats {
		m.statsMutex.Lock()
		m.stats.LastPruneTime = time.Now().Format(time.RFC3339)
		m.stats.TotalEntries = m.Size()
		m.statsMutex.Unlock()
	}

	if pruned > 0 {
		log.WithFields(log.Fields{
			"removed_entries": pruned,
			"duration":        time.Since(start),
		}).Info("Pruned stale cache entries")
	} else {
		log.Debug("No stale cache entries found to prune")
	}

	return pruned
}

// Clear removes all cache entries
func (m *DefaultManager) Clear() {
	m.mutex.Lock()
	oldSize := len(m.cache)
	m.cache = make(map[string]Entry)
	m.mutex.Unlock()

	// Reset statistics when clearing cache
	if m.config.EnableStats {
		m.statsMutex.Lock()
		oldHits := m.stats.CacheHits
		oldMisses := m.stats.CacheMisses
		m.stats = Statistics{
			CacheFilePath: m.config.FilePath,
			CacheHits:     0,
			CacheMisses:   0,
			TotalEntries:  0,
			HitRate:       0.0,
		}
		m.statsMutex.Unlock()

		log.WithFields(log.Fields{
			"cleared_entries": oldSize,
			"reset_hits":      oldHits,
			"reset_misses":    oldMisses,
		}).Info("Certificate cache and statistics cleared")
	} else {
		log.WithField("cleared_entries", oldSize).Info("Certificate cache cleared")
	}
}

// Stats returns current cache statistics
func (m *DefaultManager) Stats() Statistics {
	if !m.config.EnableStats {
		return Statistics{
			CacheFilePath: m.config.FilePath,
			TotalEntries:  m.Size(),
		}
	}

	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	// Update current size
	stats := m.stats
	stats.TotalEntries = m.Size()

	return stats
}

// Size returns the current number of cache entries
func (m *DefaultManager) Size() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.cache)
}

// updateHitRate calculates and updates the cache hit rate
func (m *DefaultManager) updateHitRate() {
	totalAccesses := m.stats.CacheHits + m.stats.CacheMisses
	if totalAccesses > 0 {
		m.stats.HitRate = float64(m.stats.CacheHits) / float64(totalAccesses) * 100
	} else {
		m.stats.HitRate = 0.0
	}
}

// pruneOldest removes the oldest cache entries to enforce max size
func (m *DefaultManager) pruneOldest() {
	if m.config.MaxEntries <= 0 {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	currentSize := len(m.cache)
	if currentSize <= m.config.MaxEntries {
		return
	}

	// Create slice of entries with timestamps for sorting
	type entryWithTime struct {
		path string
		time time.Time
	}

	entries := make([]entryWithTime, 0, currentSize)
	for path, entry := range m.cache {
		entries = append(entries, entryWithTime{
			path: path,
			time: entry.ModTime,
		})
	}

	// Sort by modification time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].time.After(entries[j].time) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries
	toRemove := currentSize - m.config.MaxEntries
	for i := 0; i < toRemove; i++ {
		delete(m.cache, entries[i].path)
	}

	log.WithFields(log.Fields{
		"removed_entries": toRemove,
		"new_size":        len(m.cache),
		"max_entries":     m.config.MaxEntries,
	}).Info("Pruned oldest cache entries to enforce size limit")
}

// IsStale checks if a cache entry is stale compared to file info
func IsStale(entry *Entry, info *FileInfo) bool {
	return !entry.ModTime.Equal(info.ModTime) || entry.Size != info.Size
}

// ValidateEntry checks if a cache entry is valid
func ValidateEntry(path string, entry *Entry) error {
	if entry == nil {
		return fmt.Errorf("cache entry is nil")
	}

	if entry.ModTime.IsZero() {
		return fmt.Errorf("invalid modification time in cache entry for %s", path)
	}

	if entry.Size < 0 {
		return fmt.Errorf("invalid size in cache entry for %s", path)
	}

	return nil
}
