// # internal/cache/cache.go
package cache

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// CachedCertMeta holds metadata about a cached certificate
type CachedCertMeta struct {
	Fingerprint [32]byte
	ModTime     time.Time
	Size        int64
}

// Cache manages certificate caching
type Cache struct {
	filePath string
	data     map[string]CachedCertMeta
	mu       sync.RWMutex
}

// New creates a new cache instance
func New(filePath string) *Cache {
	return &Cache{
		filePath: filePath,
		data:     make(map[string]CachedCertMeta),
	}
}

// Load loads the cache from disk
func (c *Cache) Load() {
	if c.filePath == "" {
		log.Debug("No cache file path specified, skipping cache load")
		return
	}
	
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		log.WithError(err).Info("No existing cache file or read error")
		return
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if err := json.Unmarshal(data, &c.data); err != nil {
		log.WithError(err).Warn("Failed to parse cache file")
		// Reset cache to empty state if parsing fails
		c.data = make(map[string]CachedCertMeta)
		return
	}
	
	log.WithField("entries", len(c.data)).Info("Loaded certificate cache from file")
}

// Save saves the cache to disk
func (c *Cache) Save() {
	if c.filePath == "" {
		log.Debug("No cache file path specified, skipping cache save")
		return
	}
	
	c.mu.RLock()
	cacheSize := len(c.data)
	// Create a copy to avoid holding the lock during I/O
	cacheCopy := make(map[string]CachedCertMeta, cacheSize)
	for k, v := range c.data {
		cacheCopy[k] = v
	}
	c.mu.RUnlock()
	
	data, err := json.MarshalIndent(cacheCopy, "", "  ")
	if err != nil {
		log.WithError(err).Warn("Failed to marshal cache")
		return
	}
	
	// Create directory if it doesn't exist
	if dir := filepath.Dir(c.filePath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.WithError(err).WithField("dir", dir).Warn("Failed to create cache directory")
			return
		}
	}
	
	if err := os.WriteFile(c.filePath, data, 0o644); err != nil {
		log.WithError(err).Warn("Failed to write cache file")
	} else {
		log.WithFields(log.Fields{
			"path":    c.filePath,
			"entries": cacheSize,
		}).Debug("Successfully saved certificate cache")
	}
}

// GetEntryAtomic safely retrieves a cache entry and file stat in one operation
func (c *Cache) GetEntryAtomic(path string) (CachedCertMeta, os.FileInfo, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return CachedCertMeta{}, nil, false, err
	}
	
	c.mu.RLock()
	cached, found := c.data[path]
	c.mu.RUnlock()
	
	return cached, info, found, nil
}

// SetEntryAtomic safely updates a cache entry with file information
func (c *Cache) SetEntryAtomic(path string, fingerprint [32]byte, info os.FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.data[path] = CachedCertMeta{
		Fingerprint: fingerprint,
		ModTime:     info.ModTime(),
		Size:        info.Size(),
	}
}

// Clear clears the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]CachedCertMeta)
}

// PruneNonExisting removes entries whose files no longer exist
func (c *Cache) PruneNonExisting() int {
	start := time.Now()
	pruned := 0
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	for path := range c.data {
		if _, err := os.Stat(path); err != nil {
			delete(c.data, path)
			pruned++
		}
	}
	
	if pruned > 0 {
		log.WithFields(log.Fields{
			"removed":  pruned,
			"duration": time.Since(start),
		}).Info("Pruned stale cache entries")
	} else {
		log.Debug("No stale cache entries to prune")
	}
	
	return pruned
}

// GetPaths returns all cached file paths
func (c *Cache) GetPaths() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	paths := make([]string, 0, len(c.data))
	for path := range c.data {
		paths = append(paths, path)
	}
	return paths
}
