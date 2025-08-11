package cache

import (
	"os"
	"time"
)

// Manager defines the interface for certificate cache management
type Manager interface {
	// Entry operations
	Get(path string) (*Entry, *FileInfo, bool, error)
	Set(path string, fingerprint [32]byte, info *FileInfo)
	Delete(path string)

	// Bulk operations
	Load(path string) error
	Save(path string) error
	Prune() int
	Clear()

	// Statistics
	Stats() Statistics
	Size() int
}

// Entry represents a cached certificate metadata entry
type Entry struct {
	Fingerprint [32]byte  `json:"fingerprint"`
	ModTime     time.Time `json:"mod_time"`
	Size        int64     `json:"size"`
}

// FileInfo wraps os.FileInfo for easier testing and serialization
type FileInfo struct {
	ModTime time.Time
	Size    int64
	Info    os.FileInfo `json:"-"` // Don't serialize the actual FileInfo
}

// Statistics contains cache performance statistics
type Statistics struct {
	TotalEntries  int     `json:"total_entries"`
	CacheHits     int64   `json:"cache_hits"`
	CacheMisses   int64   `json:"cache_misses"`
	HitRate       float64 `json:"hit_rate"`
	LastPruneTime string  `json:"last_prune_time,omitempty"`
	CacheFilePath string  `json:"cache_file_path"`
	LastSaveTime  string  `json:"last_save_time,omitempty"`
	LastLoadTime  string  `json:"last_load_time,omitempty"`
}

// Config configures cache behavior
type Config struct {
	FilePath      string
	AutoSave      bool
	SaveInterval  time.Duration
	PruneInterval time.Duration
	MaxEntries    int
	EnableStats   bool
}

// Result represents the result of a cache operation
type Result struct {
	Hit   bool
	Entry *Entry
	Error error
}
