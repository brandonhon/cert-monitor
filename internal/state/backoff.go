package state

import (
	"math/rand"
	"sync"
	"time"

	"github.com/brandonhon/cert-monitor/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// BackoffManager handles scan failure backoff logic
type BackoffManager struct {
	backoffs map[string]time.Time
	mutex    sync.Mutex
}

// NewBackoffManager creates a new backoff manager
func NewBackoffManager() *BackoffManager {
	return &BackoffManager{
		backoffs: make(map[string]time.Time),
	}
}

// RegisterFailure registers a scan failure and applies exponential backoff
func (bm *BackoffManager) RegisterFailure(directory string) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	now := time.Now()
	delay := 30 * time.Second

	// Apply exponential backoff if already in backoff
	if lastBackoff, exists := bm.backoffs[directory]; exists && lastBackoff.After(now) {
		delay = lastBackoff.Sub(now) * 2
		if delay < 0 || delay > utils.MaxBackoff {
			delay = utils.MaxBackoff
		}
	}

	// Add jitter to prevent thundering herd
	jitter := time.Duration(rand.Int63n(int64(10 * time.Second)))
	nextScan := now.Add(delay + jitter)
	bm.backoffs[directory] = nextScan

	log.WithFields(log.Fields{
		"directory":     directory,
		"backoff_delay": delay + jitter,
		"retry_after":   nextScan.Format(time.RFC3339),
	}).Warn("Scan failed, applying exponential backoff")
}

// ShouldSkip checks if a directory should be skipped due to backoff
func (bm *BackoffManager) ShouldSkip(directory string) bool {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	nextAllowed, exists := bm.backoffs[directory]
	if !exists {
		return false
	}

	now := time.Now()
	if now.Before(nextAllowed) {
		log.WithFields(log.Fields{
			"directory":      directory,
			"backoff_until":  nextAllowed.Format(time.RFC3339),
			"remaining_time": nextAllowed.Sub(now),
		}).Debug("Directory scan skipped due to backoff")
		return true
	}

	// Backoff expired, remove entry
	delete(bm.backoffs, directory)
	log.WithField("directory", directory).Debug("Backoff period expired, allowing scan")
	return false
}

// ClearExpired removes expired backoff entries
func (bm *BackoffManager) ClearExpired() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	now := time.Now()
	removed := 0

	for directory, nextAllowed := range bm.backoffs {
		if now.After(nextAllowed) {
			delete(bm.backoffs, directory)
			removed++
		}
	}

	if removed > 0 {
		log.WithFields(log.Fields{
			"removed_entries":   removed,
			"remaining_entries": len(bm.backoffs),
		}).Debug("Cleared expired backoff entries")
	}
}

// GetStats returns statistics about current backoffs
func (bm *BackoffManager) GetStats() map[string]interface{} {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	return map[string]interface{}{
		"active_backoffs": len(bm.backoffs),
		"directories": func() []string {
			var dirs []string
			for dir := range bm.backoffs {
				dirs = append(dirs, dir)
			}
			return dirs
		}(),
	}
}
