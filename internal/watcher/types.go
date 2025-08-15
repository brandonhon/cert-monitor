package watcher

import (
	"context"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher defines the interface for file system watching
type Watcher interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	AddDirectories(dirs []string) error
	RemoveDirectories(dirs []string) error
	IsWatching(path string) bool
	GetWatchedDirs() []string
}

// Config holds watcher configuration
type Config struct {
	// Directories to watch
	CertificateDirs []string

	// Configuration file to watch for changes
	ConfigFilePath string

	// Debounce duration for rapid file changes
	DebounceDelay time.Duration

	// Directories to exclude from watching
	ExcludedDirs []string

	// Event handling
	OnFileChange   func(event Event)
	OnConfigChange func(configPath string)
}

// Event represents a file system event
type Event struct {
	Type EventType
	Path string
	Op   fsnotify.Op
}

// EventType represents different types of events we care about
type EventType int

const (
	EventCertificateChange EventType = iota
	EventDirectoryChange
	EventConfigChange
)

// DefaultConfig returns a default watcher configuration
func DefaultConfig() *Config {
	return &Config{
		DebounceDelay: 2 * time.Second,
		ExcludedDirs:  []string{"old", "working", ".git", ".svn"},
	}
}
