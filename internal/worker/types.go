package worker

import (
	"context"
	"sync"
)

// Pool represents a worker pool for processing certificate directories
type Pool interface {
	// Start initializes the worker pool with the specified number of workers
	Start(ctx context.Context, numWorkers int) error

	// Submit adds a job to the processing queue
	Submit(job Job) error

	// Wait waits for all submitted jobs to complete
	Wait(ctx context.Context) error

	// Shutdown gracefully shuts down the worker pool
	Shutdown(ctx context.Context) error

	// Stats returns current pool statistics
	Stats() Statistics
}

// Job represents a unit of work for the worker pool
type Job interface {
	// Process executes the job
	Process(ctx context.Context) error

	// ID returns a unique identifier for the job
	ID() string

	// Priority returns the job priority (higher numbers = higher priority)
	Priority() int
}

// Statistics contains worker pool statistics
type Statistics struct {
	// Total number of workers in the pool
	WorkerCount int

	// Number of currently active workers
	ActiveWorkers int

	// Number of jobs currently queued
	QueuedJobs int

	// Total number of jobs processed
	ProcessedJobs int64

	// Total number of jobs failed
	FailedJobs int64

	// Current pool status
	Status PoolStatus
}

// PoolStatus represents the current status of the worker pool
type PoolStatus int

const (
	// StatusStopped indicates the pool is not running
	StatusStopped PoolStatus = iota

	// StatusStarting indicates the pool is starting up
	StatusStarting

	// StatusRunning indicates the pool is running and accepting jobs
	StatusRunning

	// StatusStopping indicates the pool is shutting down
	StatusStopping
)

// String returns a string representation of the pool status
func (s PoolStatus) String() string {
	switch s {
	case StatusStopped:
		return "stopped"
	case StatusStarting:
		return "starting"
	case StatusRunning:
		return "running"
	case StatusStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

// WorkerPoolConfig contains configuration for the worker pool
type WorkerPoolConfig struct {
	// NumWorkers is the number of worker goroutines to create
	NumWorkers int

	// QueueSize is the size of the job queue buffer
	QueueSize int

	// EnableMetrics enables collection of worker pool metrics
	EnableMetrics bool
}

// DefaultConfig returns a default worker pool configuration
func DefaultConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		NumWorkers:    4,
		QueueSize:     100,
		EnableMetrics: true,
	}
}

// worker represents an individual worker in the pool
type worker struct {
	id     int
	pool   *workerPool
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// workerPool is the internal implementation of the Pool interface
type workerPool struct {
	// Configuration
	config *WorkerPoolConfig

	// Job processing
	jobs    chan Job
	workers []*worker

	// Synchronization
	wg     *sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics tracking
	stats      Statistics
	statsMutex sync.RWMutex

	// State management
	statusMutex sync.RWMutex
	status      PoolStatus
}
