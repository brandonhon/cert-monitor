package worker

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// JobType represents different types of jobs that can be processed
type JobType int

const (
	// JobTypeDirectory represents a directory scanning job
	JobTypeDirectory JobType = iota

	// JobTypeCertificate represents a single certificate processing job
	JobTypeCertificate

	// JobTypeMaintenance represents a maintenance task job
	JobTypeMaintenance
)

// String returns a string representation of the job type
func (jt JobType) String() string {
	switch jt {
	case JobTypeDirectory:
		return "directory"
	case JobTypeCertificate:
		return "certificate"
	case JobTypeMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// JobResult contains the result of job processing
type JobResult struct {
	// JobID is the unique identifier of the processed job
	JobID string

	// Success indicates whether the job completed successfully
	Success bool

	// Error contains any error that occurred during processing
	Error error

	// ProcessingTime is the duration the job took to process
	ProcessingTime time.Duration

	// Metadata contains job-specific result data
	Metadata map[string]interface{}
}

// BaseJob provides common functionality for all job types
type BaseJob struct {
	id          string
	jobType     JobType
	priority    int
	submitted   time.Time
	started     *time.Time
	completed   *time.Time
	attempts    int32
	maxAttempts int32
}

// NewBaseJob creates a new base job with the given parameters
func NewBaseJob(id string, jobType JobType, priority int) *BaseJob {
	return &BaseJob{
		id:          id,
		jobType:     jobType,
		priority:    priority,
		submitted:   time.Now(),
		maxAttempts: 3, // Default retry attempts
	}
}

// ID returns the job ID
func (b *BaseJob) ID() string {
	return b.id
}

// Priority returns the job priority
func (b *BaseJob) Priority() int {
	return b.priority
}

// Type returns the job type
func (b *BaseJob) Type() JobType {
	return b.jobType
}

// Attempts returns the number of processing attempts
func (b *BaseJob) Attempts() int32 {
	return atomic.LoadInt32(&b.attempts)
}

// IncrementAttempts atomically increments the attempt counter
func (b *BaseJob) IncrementAttempts() int32 {
	return atomic.AddInt32(&b.attempts, 1)
}

// ShouldRetry returns whether the job should be retried
func (b *BaseJob) ShouldRetry() bool {
	return atomic.LoadInt32(&b.attempts) < b.maxAttempts
}

// SetStartTime marks the job as started
func (b *BaseJob) SetStartTime() {
	now := time.Now()
	b.started = &now
}

// SetCompletedTime marks the job as completed
func (b *BaseJob) SetCompletedTime() {
	now := time.Now()
	b.completed = &now
}

// ProcessingDuration returns the time taken to process the job
func (b *BaseJob) ProcessingDuration() time.Duration {
	if b.started == nil || b.completed == nil {
		return 0
	}
	return b.completed.Sub(*b.started)
}

// DirectoryJob represents a certificate directory processing job
type DirectoryJob struct {
	*BaseJob

	// DirectoryPath is the path to scan for certificates
	DirectoryPath string

	// ProcessorFunc is the function to call for processing the directory
	ProcessorFunc func(string, bool)
}

// Process implements the Job interface
func (d *DirectoryJob) Process(ctx context.Context) error {
	d.SetStartTime()
	defer d.SetCompletedTime()

	attempt := d.IncrementAttempts()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		log.WithFields(log.Fields{
			"directory": d.DirectoryPath,
			"attempt":   attempt,
		}).Info("Processing certificate directory")

		if d.ProcessorFunc != nil {
			d.ProcessorFunc(d.DirectoryPath, false)
		}
		return nil
	}
}

// NewDirectoryJob creates a new directory processing job
func NewDirectoryJob(directoryPath string, processorFunc func(string, bool), priority int) *DirectoryJob {
	cleanPath := filepath.Clean(directoryPath)
	jobID := fmt.Sprintf("dir-%s-%d", sanitizeForID(cleanPath), time.Now().UnixNano())

	return &DirectoryJob{
		BaseJob:       NewBaseJob(jobID, JobTypeDirectory, priority),
		DirectoryPath: directoryPath,
		ProcessorFunc: processorFunc,
	}
}

// CertificateJob represents a single certificate processing job
type CertificateJob struct {
	*BaseJob

	// CertificatePath is the path to the certificate file
	CertificatePath string

	// ProcessorFunc is the function to call for processing the certificate
	ProcessorFunc func(string) error
}

// Process implements the Job interface for CertificateJob
func (c *CertificateJob) Process(ctx context.Context) error {
	c.SetStartTime()
	defer c.SetCompletedTime()

	attempt := c.IncrementAttempts()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		log.WithFields(log.Fields{
			"certificate": c.CertificatePath,
			"attempt":     attempt,
		}).Debug("Processing certificate")

		if c.ProcessorFunc != nil {
			return c.ProcessorFunc(c.CertificatePath)
		}
		return nil
	}
}

// NewCertificateJob creates a new certificate processing job
func NewCertificateJob(certificatePath string, processorFunc func(string) error, priority int) *CertificateJob {
	cleanPath := filepath.Clean(certificatePath)
	jobID := fmt.Sprintf("cert-%s-%d", sanitizeForID(cleanPath), time.Now().UnixNano())

	return &CertificateJob{
		BaseJob:         NewBaseJob(jobID, JobTypeCertificate, priority),
		CertificatePath: certificatePath,
		ProcessorFunc:   processorFunc,
	}
}

// MaintenanceJob represents a maintenance task job
type MaintenanceJob struct {
	*BaseJob

	// TaskName is a human-readable name for the maintenance task
	TaskName string

	// TaskFunc is the function to execute for the maintenance task
	TaskFunc func(ctx context.Context) error
}

// Process implements the Job interface for MaintenanceJob
func (m *MaintenanceJob) Process(ctx context.Context) error {
	m.SetStartTime()
	defer m.SetCompletedTime()

	attempt := m.IncrementAttempts()

	log.WithFields(log.Fields{
		"task":    m.TaskName,
		"attempt": attempt,
	}).Debug("Executing maintenance task")

	if m.TaskFunc != nil {
		return m.TaskFunc(ctx)
	}
	return nil
}

// NewMaintenanceJob creates a new maintenance job
func NewMaintenanceJob(taskName string, taskFunc func(ctx context.Context) error, priority int) *MaintenanceJob {
	jobID := fmt.Sprintf("maint-%s-%d", sanitizeForID(taskName), time.Now().UnixNano())

	return &MaintenanceJob{
		BaseJob:  NewBaseJob(jobID, JobTypeMaintenance, priority),
		TaskName: taskName,
		TaskFunc: taskFunc,
	}
}

// sanitizeForID removes problematic characters from strings for use in IDs
func sanitizeForID(s string) string {
	// Replace path separators and other problematic characters
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ":", "_")

	// Limit length to prevent excessively long IDs
	if len(s) > 50 {
		s = s[:50]
	}

	return s
}

// JobQueue represents a priority queue for jobs
type JobQueue struct {
	jobs     []Job
	capacity int
}

// NewJobQueue creates a new job queue with the specified capacity
func NewJobQueue(capacity int) *JobQueue {
	return &JobQueue{
		jobs:     make([]Job, 0, capacity),
		capacity: capacity,
	}
}

// Push adds a job to the queue
func (jq *JobQueue) Push(job Job) bool {
	if len(jq.jobs) >= jq.capacity {
		return false
	}

	jq.jobs = append(jq.jobs, job)
	jq.sortByPriority()
	return true
}

// Pop removes and returns the highest priority job
func (jq *JobQueue) Pop() Job {
	if len(jq.jobs) == 0 {
		return nil
	}

	job := jq.jobs[0]
	jq.jobs = jq.jobs[1:]
	return job
}

// Len returns the number of jobs in the queue
func (jq *JobQueue) Len() int {
	return len(jq.jobs)
}

// sortByPriority sorts jobs by priority (highest first)
func (jq *JobQueue) sortByPriority() {
	for i := len(jq.jobs) - 1; i > 0; i-- {
		if jq.jobs[i].Priority() > jq.jobs[i-1].Priority() {
			jq.jobs[i], jq.jobs[i-1] = jq.jobs[i-1], jq.jobs[i]
		} else {
			break
		}
	}
}
