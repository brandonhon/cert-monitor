package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testJob is a simple test implementation of the Job interface
type testJob struct {
	id          string
	priority    int
	processFunc func(ctx context.Context) error
}

func (j *testJob) ID() string {
	return j.id
}

func (j *testJob) Priority() int {
	return j.priority
}

func (j *testJob) Process(ctx context.Context) error {
	if j.processFunc != nil {
		return j.processFunc(ctx)
	}
	return nil
}

// TestPool tests basic worker pool functionality
func TestPool(t *testing.T) {
	config := &WorkerPoolConfig{
		NumWorkers:    3,
		QueueSize:     10,
		EnableMetrics: true,
	}

	pool := NewPool(config)

	// Test initial status
	stats := pool.Stats()
	if stats.Status != StatusStopped {
		t.Errorf("Expected status %s, got %s", StatusStopped, stats.Status)
	}

	// Start the pool
	ctx := context.Background()
	if err := pool.Start(ctx, 0); err != nil {
		t.Fatalf("Failed to start pool: %v", err)
	}

	// Test running status
	stats = pool.Stats()
	if stats.Status != StatusRunning {
		t.Errorf("Expected status %s, got %s", StatusRunning, stats.Status)
	}
	if stats.WorkerCount != 3 {
		t.Errorf("Expected 3 workers, got %d", stats.WorkerCount)
	}

	// Test job submission
	var processed int32
	job := &testJob{
		id:       "test-1",
		priority: 1,
		processFunc: func(ctx context.Context) error {
			atomic.AddInt32(&processed, 1)
			return nil
		},
	}

	if err := pool.Submit(job); err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	// Wait for completion
	if err := pool.Wait(ctx); err != nil {
		t.Fatalf("Failed to wait for jobs: %v", err)
	}

	if atomic.LoadInt32(&processed) != 1 {
		t.Errorf("Expected 1 processed job, got %d", atomic.LoadInt32(&processed))
	}

	// Test shutdown
	if err := pool.Shutdown(ctx); err != nil {
		t.Fatalf("Failed to shutdown pool: %v", err)
	}

	stats = pool.Stats()
	if stats.Status != StatusStopped {
		t.Errorf("Expected status %s after shutdown, got %s", StatusStopped, stats.Status)
	}
}

// TestPoolConcurrency tests concurrent job processing
func TestPoolConcurrency(t *testing.T) {
	config := &WorkerPoolConfig{
		NumWorkers:    5,
		QueueSize:     100,
		EnableMetrics: true,
	}

	pool := NewPool(config)
	ctx := context.Background()

	if err := pool.Start(ctx, 0); err != nil {
		t.Fatalf("Failed to start pool: %v", err)
	}
	defer func() {
		if err := pool.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown pool: %v", err)
		}
	}()

	const numJobs = 50
	var processed int32
	var mu sync.Mutex
	processedJobs := make(map[string]bool)

	// Submit multiple jobs
	for i := 0; i < numJobs; i++ {
		job := &testJob{
			id:       fmt.Sprintf("job-%d", i),
			priority: i % 3, // Mix priorities
			processFunc: func(ctx context.Context) error {
				time.Sleep(10 * time.Millisecond) // Simulate work
				atomic.AddInt32(&processed, 1)
				return nil
			},
		}

		// Track job for uniqueness verification
		mu.Lock()
		processedJobs[job.ID()] = false
		mu.Unlock()

		if err := pool.Submit(job); err != nil {
			t.Fatalf("Failed to submit job %d: %v", i, err)
		}
	}

	// Wait for completion
	if err := pool.Wait(ctx); err != nil {
		t.Fatalf("Failed to wait for jobs: %v", err)
	}

	if atomic.LoadInt32(&processed) != numJobs {
		t.Errorf("Expected %d processed jobs, got %d", numJobs, atomic.LoadInt32(&processed))
	}

	// Verify statistics
	stats := pool.Stats()
	if stats.ProcessedJobs != int64(numJobs) {
		t.Errorf("Expected %d processed jobs in stats, got %d", numJobs, stats.ProcessedJobs)
	}
}

// TestDirectoryJob tests directory job functionality
func TestDirectoryJob(t *testing.T) {
	var processedPath string
	var processedRecursive bool

	processorFunc := func(path string, recursive bool) {
		processedPath = path
		processedRecursive = recursive
	}

	job := NewDirectoryJob("/test/path", processorFunc, 1)

	if job.ID() == "" {
		t.Error("Directory job should have a non-empty ID")
	}

	if job.Priority() != 1 {
		t.Errorf("Expected priority 1, got %d", job.Priority())
	}

	ctx := context.Background()
	if err := job.Process(ctx); err != nil {
		t.Fatalf("Failed to process directory job: %v", err)
	}

	expectedPath := "/test/path"
	if processedPath != expectedPath {
		t.Errorf("Expected processed path %s, got %s", expectedPath, processedPath)
	}

	if processedRecursive != false {
		t.Errorf("Expected recursive=false, got %t", processedRecursive)
	}
}

// TestCertificateJob tests certificate job functionality
func TestCertificateJob(t *testing.T) {
	var processedPath string

	processorFunc := func(path string) error {
		processedPath = path
		return nil
	}

	certPath := "/test/cert.pem"
	job := NewCertificateJob(certPath, processorFunc, 2)

	if job.ID() == "" {
		t.Error("Certificate job should have a non-empty ID")
	}

	if job.Priority() != 2 {
		t.Errorf("Expected priority 2, got %d", job.Priority())
	}

	ctx := context.Background()
	if err := job.Process(ctx); err != nil {
		t.Fatalf("Failed to process certificate job: %v", err)
	}

	if processedPath != certPath {
		t.Errorf("Expected processed path %s, got %s", certPath, processedPath)
	}
}

// TestMaintenanceJob tests maintenance job functionality
func TestMaintenanceJob(t *testing.T) {
	var executed bool

	taskFunc := func(ctx context.Context) error {
		executed = true
		return nil
	}

	job := NewMaintenanceJob("test-maintenance", taskFunc, 3)

	if job.ID() == "" {
		t.Error("Maintenance job should have a non-empty ID")
	}

	if job.Priority() != 3 {
		t.Errorf("Expected priority 3, got %d", job.Priority())
	}

	ctx := context.Background()
	if err := job.Process(ctx); err != nil {
		t.Fatalf("Failed to process maintenance job: %v", err)
	}

	if !executed {
		t.Error("Maintenance task should have been executed")
	}
}

// TestJobQueue tests priority queue functionality
func TestJobQueue(t *testing.T) {
	queue := NewJobQueue(10)

	// Add jobs with different priorities
	jobs := []*testJob{
		{id: "low", priority: 1},
		{id: "high", priority: 5},
		{id: "medium", priority: 3},
	}

	for _, job := range jobs {
		if !queue.Push(job) {
			t.Fatalf("Failed to push job %s", job.ID())
		}
	}

	if queue.Len() != 3 {
		t.Errorf("Expected queue length 3, got %d", queue.Len())
	}

	// Pop jobs - should come out in priority order (highest first)
	expectedOrder := []string{"high", "medium", "low"}
	for i, expectedID := range expectedOrder {
		job := queue.Pop()
		if job == nil {
			t.Fatalf("Expected job at position %d, got nil", i)
		}
		if job.ID() != expectedID {
			t.Errorf("Expected job ID %s at position %d, got %s", expectedID, i, job.ID())
		}
	}

	if queue.Len() != 0 {
		t.Errorf("Expected empty queue, got length %d", queue.Len())
	}
}

// TestProcessDirectories tests the convenience function
func TestProcessDirectories(t *testing.T) {
	var processedDirs []string
	var mu sync.Mutex

	processorFunc := func(dir string, recursive bool) {
		mu.Lock()
		processedDirs = append(processedDirs, dir)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond) // Simulate work
	}

	directories := []string{"/dir1", "/dir2", "/dir3"}
	ctx := context.Background()

	err := ProcessDirectories(ctx, directories, 2, processorFunc)
	if err != nil {
		t.Fatalf("ProcessDirectories failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(processedDirs) != len(directories) {
		t.Errorf("Expected %d processed directories, got %d", len(directories), len(processedDirs))
	}

	// Verify all directories were processed (order may vary due to concurrency)
	processed := make(map[string]bool)
	for _, dir := range processedDirs {
		processed[dir] = true
	}

	for _, expectedDir := range directories {
		if !processed[expectedDir] {
			t.Errorf("Directory %s was not processed", expectedDir)
		}
	}
}

// TestPoolErrorHandling tests error handling and recovery
func TestPoolErrorHandling(t *testing.T) {
	config := &WorkerPoolConfig{
		NumWorkers:    2,
		QueueSize:     10,
		EnableMetrics: true,
	}

	pool := NewPool(config)
	ctx := context.Background()

	if err := pool.Start(ctx, 0); err != nil {
		t.Fatalf("Failed to start pool: %v", err)
	}
	defer func() {
		if err := pool.Shutdown(ctx); err != nil {
			t.Errorf("Failed to shutdown pool: %v", err)
		}
	}()

	// Submit jobs that will fail
	failingJob := &testJob{
		id:       "failing-job",
		priority: 1,
		processFunc: func(ctx context.Context) error {
			return fmt.Errorf("intentional test error")
		},
	}

	successJob := &testJob{
		id:       "success-job",
		priority: 1,
		processFunc: func(ctx context.Context) error {
			return nil
		},
	}

	if err := pool.Submit(failingJob); err != nil {
		t.Fatalf("Failed to submit failing job: %v", err)
	}

	if err := pool.Submit(successJob); err != nil {
		t.Fatalf("Failed to submit success job: %v", err)
	}

	// Wait for completion
	if err := pool.Wait(ctx); err != nil {
		t.Fatalf("Failed to wait for jobs: %v", err)
	}

	// Check statistics
	stats := pool.Stats()
	if stats.FailedJobs != 1 {
		t.Errorf("Expected 1 failed job, got %d", stats.FailedJobs)
	}
	if stats.ProcessedJobs != 1 {
		t.Errorf("Expected 1 successful job, got %d", stats.ProcessedJobs)
	}
}

// TestPoolContextCancellation tests context cancellation handling
func TestPoolContextCancellation(t *testing.T) {
	config := &WorkerPoolConfig{
		NumWorkers:    2,
		QueueSize:     10,
		EnableMetrics: true,
	}

	pool := NewPool(config)
	ctx, cancel := context.WithCancel(context.Background())

	if err := pool.Start(ctx, 0); err != nil {
		t.Fatalf("Failed to start pool: %v", err)
	}

	// Submit a long-running job
	longJob := &testJob{
		id:       "long-job",
		priority: 1,
		processFunc: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return nil
			}
		},
	}

	if err := pool.Submit(longJob); err != nil {
		t.Fatalf("Failed to submit long job: %v", err)
	}

	// Cancel context after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Wait should return with context cancellation
	err := pool.Wait(ctx)
	if err == nil {
		t.Error("Expected context cancellation error")
	}

	// Shutdown should still work
	shutdownCtx := context.Background()
	if err := pool.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Failed to shutdown after cancellation: %v", err)
	}
}

// TestJobRetryLogic tests job retry functionality
func TestJobRetryLogic(t *testing.T) {
	baseJob := NewBaseJob("test-retry", JobTypeDirectory, 1)

	// Test initial state
	if baseJob.Attempts() != 0 {
		t.Errorf("Expected 0 initial attempts, got %d", baseJob.Attempts())
	}

	if !baseJob.ShouldRetry() {
		t.Error("Job should be retryable initially")
	}

	// Test incrementing attempts
	for i := 1; i <= 3; i++ {
		attempts := baseJob.IncrementAttempts()
		if attempts != int32(i) {
			t.Errorf("Expected %d attempts, got %d", i, attempts)
		}
	}

	// After 3 attempts, should not retry
	if baseJob.ShouldRetry() {
		t.Error("Job should not be retryable after max attempts")
	}
}

// TestJobTiming tests job timing functionality
func TestJobTiming(t *testing.T) {
	baseJob := NewBaseJob("test-timing", JobTypeDirectory, 1)

	// Test initial state
	if baseJob.ProcessingDuration() != 0 {
		t.Errorf("Expected 0 processing duration initially, got %v", baseJob.ProcessingDuration())
	}

	// Set start time
	baseJob.SetStartTime()
	time.Sleep(10 * time.Millisecond)

	// Set completed time
	baseJob.SetCompletedTime()

	duration := baseJob.ProcessingDuration()
	if duration <= 0 {
		t.Errorf("Expected positive processing duration, got %v", duration)
	}

	if duration < 10*time.Millisecond {
		t.Errorf("Expected duration >= 10ms, got %v", duration)
	}
}

// TestPoolShutdownGracefully tests graceful shutdown
func TestPoolShutdownGracefully(t *testing.T) {
	config := &WorkerPoolConfig{
		NumWorkers:    3,
		QueueSize:     10,
		EnableMetrics: true,
	}

	pool := NewPool(config)
	ctx := context.Background()

	if err := pool.Start(ctx, 0); err != nil {
		t.Fatalf("Failed to start pool: %v", err)
	}

	// Submit some quick jobs
	for i := 0; i < 5; i++ {
		job := &testJob{
			id:       fmt.Sprintf("quick-job-%d", i),
			priority: 1,
			processFunc: func(ctx context.Context) error {
				time.Sleep(50 * time.Millisecond)
				return nil
			},
		}

		if err := pool.Submit(job); err != nil {
			t.Fatalf("Failed to submit job %d: %v", i, err)
		}
	}

	// Shutdown should wait for jobs to complete
	start := time.Now()
	if err := pool.Shutdown(ctx); err != nil {
		t.Fatalf("Failed to shutdown pool: %v", err)
	}
	duration := time.Since(start)

	// Should take at least some time to process jobs
	if duration < 50*time.Millisecond {
		t.Errorf("Shutdown too fast: %v (expected >= 50ms)", duration)
	}

	// Pool should be stopped
	stats := pool.Stats()
	if stats.Status != StatusStopped {
		t.Errorf("Expected pool status %s, got %s", StatusStopped, stats.Status)
	}
}

// TestJobQueueCapacity tests job queue capacity limits
func TestJobQueueCapacity(t *testing.T) {
	capacity := 3
	queue := NewJobQueue(capacity)

	// Fill queue to capacity
	for i := 0; i < capacity; i++ {
		job := &testJob{id: fmt.Sprintf("job-%d", i), priority: 1}
		if !queue.Push(job) {
			t.Fatalf("Failed to push job %d to queue", i)
		}
	}

	// Should reject additional jobs
	overflowJob := &testJob{id: "overflow", priority: 1}
	if queue.Push(overflowJob) {
		t.Error("Queue should reject jobs when at capacity")
	}

	// Pop one job, should have space again
	queue.Pop()

	if !queue.Push(overflowJob) {
		t.Error("Queue should accept jobs after popping")
	}
}

// TestSanitizeForID tests ID sanitization
func TestSanitizeForID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/path/to/file", "_path_to_file"},
		{"C:\\Windows\\Path", "C__Windows_Path"},
		{"file with spaces", "file_with_spaces"},
		{"file:with:colons", "file_with_colons"},
		{"very-long-file-name-that-exceeds-fifty-characters-limit", "very-long-file-name-that-exceeds-fifty-characters-"},
	}

	for _, test := range tests {
		result := sanitizeForID(test.input)
		if result != test.expected {
			t.Errorf("sanitizeForID(%q) = %q, expected %q", test.input, result, test.expected)
		}

		// Verify length constraint
		if len(result) > 50 {
			t.Errorf("sanitizeForID(%q) result length %d exceeds 50 characters", test.input, len(result))
		}
	}
}

// TestPoolStatusString tests status string representation
func TestPoolStatusString(t *testing.T) {
	tests := []struct {
		status   PoolStatus
		expected string
	}{
		{StatusStopped, "stopped"},
		{StatusStarting, "starting"},
		{StatusRunning, "running"},
		{StatusStopping, "stopping"},
		{PoolStatus(99), "unknown"},
	}

	for _, test := range tests {
		result := test.status.String()
		if result != test.expected {
			t.Errorf("PoolStatus(%d).String() = %q, expected %q", test.status, result, test.expected)
		}
	}
}

// TestDefaultConfig tests default configuration
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.NumWorkers != 4 {
		t.Errorf("Expected default NumWorkers=4, got %d", config.NumWorkers)
	}

	if config.QueueSize != 100 {
		t.Errorf("Expected default QueueSize=100, got %d", config.QueueSize)
	}

	if !config.EnableMetrics {
		t.Error("Expected default EnableMetrics=true")
	}
}

// Benchmark tests
func BenchmarkPoolSubmit(b *testing.B) {
	config := &WorkerPoolConfig{
		NumWorkers:    4,
		QueueSize:     1000,
		EnableMetrics: false, // Disable metrics for pure performance test
	}

	pool := NewPool(config)
	ctx := context.Background()

	if err := pool.Start(ctx, 0); err != nil {
		b.Fatalf("Failed to start pool: %v", err)
	}
	defer func() {
		if err := pool.Shutdown(ctx); err != nil {
			b.Errorf("Failed to shutdown pool: %v", err)
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		job := &testJob{
			id:       fmt.Sprintf("bench-job-%d", i),
			priority: 1,
			processFunc: func(ctx context.Context) error {
				return nil
			},
		}

		if err := pool.Submit(job); err != nil {
			b.Fatalf("Failed to submit job: %v", err)
		}
	}
}

func BenchmarkJobCreation(b *testing.B) {
	processorFunc := func(string, bool) {}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = NewDirectoryJob(fmt.Sprintf("/path/to/dir%d", i), processorFunc, 1)
	}
}

func BenchmarkJobQueueOperations(b *testing.B) {
	queue := NewJobQueue(1000)

	// Pre-fill with some jobs
	for i := 0; i < 500; i++ {
		job := &testJob{id: fmt.Sprintf("job-%d", i), priority: i % 10}
		queue.Push(job)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			// Push operation
			job := &testJob{id: fmt.Sprintf("bench-job-%d", i), priority: i % 10}
			queue.Push(job)
		} else {
			// Pop operation
			queue.Pop()
		}
	}
}
