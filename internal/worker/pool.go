package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// NewPool creates a new worker pool with the given configuration
func NewPool(config *WorkerPoolConfig) Pool {
	if config == nil {
		config = DefaultConfig()
	}

	return &workerPool{
		config: config,
		jobs:   make(chan Job, config.QueueSize),
		status: StatusStopped,
		stats: Statistics{
			WorkerCount: config.NumWorkers,
			Status:      StatusStopped,
		},
	}
}

// Start implements the Pool interface
func (p *workerPool) Start(ctx context.Context, numWorkers int) error {
	p.statusMutex.Lock()
	defer p.statusMutex.Unlock()

	if p.status != StatusStopped {
		return fmt.Errorf("worker pool is already running or starting")
	}

	// Override config if numWorkers is specified
	if numWorkers > 0 {
		p.config.NumWorkers = numWorkers
	}

	p.setStatus(StatusStarting)

	// Create context for the worker pool
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wg = &sync.WaitGroup{}

	// Create and start workers
	p.workers = make([]*worker, p.config.NumWorkers)
	for i := 0; i < p.config.NumWorkers; i++ {
		worker := &worker{
			id:   i,
			pool: p,
			wg:   p.wg,
		}
		worker.ctx, worker.cancel = context.WithCancel(p.ctx)
		p.workers[i] = worker

		p.wg.Add(1)
		go worker.run()
	}

	p.setStatus(StatusRunning)
	p.updateStats(func(s *Statistics) {
		s.WorkerCount = p.config.NumWorkers
		s.Status = StatusRunning
	})

	log.WithField("worker_count", p.config.NumWorkers).Info("Worker pool started")
	return nil
}

// Submit implements the Pool interface
func (p *workerPool) Submit(job Job) error {
	p.statusMutex.RLock()
	defer p.statusMutex.RUnlock()

	if p.status != StatusRunning {
		return fmt.Errorf("worker pool is not running (status: %s)", p.status.String())
	}

	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.jobs <- job:
		p.updateStats(func(s *Statistics) {
			s.QueuedJobs++
		})
		return nil
	}
}

// Wait implements the Pool interface
func (p *workerPool) Wait(ctx context.Context) error {
	// Wait for all jobs to be submitted
	close(p.jobs)

	// Wait for workers to complete with context timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		log.Warn("Context cancelled while waiting for workers")
		p.cancel()
		return ctx.Err()
	case <-done:
		log.Info("All certificate processing workers completed")
		return nil
	}
}

// Shutdown implements the Pool interface
func (p *workerPool) Shutdown(ctx context.Context) error {
	p.statusMutex.Lock()
	defer p.statusMutex.Unlock()

	if p.status == StatusStopped || p.status == StatusStopping {
		return nil
	}

	p.setStatus(StatusStopping)

	// Cancel all workers
	if p.cancel != nil {
		p.cancel()
	}

	// Wait for workers to stop with timeout
	done := make(chan struct{})
	go func() {
		if p.wg != nil {
			p.wg.Wait()
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		log.Warn("Timeout while shutting down worker pool")
		return ctx.Err()
	case <-done:
		p.setStatus(StatusStopped)
		p.updateStats(func(s *Statistics) {
			s.Status = StatusStopped
			s.ActiveWorkers = 0
			s.QueuedJobs = 0
		})
		log.Info("Worker pool shut down successfully")
		return nil
	}
}

// Stats implements the Pool interface
func (p *workerPool) Stats() Statistics {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return p.stats
}

// run executes the worker loop
func (w *worker) run() {
	defer w.wg.Done()

	logger := log.WithField("worker_id", w.id)
	logger.Debug("Certificate worker started")

	for {
		select {
		case <-w.ctx.Done():
			logger.Info("Worker cancelled, stopping")
			return
		case job, ok := <-w.pool.jobs:
			if !ok {
				logger.Debug("Job channel closed, worker stopping")
				return
			}

			// Update active worker count
			w.pool.updateStats(func(s *Statistics) {
				s.ActiveWorkers++
				s.QueuedJobs--
			})

			// Process the job
			if err := job.Process(w.ctx); err != nil {
				logger.WithError(err).WithField("job_id", job.ID()).Error("Job processing failed")
				w.pool.updateStats(func(s *Statistics) {
					atomic.AddInt64(&s.FailedJobs, 1)
				})
			} else {
				w.pool.updateStats(func(s *Statistics) {
					atomic.AddInt64(&s.ProcessedJobs, 1)
				})
			}

			// Update active worker count
			w.pool.updateStats(func(s *Statistics) {
				s.ActiveWorkers--
			})
		}
	}
}

// setStatus updates the pool status (caller must hold statusMutex)
func (p *workerPool) setStatus(status PoolStatus) {
	p.status = status
}

// updateStats safely updates pool statistics
func (p *workerPool) updateStats(updateFn func(*Statistics)) {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()
	updateFn(&p.stats)
}

// ProcessDirectories is a convenience function that mimics the original behavior
// This provides backward compatibility while using the new worker pool architecture
func ProcessDirectories(ctx context.Context, directories []string, numWorkers int, processorFunc func(string, bool)) error {
	config := &WorkerPoolConfig{
		NumWorkers:    numWorkers,
		QueueSize:     len(directories),
		EnableMetrics: true,
	}

	pool := NewPool(config)

	// Start the worker pool
	if err := pool.Start(ctx, numWorkers); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	// Submit jobs for each directory
	for i, dir := range directories {
		job := &DirectoryJob{
			BaseJob:       NewBaseJob(fmt.Sprintf("dir-%d-%s", i, dir), JobTypeDirectory, 1),
			DirectoryPath: dir,
			ProcessorFunc: processorFunc,
		}

		if err := pool.Submit(job); err != nil {
			return fmt.Errorf("failed to submit job for directory %s: %w", dir, err)
		}
	}

	// Wait for all jobs to complete
	return pool.Wait(ctx)
}
