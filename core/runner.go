package core

import (
	"sync"
)

type Runner struct {
	threads int
	wg      sync.WaitGroup
	queue   chan func()
}

func NewRunner(threads int) *Runner {
	if threads <= 0 {
		threads = 25
	}

	r := &Runner{
		threads: threads,
		queue:   make(chan func(), threads*2),
	}

	// Start worker pool
	for i := 0; i < threads; i++ {
		r.wg.Add(1)
		go r.worker()
	}

	return r
}

func (r *Runner) worker() {
	defer r.wg.Done()
	for task := range r.queue {
		task()
	}
}

func (r *Runner) Submit(task func()) {
	r.queue <- task
}

func (r *Runner) Wait() {
	close(r.queue)
	r.wg.Wait()
}

