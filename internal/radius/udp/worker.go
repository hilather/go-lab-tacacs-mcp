package udp

import (
	"context"
	"time"
)

func (l *Listener) worker() {
	defer l.workerWG.Done()
	for item := range l.queue {
		l.queued.Add(-1)
		l.handleItem(item)
	}
}

func (l *Listener) handleItem(item workItem) {
	l.inflight.Add(1)
	defer func() {
		l.inflight.Add(-1)
		wipe(item.buf)
		if rec := recover(); rec != nil {
			l.opts.Logger.Error("radius worker panic", "listener", l.id)
			l.setError("internal")
		}
	}()
	deadline := l.opts.Settings.WorkerDeadline
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	l.process(ctx, item.buf, item.src)
}
