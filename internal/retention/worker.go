package retention

import (
	"context"
	"log"
	"time"

	"github.com/elematte/observer/internal/db"
)

// Worker periodically purges expired webhook events from SQLite.
type Worker struct {
	store    *db.Store
	defaults db.RetentionSettings
	interval time.Duration
}

// NewWorker creates a background retention cleanup worker.
func NewWorker(store *db.Store, defaults db.RetentionSettings, interval time.Duration) *Worker {
	return &Worker{
		store:    store,
		defaults: defaults,
		interval: interval,
	}
}

// Run executes an immediate purge and then runs periodically until ctx is canceled.
func (w *Worker) Run(ctx context.Context) {
	w.RunOnce(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.RunOnce(ctx)
		}
	}
}

// RunOnce executes one retention cleanup pass and returns the number of deleted rows.
func (w *Worker) RunOnce(ctx context.Context) int64 {
	deleted, err := w.store.PurgeExpired(ctx, time.Now().UTC(), w.defaults)
	if err != nil {
		log.Printf("retention purge error: %v", err)
		return 0
	}
	if deleted > 0 {
		log.Printf("retention purge deleted %d expired event(s)", deleted)
	}
	return deleted
}
