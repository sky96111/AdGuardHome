package querylog

import (
	"context"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// flushLogBuffer flushes the current buffer to the database and resets the
// buffer.  It does nothing in the memory-only mode.
func (l *queryLog) flushLogBuffer(ctx context.Context) (err error) {
	if l.store == nil {
		return nil
	}

	defer func() { err = errors.Annotate(err, "flushing log buffer: %w") }()

	l.flushLock.Lock()
	defer l.flushLock.Unlock()

	entries := l.drainBuffer()
	if len(entries) == 0 {
		return nil
	}

	start := time.Now()

	err = l.store.insertBatch(ctx, entries)
	if err != nil {
		return err
	}

	l.logger.DebugContext(
		ctx,
		"flushed entries",
		"count", len(entries),
		"elapsed", time.Since(start),
	)

	return nil
}

// drainBuffer returns all the buffered entries and resets the buffer.
func (l *queryLog) drainBuffer() (entries []*logEntry) {
	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.Range(func(entry *logEntry) (cont bool) {
		entries = append(entries, entry)

		return true
	})

	l.buffer.Clear()
	l.flushPending = false

	return entries
}

// periodicRetention periodically removes the entries that are older than the
// configured interval.  It returns when ctx is canceled.
func (l *queryLog) periodicRetention(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, l.logger)

	l.deleteOldEntries(ctx)

	// retentionCheckIvl is the period of time between checking the need for
	// deleting the old entries.  It's much smaller than any available
	// retention interval to increase time accuracy.
	const retentionCheckIvl = 1 * time.Hour

	retentions := time.NewTicker(retentionCheckIvl)
	defer retentions.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-retentions.C:
			l.deleteOldEntries(ctx)
		}
	}
}

// deleteOldEntries removes the log entries older than the configured interval
// from the database.  Unlike the previous file rotation, the actual retention
// time is equal to the interval.
func (l *queryLog) deleteOldEntries(ctx context.Context) {
	if l.store == nil {
		return
	}

	l.confMu.RLock()
	ivl := l.conf.RotationIvl
	l.confMu.RUnlock()

	cutoff := time.Now().Add(-ivl)

	n, err := l.store.deleteOlderThan(ctx, cutoff)
	if err != nil {
		l.logger.ErrorContext(ctx, "deleting old entries", slogutil.KeyError, err)

		return
	}

	if n > 0 {
		l.logger.DebugContext(ctx, "deleted old entries", "count", n)
	}
}

// clear removes all the entries, both buffered and stored.  It implements the
// POST /control/querylog_clear HTTP API.
func (l *queryLog) clear(ctx context.Context) {
	l.flushLock.Lock()
	defer l.flushLock.Unlock()

	l.bufferLock.Lock()
	l.buffer.Clear()
	l.flushPending = false
	l.bufferLock.Unlock()

	if l.store == nil {
		l.logger.DebugContext(ctx, "cleared")

		return
	}

	err := l.store.clear(ctx)
	if err != nil {
		l.logger.ErrorContext(ctx, "clearing log database", slogutil.KeyError, err)

		return
	}

	l.logger.DebugContext(ctx, "cleared")
}
