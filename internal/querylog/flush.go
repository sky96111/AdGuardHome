package querylog

import (
	"context"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghsqldb"
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

	// The buffer has already been drained, so the persistence of the entries
	// must not be interrupted by the cancellation of the caller's context.
	// A search request, for example, flushes the buffer and may be canceled
	// by a disconnected client at any moment.  The database busy timeout
	// provides the bounded wait instead.
	insertCtx := context.WithoutCancel(ctx)

	err = l.store.insertBatch(insertCtx, entries)
	if err != nil {
		// Return the drained entries to the buffer, so that a transient
		// database failure, e.g. a busy timeout, doesn't lose the whole
		// batch.
		l.prependBuffer(entries)

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

// prependBuffer puts entries back into the buffer before the entries that were
// added while the flush was in progress, keeping the chronological order.  If
// the buffer capacity is exceeded, the oldest entries are dropped, but an
// error is logged to make the loss visible.
func (l *queryLog) prependBuffer(entries []*logEntry) {
	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	var added []*logEntry
	l.buffer.Range(func(e *logEntry) (cont bool) {
		added = append(added, e)

		return true
	})

	l.buffer.Clear()

	if dropped := len(entries) + len(added) - int(l.bufferSize); dropped > 0 {
		l.logger.Error(
			"requeueing entries: buffer overflow, dropping entries",
			"dropped", dropped,
			"buffer_size", l.bufferSize,
		)
	}

	for _, e := range entries {
		l.buffer.Push(e)
	}

	for _, e := range added {
		l.buffer.Push(e)
	}

	// Allow the next added entry to trigger a flush again.
	l.flushPending = false
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
	defer l.retentionWG.Done()
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

	// SQLite can recreate the WAL and SHM sidecar files with the process umask,
	// e.g. on a checkpoint, so reapply the restrictive permissions here, much
	// more often than on the next start.
	dbPath := filepath.Join(l.conf.BaseDir, querylogDBFileName)
	err = aghsqldb.ChmodFiles(dbPath)
	if err != nil {
		l.logger.ErrorContext(ctx, "setting db file permissions", slogutil.KeyError, err)
	}
}

// clear removes all the entries, both buffered and stored.
func (l *queryLog) clear(ctx context.Context) (err error) {
	l.flushLock.Lock()
	defer l.flushLock.Unlock()

	l.bufferLock.Lock()
	l.buffer.Clear()
	l.flushPending = false
	l.bufferLock.Unlock()

	if l.store == nil {
		l.logger.DebugContext(ctx, "cleared")

		return nil
	}

	err = l.store.clear(ctx)
	if err != nil {
		return errors.Annotate(err, "clearing log database: %w")
	}

	l.logger.DebugContext(ctx, "cleared")

	return nil
}
