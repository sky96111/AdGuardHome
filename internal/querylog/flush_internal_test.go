package querylog

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryLog_FlushLogBuffer_canceledContext makes sure that a canceled
// caller context, e.g. a disconnected search client, doesn't prevent the
// drained entries from being persisted.
func TestQueryLog_FlushLogBuffer_canceledContext(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)

	const entNum = 3
	for i := range entNum {
		addTestEntry(
			l,
			fmt.Sprintf("host%d.example.org", i),
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Cancel the context before flushing, like a disconnected client would.
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	require.NoError(t, l.flushLogBuffer(canceledCtx))

	params := newSearchParams()
	found, _, _, err := l.search(ctx, params)
	require.NoError(t, err)
	assert.Len(t, found, entNum)
}

// TestQueryLog_FlushFailureRequeue makes sure that the entries drained by a
// failed flush are returned to the buffer and can be persisted later.
func TestQueryLog_FlushFailureRequeue(t *testing.T) {
	dir := t.TempDir()
	l := newTestDBQueryLog(t, dir, nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	const entNum = 3
	for i := range entNum {
		addTestEntry(
			l,
			fmt.Sprintf("host%d.example.org", i),
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}

	// Force the flush to fail.
	require.NoError(t, l.store.db.Close())

	require.Error(t, l.flushLogBuffer(ctx))

	l.bufferLock.RLock()
	buffered := l.buffer.Len()
	l.bufferLock.RUnlock()
	assert.Equal(t, uint(entNum), buffered)

	// Open a fresh store for the same file and flush the requeued entries
	// again.
	st, err := newStore(ctx, testLogger, filepath.Join(dir, querylogDBFileName))
	require.NoError(t, err)
	l.store = st

	require.NoError(t, l.flushLogBuffer(ctx))

	params := newSearchParams()
	found, _, _, err := l.search(ctx, params)
	require.NoError(t, err)
	assert.Len(t, found, entNum)
}

// TestQueryLog_PrependBufferOrder makes sure that the requeued entries precede
// the entries added while the flush was in progress.
func TestQueryLog_PrependBufferOrder(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.MemSize = 4
	})

	old := []*logEntry{
		{QHost: "old1.example.org"},
		{QHost: "old2.example.org"},
	}

	// Simulate the entries added while the flush was in progress.
	l.bufferLock.Lock()
	l.buffer.Push(&logEntry{QHost: "new1.example.org"})
	l.buffer.Push(&logEntry{QHost: "new2.example.org"})
	l.bufferLock.Unlock()

	l.prependBuffer(old)

	var got []string
	l.bufferLock.RLock()
	l.buffer.Range(func(e *logEntry) (cont bool) {
		got = append(got, e.QHost)

		return true
	})
	l.bufferLock.RUnlock()

	assert.Equal(t, []string{
		"old1.example.org",
		"old2.example.org",
		"new1.example.org",
		"new2.example.org",
	}, got)
}

// TestQueryLog_ShutdownClosesStoreOnFlushFailure makes sure that the store is
// closed even when the final flush fails.
func TestQueryLog_ShutdownClosesStoreOnFlushFailure(t *testing.T) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	l, err := newQueryLog(ctx, Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	addTestEntry(l, "example.org", testAnswerIPv4, testClientIPv4, filtering.Rewritten)

	// Force the final flush to fail.
	require.NoError(t, l.store.db.Close())

	err = l.Shutdown(ctx)
	require.Error(t, err)

	l.store.stmtsMu.Lock()
	closed := l.store.closed
	l.store.stmtsMu.Unlock()
	assert.True(t, closed)
}

// TestQueryLog_ShutdownStopsRetention makes sure that Shutdown cancels and
// waits for the periodic-retention goroutine.  It doesn't start a web server,
// so the goroutine only waits for the context.
func TestQueryLog_ShutdownStopsRetention(t *testing.T) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	l, err := newQueryLog(ctx, Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: false,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	require.NoError(t, l.Start(ctx))

	require.NoError(t, l.Shutdown(ctx))

	// The retention goroutine must have exited before Shutdown returned, so
	// the context must be canceled.
	assert.ErrorIs(t, l.flushCtx.Err(), context.Canceled)
}
