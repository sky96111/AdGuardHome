package stats

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupStore closes st at the cleanup stage of tb.
func cleanupStore(tb testing.TB, st *store) {
	tb.Helper()

	tb.Cleanup(func() {
		require.NoError(tb, st.Close(context.Background()))
	})
}

// cleanupStatsCtx closes s at the cleanup stage of tb.
func cleanupStatsCtx(tb testing.TB, s *StatsCtx) {
	tb.Helper()

	tb.Cleanup(func() {
		require.NoError(tb, s.Close())
	})
}

// testUnitDB returns a unitDB with some data of every kind.
func testUnitDB() (udb *unitDB) {
	return &unitDB{
		NResult:        []uint64{1, 2, 3, 4, 5, 6},
		Domains:        []countPair{{Name: "example.org", Count: 2}},
		BlockedDomains: []countPair{{Name: "blocked.example.org", Count: 3}},
		Clients:        []countPair{{Name: "192.0.2.1", Count: 6}},
		UpstreamsResponses: []countPair{
			{Name: "https://dns.example.org", Count: 6},
		},
		UpstreamsTimeSum: []countPair{
			{Name: "https://dns.example.org", Count: 600},
		},
		NTotal:    21,
		TimeSumUs: 123456,
	}
}

func TestStore_SchemaVersion(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	var v int64
	err = st.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	require.NoError(t, err)
	assert.Equal(t, int64(statsSchemaVersion), v)
}

func TestStore_PersistLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	const id uint32 = 123456

	want := testUnitDB()
	err = st.persistUnit(ctx, id, want, true)
	require.NoError(t, err)

	got, err := st.loadUnit(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, want, got)

	// A missing bucket yields no data.
	got, err = st.loadUnit(ctx, id+1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestStore_ReplaceBucket(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	const id uint32 = 42

	err = st.persistUnit(ctx, id, testUnitDB(), true)
	require.NoError(t, err)

	// Persisting the same bucket again replaces the previous data instead of
	// adding to it, since the bucket contains a snapshot of the whole unit.
	want := &unitDB{
		NResult:   []uint64{0, 0, 0, 0, 0, 1},
		Domains:   []countPair{{Name: "other.example.org", Count: 1}},
		NTotal:    1,
		TimeSumUs: 100,
	}
	err = st.persistUnit(ctx, id, want, true)
	require.NoError(t, err)

	got, err := st.loadUnit(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, got)

	// The aggregated top counters must contain only the data of the latest
	// snapshot, not the sum of both.
	domains, err := st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, want.Domains, domains)

	blocked, err := st.loadTopDomains(ctx, maxDomains, true)
	require.NoError(t, err)
	assert.Empty(t, blocked)

	clients, err := st.loadTopClients(ctx, maxClients)
	require.NoError(t, err)
	assert.Equal(t, want.Clients, clients)

	responses, timeSums, err := st.loadTopUpstreams(ctx, maxUpstreams)
	require.NoError(t, err)
	assert.Equal(t, want.UpstreamsResponses, responses)
	assert.Equal(t, want.UpstreamsTimeSum, timeSums)
}

func TestStore_SnapshotCoveredBucket(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	const id uint32 = 42

	// Complete the hour, so that the bucket becomes covered by the top
	// counters.
	err = st.persistUnit(ctx, id, testUnitDB(), true)
	require.NoError(t, err)

	// A snapshot write for the same (covered) bucket.  It must keep the top
	// counters consistent with the rows by subtracting the previous
	// contribution and adding the new one.  This covers both erasing counts
	// and adding them.
	snap := &unitDB{
		NResult:   []uint64{0, 0, 0, 0, 0, 2},
		Domains:   []countPair{{Name: "other.example.org", Count: 2}},
		Clients:   []countPair{{Name: "192.0.2.2", Count: 2}},
		NTotal:    2,
		TimeSumUs: 200,
	}
	err = st.persistUnit(ctx, id, snap, false)
	require.NoError(t, err)

	got, err := st.loadUnit(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, snap, got)

	// The top counters must match the per-bucket rows exactly.
	domains, err := st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, snap.Domains, domains)

	blocked, err := st.loadTopDomains(ctx, maxDomains, true)
	require.NoError(t, err)
	assert.Empty(t, blocked)

	clients, err := st.loadTopClients(ctx, maxClients)
	require.NoError(t, err)
	assert.Equal(t, snap.Clients, clients)

	responses, timeSums, err := st.loadTopUpstreams(ctx, maxUpstreams)
	require.NoError(t, err)
	assert.Empty(t, responses)
	assert.Empty(t, timeSums)
}

func TestStore_DeleteBucketsBefore(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	const firstID uint32 = 100

	for id := uint32(95); id < 105; id++ {
		err = st.persistUnit(ctx, id, testUnitDB(), true)
		require.NoError(t, err)
	}

	err = st.deleteBucketsBefore(ctx, firstID)
	require.NoError(t, err)

	for id := uint32(95); id < 105; id++ {
		got, err := st.loadUnit(ctx, id)
		require.NoError(t, err)

		if id < firstID {
			assert.Nil(t, got, "bucket %d should be deleted", id)
		} else {
			assert.NotNil(t, got, "bucket %d should be kept", id)
		}
	}

	// The aggregated top counters must only contain the data of the kept
	// buckets: 5 buckets, each with a single domain counted 2 times.
	domains, err := st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, []countPair{{Name: "example.org", Count: 10}}, domains)

	blocked, err := st.loadTopDomains(ctx, maxDomains, true)
	require.NoError(t, err)
	assert.Equal(t, []countPair{{Name: "blocked.example.org", Count: 15}}, blocked)
}

func TestStore_LegacyBboltRejected(t *testing.T) {
	// The magic value of the bbolt meta page is stored in the native byte
	// order of the machine that created the file, so check both of them.
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		name := fmt.Sprintf("magic_%s", order)
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			filename := filepath.Join(t.TempDir(), "stats.db")

			// Write the legacy bbolt magic at the offset of the meta page
			// field, right after the page header.
			data := make([]byte, 64)
			order.PutUint32(data[16:], 0xED0CDAED)
			err := os.WriteFile(filename, data, 0o600)
			require.NoError(t, err)

			st, err := newStore(ctx, testLogger, filename)
			require.Error(t, err)
			assert.Nil(t, st)
			assert.ErrorIs(t, err, errLegacyDB)

			// The legacy file must be left untouched for the user to delete
			// manually.
			_, err = os.Stat(filename)
			require.NoError(t, err)
		})
	}
}

func TestStatsCtx_FlushTick(t *testing.T) {
	var curHour uint32 = 100
	s := newTestStatsCtx(t, Config{
		Enabled: true,
		UnitID:  func() (id uint32) { return curHour },
	})

	cleanupStatsCtx(t, s)

	// Add a couple of entries into the current unit.
	s.Update(&Entry{
		Client:         "192.0.2.1",
		Domain:         "example.org",
		Result:         RNotFiltered,
		ProcessingTime: time.Microsecond,
	})

	// A flush tick after the snapshot interval refreshes the snapshot of the
	// current unit.
	s.flushTick(context.Background(), time.Now().Add(time.Hour))

	st := s.store.Load()
	require.NotNil(t, st)

	udb, err := st.loadUnit(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, udb)
	assert.Equal(t, uint64(1), udb.NTotal)

	// A flush tick after the hour has passed persists the old unit and
	// replaces the current one with an empty unit of the new hour.
	curHour = 101
	s.flushTick(context.Background(), time.Now().Add(time.Hour))

	udb, err = st.loadUnit(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, udb)
	assert.Equal(t, uint64(1), udb.NTotal)

	udb, err = st.loadUnit(context.Background(), 101)
	require.NoError(t, err)
	assert.Nil(t, udb)

	s.currMu.RLock()
	assert.Equal(t, uint32(101), s.curr.id)
	assert.Equal(t, uint64(0), s.curr.nTotal)
	s.currMu.RUnlock()
}

func TestUnit_SerializeCaps(t *testing.T) {
	// The top lists must be capped the same way the previous storage capped
	// them.
	u := newUnit(1)
	for i := range 200 {
		u.add(&Entry{
			Client: fmt.Sprintf("client-%d", i),
			Domain: fmt.Sprintf("domain%d.example.org", i),
			Result: RNotFiltered,
		})
	}

	udb := u.serialize()
	assert.Len(t, udb.Domains, maxDomains)
	assert.Len(t, udb.Clients, maxClients)
	assert.Equal(t, uint64(200), udb.NTotal)
	assert.Equal(t, uint64(0), udb.TimeSumUs)
}

// runStatsCtx returns a StatsCtx using the given filename and unit ID,
// simulating a process run.  It doesn't close s; the caller is responsible for
// simulating the process exit.
func runStatsCtx(tb testing.TB, filename string, unitID func() uint32) (s *StatsCtx) {
	tb.Helper()

	return newTestStatsCtx(tb, Config{
		Enabled:  true,
		UnitID:   unitID,
		Filename: filename,
	})
}

func TestStatsCtx_RestartSameHourTopCounters(t *testing.T) {
	ctx := context.Background()

	var curHour uint32 = 100
	filename := filepath.Join(t.TempDir(), "stats.db")

	// The first "process": add an entry and snapshot the current unit, then
	// crash without closing the database.
	first := runStatsCtx(t, filename, func() uint32 { return curHour })
	first.Update(&Entry{
		Client: "192.0.2.1",
		Domain: "example.org",
		Result: RNotFiltered,
	})
	first.flushTick(ctx, time.Now().Add(time.Hour))

	first.store.Swap(nil)

	// The second "process" restarts within the same hour, adds another entry,
	// and rolls the unit over.
	second := runStatsCtx(t, filename, func() uint32 { return curHour })
	second.Update(&Entry{
		Client: "192.0.2.2",
		Domain: "example.org",
		Result: RNotFiltered,
	})

	curHour = 101
	second.flushTick(ctx, time.Now().Add(time.Hour))
	testutil.CleanupAndRequireSuccess(t, second.Close)

	st := second.store.Load()
	require.NotNil(t, st)

	udb, err := st.loadUnit(ctx, 100)
	require.NoError(t, err)
	require.NotNil(t, udb)
	assert.Equal(t, uint64(2), udb.NTotal)

	// The top counters must count the completed hour exactly once, even
	// though the bucket previously held a snapshot.
	domains, err := st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, []countPair{{Name: "example.org", Count: 2}}, domains)
}

func TestStatsCtx_OrphanBucketTopCounters(t *testing.T) {
	ctx := context.Background()

	var curHour uint32 = 100
	filename := filepath.Join(t.TempDir(), "stats.db")

	// The first "process": add an entry and snapshot the current unit, then
	// crash without closing the database.
	first := runStatsCtx(t, filename, func() uint32 { return curHour })
	first.Update(&Entry{
		Client: "192.0.2.1",
		Domain: "example.org",
		Result: RNotFiltered,
	})
	first.flushTick(ctx, time.Now().Add(time.Hour))

	first.store.Swap(nil)

	// The second "process" restarts two hours later, so the snapshot of hour
	// 100 becomes an orphan bucket, which the aggregated top counters must
	// adopt.
	curHour = 102
	second := runStatsCtx(t, filename, func() uint32 { return curHour })
	t.Cleanup(func() { require.NoError(t, second.Close()) })

	st := second.store.Load()
	require.NotNil(t, st)

	domains, err := st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, []countPair{{Name: "example.org", Count: 1}}, domains)

	// Add another entry for the same domain and roll the current unit over,
	// aging the orphan bucket out of the retention window while keeping the
	// completed hour 102 within it.
	second.Update(&Entry{
		Client: "192.0.2.2",
		Domain: "example.org",
		Result: RNotFiltered,
	})

	curHour = 124
	second.flushTick(ctx, time.Now().Add(time.Hour))

	// The top counters must only contain the data of the kept buckets: the
	// aged-out orphan bucket is subtracted, but the completed hour 102 isn't,
	// despite the orphan bucket never entering the top counters through the
	// completion write.
	domains, err = st.loadTopDomains(ctx, maxDomains, false)
	require.NoError(t, err)
	assert.Equal(t, []countPair{{Name: "example.org", Count: 1}}, domains)
}

func TestStore_InvalidResultCode(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	// A corrupted counter row must yield an error instead of a panic.
	_, err = st.db.ExecContext(ctx,
		"INSERT INTO stats_counters (bucket, result, count) VALUES (?, ?, ?)",
		1, int64(resultLast), 1,
	)
	require.NoError(t, err)

	_, err = st.loadUnit(ctx, 1)
	require.Error(t, err)

	_, err = st.loadCounters(ctx, 0, 2)
	require.Error(t, err)
}

func TestStore_NegativeCount(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "stats.db")

	st, err := newStore(ctx, testLogger, filename)
	require.NoError(t, err)
	cleanupStore(t, st)

	// A negative counter would wrap around when converted to uint64, so it
	// must be rejected on load.
	_, err = st.db.ExecContext(ctx,
		"INSERT INTO stats_counters (bucket, result, count) VALUES (?, ?, ?)",
		1, 0, int64(-1),
	)
	require.NoError(t, err)

	_, err = st.loadUnit(ctx, 1)
	require.Error(t, err)

	_, err = st.loadCounters(ctx, 0, 2)
	require.Error(t, err)
}
