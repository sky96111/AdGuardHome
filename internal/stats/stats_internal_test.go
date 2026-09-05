package stats

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// newTestStatsCtx returns StatsCtx initialised with given values.  All empty
// values from c will be replaced with defaults.
func newTestStatsCtx(tb testing.TB, c Config) (s *StatsCtx) {
	c.Logger = cmp.Or(c.Logger, testLogger)
	c.ConfigModifier = cmp.Or[agh.ConfigModifier](c.ConfigModifier, agh.EmptyConfigModifier{})
	c.HTTPReg = cmp.Or[aghhttp.Registrar](c.HTTPReg, aghhttp.EmptyRegistrar{})
	c.Filename = cmp.Or(c.Filename, filepath.Join(tb.TempDir(), "./stats.db"))
	c.Limit = cmp.Or(c.Limit, timeutil.Day)
	if c.ShouldCountClient == nil {
		c.ShouldCountClient = func([]string) bool { return true }
	}

	if c.UnitID == nil {
		c.UnitID = newUnitID
	}

	var err error
	s, err = New(context.TODO(), c)
	require.NoError(tb, err)

	return s
}

func TestStats_races(t *testing.T) {
	var currentRound atomic.Uint32
	s := newTestStatsCtx(t, Config{
		UnitID:  currentRound.Load,
		Enabled: true,
	})

	s.Start()
	startTime := time.Now()
	testutil.CleanupAndRequireSuccess(t, s.Close)

	writeFunc := func(start, fin *sync.WaitGroup, waitCh <-chan unit, i int) {
		e := &Entry{
			Domain:         fmt.Sprintf("example-%d.org", i),
			Client:         fmt.Sprintf("client_%d", i),
			Result:         Result(i)%(resultLast-1) + 1,
			ProcessingTime: time.Since(startTime),
		}

		start.Done()
		defer fin.Done()

		<-waitCh

		s.Update(e)
	}
	readFunc := func(start, fin *sync.WaitGroup, waitCh <-chan unit) {
		start.Done()
		defer fin.Done()

		<-waitCh

		_, _ = s.getData(context.TODO(), 24)
	}

	const (
		roundsNum uint32 = 3

		writersNum = 10
		readersNum = 5
	)

	for round := range roundsNum {
		currentRound.Store(round)

		startWG, finWG := &sync.WaitGroup{}, &sync.WaitGroup{}
		waitCh := make(chan unit)

		for i := range writersNum {
			startWG.Add(1)
			finWG.Add(1)
			go writeFunc(startWG, finWG, waitCh, i)
		}

		for range readersNum {
			startWG.Add(1)
			finWG.Add(1)
			go readFunc(startWG, finWG, waitCh)
		}

		startWG.Wait()
		close(waitCh)
		finWG.Wait()
	}
}

func TestStatsCtx_FillCollectedStats_daily(t *testing.T) {
	const (
		daysCount = 10

		timeUnits = "days"
	)

	s := newTestStatsCtx(t, Config{
		Limit:   time.Hour,
		Enabled: true,
	})

	testutil.CleanupAndRequireSuccess(t, s.Close)

	sum := make([][]uint64, resultLast)
	sum[RFiltered] = make([]uint64, daysCount)
	sum[RSafeBrowsing] = make([]uint64, daysCount)
	sum[RParental] = make([]uint64, daysCount)

	total := make([]uint64, daysCount)

	perBucket := make([][resultLast]uint64, 0, daysCount*24)

	for i := range daysCount * 24 {
		n := uint64(i)
		nResult := [resultLast]uint64{}
		nResult[RFiltered] = n
		nResult[RSafeBrowsing] = n
		nResult[RParental] = n

		day := i / 24
		sum[RFiltered][day] += n
		sum[RSafeBrowsing][day] += n
		sum[RParental][day] += n

		t := n * 3

		total[day] += t

		perBucket = append(perBucket, nResult)
	}

	data := &StatsResp{}

	// In this way we will not skip first hours.
	curID := uint32(daysCount * 24)

	s.fillCollectedStats(data, perBucket, curID)

	assert.Equal(t, timeUnits, data.TimeUnits)
	assert.Equal(t, sum[RFiltered], data.BlockedFiltering)
	assert.Equal(t, sum[RSafeBrowsing], data.ReplacedSafebrowsing)
	assert.Equal(t, sum[RParental], data.ReplacedParental)
	assert.Equal(t, total, data.DNSQueries)
}

// TestStatsCtx_getData_month checks that the statistics of a whole month of
// persisted buckets are loaded and aggregated properly.
func TestStatsCtx_getData_month(t *testing.T) {
	const hoursInMonth = 720

	s := newTestStatsCtx(t, Config{
		Limit:   timeutil.Day * 30,
		Enabled: true,
	})

	testutil.CleanupAndRequireSuccess(t, s.Close)

	st := s.store.Load()
	require.NotNil(t, st)

	ctx := context.Background()
	curID := newUnitID()

	// Persist a bucket for every hour of the month but the current one.
	for i := range hoursInMonth {
		id := curID - uint32(hoursInMonth) + uint32(i)
		udb := &unitDB{
			NResult:   []uint64{0, 1, 0, 0, 0, 0},
			NTotal:    1,
			TimeSumUs: 1000,
		}

		require.NoError(t, st.persistUnit(ctx, id, udb, true))
	}

	data, ok := s.getData(ctx, hoursInMonth)
	require.True(t, ok)
	require.NotNil(t, data)

	assert.Equal(t, timeUnitsDays, data.TimeUnits)
	assert.Equal(t, uint64(hoursInMonth-1), data.NumDNSQueries)
	assert.Len(t, data.DNSQueries, hoursInMonth/24)
}
