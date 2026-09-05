package stats

import (
	"context"
	"fmt"
	"testing"

	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/require"
)

// BenchmarkGetData measures the dashboard data preparation over 90 days of
// pre-aggregated statistics.
func BenchmarkGetData(b *testing.B) {
	s := newTestStatsCtx(b, Config{
		Limit:   timeutil.Day * 90,
		Enabled: true,
	})
	cleanupStatsCtx(b, s)

	ctx := context.Background()

	const hoursIn90Days = 90 * 24

	st := s.store.Load()
	require.NotNil(b, st)

	curID := newUnitID()

	// Persist a bucket for every hour but the current one, with the same
	// amount of data a busy home router could produce: a hundred per-hour
	// domain and client counters.
	for i := range hoursIn90Days {
		id := curID - hoursIn90Days + uint32(i)

		udb := &unitDB{
			NResult:   []uint64{800, 200, 20, 10, 5},
			NTotal:    1035,
			TimeSumUs: 1035 * 50_000,
		}
		for d := range maxDomains {
			udb.Domains = append(udb.Domains, countPair{
				Name:  fmt.Sprintf("domain%d.example.org", d),
				Count: uint64(1000 - d),
			})
		}
		for c := range maxClients {
			udb.Clients = append(udb.Clients, countPair{
				Name:  fmt.Sprintf("192.0.2.%d", c+1),
				Count: uint64(100 - c%20),
			})
		}
		udb.BlockedDomains = udb.Domains[:maxDomains/2]

		require.NoError(b, st.persistUnit(ctx, id, udb, true))
	}

	b.ResetTimer()

	for b.Loop() {
		data, ok := s.getData(ctx, hoursIn90Days)
		if !ok {
			b.Fatal("no data")
		}

		if data.NumDNSQueries == 0 {
			b.Fatal("no queries")
		}
	}
}
