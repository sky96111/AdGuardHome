package stats

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
)

const (
	// maxDomains is the max number of top domains to return.
	maxDomains = 100

	// maxClients is the max number of top clients to return.
	maxClients = 100

	// maxUpstreams is the max number of top upstreams to return.
	maxUpstreams = 100
)

// UnitIDGenFunc is the signature of a function that generates a unique ID for
// the statistics unit.
type UnitIDGenFunc func() (id uint32)

// Supported values of [StatsResp.TimeUnits].
const (
	timeUnitsHours = "hours"
	timeUnitsDays  = "days"
)

// Result is the resulting code of processing the DNS request.
type Result int

// Supported Result values.
//
// TODO(e.burkov):  Think about better naming.
const (
	RNotFiltered Result = iota + 1
	RFiltered
	RSafeBrowsing
	RSafeSearch
	RParental

	resultLast = RParental + 1
)

// Entry is a statistics data entry.
type Entry struct {
	// Clients is the client's primary ID.
	//
	// TODO(a.garipov): Make this a {net.IP, string} enum?
	Client string

	// Domain is the domain name requested.
	Domain string

	// UpstreamStats contains the DNS query statistics for both the upstream and
	// fallback DNS servers.  Don't modify items in the slice.
	UpstreamStats []*proxy.UpstreamStatistics

	// Result is the result of processing the request.
	Result Result

	// ProcessingTime is the duration of the request processing from the start
	// of the request including timeouts.
	ProcessingTime time.Duration
}

// validate returns an error if entry is not valid.
func (e *Entry) validate() (err error) {
	switch {
	case e.Result == 0:
		return errors.Error("result code is not set")
	case e.Result >= resultLast:
		return fmt.Errorf("unknown result code %d", e.Result)
	case e.Domain == "":
		return errors.Error("domain is empty")
	case e.Client == "":
		return errors.Error("client is empty")
	default:
		return nil
	}
}

// unit collects the statistics data for a specific period of time.
type unit struct {
	// domains stores the number of requests for each domain.
	domains map[string]uint64

	// blockedDomains stores the number of requests for each domain that has
	// been blocked.
	blockedDomains map[string]uint64

	// clients stores the number of requests from each client.
	clients map[string]uint64

	// upstreamsResponses stores the number of responses from each upstream.
	upstreamsResponses map[string]uint64

	// upstreamsTimeSum stores the sum of durations of successful queries in
	// microseconds to each upstream.
	upstreamsTimeSum map[string]uint64

	// nResult stores the number of requests grouped by it's result.
	nResult []uint64

	// id is the unique unit's identifier.  It's set to an absolute hour number
	// since the beginning of UNIX time by the default ID generating function.
	//
	// Must not be rewritten after creating to be accessed concurrently without
	// using mu.
	id uint32

	// nTotal stores the total number of requests.
	nTotal uint64

	// timeSum stores the sum of processing time in microseconds of each request
	// written by the unit.
	timeSum uint64
}

// newUnit allocates the new *unit.
func newUnit(id uint32) (u *unit) {
	return &unit{
		domains:            map[string]uint64{},
		blockedDomains:     map[string]uint64{},
		clients:            map[string]uint64{},
		upstreamsResponses: map[string]uint64{},
		upstreamsTimeSum:   map[string]uint64{},
		nResult:            make([]uint64, resultLast),
		id:                 id,
	}
}

// countPair is a single name-number pair used to store the per-name counters.
type countPair struct {
	Name  string
	Count uint64
}

// unitDB is the structure for serializing statistics data into the database
// and aggregating it back.  The top lists are capped by the max* constants at
// the serialization time, so the data beyond those lists is discarded, just
// like in the previous storage.
type unitDB struct {
	// NResult is the number of requests by the result's kind.
	NResult []uint64

	// Domains is the number of requests for each domain name.
	Domains []countPair

	// BlockedDomains is the number of requests blocked for each domain name.
	BlockedDomains []countPair

	// Clients is the number of requests from each client.
	Clients []countPair

	// UpstreamsResponses is the number of responses from each upstream.
	UpstreamsResponses []countPair

	// UpstreamsTimeSum is the sum of processing time in microseconds of
	// responses from each upstream.
	UpstreamsTimeSum []countPair

	// NTotal is the total number of requests.
	NTotal uint64

	// TimeSumUs is the sum of processing times in microseconds of all the
	// requests in the unit.
	TimeSumUs uint64
}

// newUnitID is the default UnitIDGenFunc that generates the unique id hourly.
func newUnitID() (id uint32) {
	const secsInHour = int64(time.Hour / time.Second)

	return uint32(time.Now().Unix() / secsInHour)
}

// compareCount used to sort countPair by Count in descending order.
func (a countPair) compareCount(b countPair) (res int) {
	switch x, y := a.Count, b.Count; {
	case x > y:
		return -1
	case x < y:
		return +1
	default:
		return 0
	}
}

func convertMapToSlice(m map[string]uint64, maxVal int) (s []countPair) {
	s = make([]countPair, 0, len(m))
	for k, v := range m {
		s = append(s, countPair{Name: k, Count: v})
	}

	slices.SortFunc(s, countPair.compareCount)

	return s[:min(maxVal, len(s))]
}

func convertSliceToMap(a []countPair) (m map[string]uint64) {
	m = map[string]uint64{}
	for _, it := range a {
		m[it.Name] = it.Count
	}

	return m
}

// serialize converts u to the *unitDB.  It's safe for concurrent use.  u must
// not be nil.  The per-name counters beyond the top max* lists are discarded,
// which is the same behavior the previous storage had.
func (u *unit) serialize() (udb *unitDB) {
	return &unitDB{
		NTotal:             u.nTotal,
		NResult:            append([]uint64{}, u.nResult...),
		Domains:            convertMapToSlice(u.domains, maxDomains),
		BlockedDomains:     convertMapToSlice(u.blockedDomains, maxDomains),
		Clients:            convertMapToSlice(u.clients, maxClients),
		UpstreamsResponses: convertMapToSlice(u.upstreamsResponses, maxUpstreams),
		UpstreamsTimeSum:   convertMapToSlice(u.upstreamsTimeSum, maxUpstreams),
		TimeSumUs:          u.timeSum,
	}
}

// deserialize assigns the appropriate values from udb to u.  u must not be nil.
// It's safe for concurrent use.  udb may be nil, in which case u isn't
// changed.
func (u *unit) deserialize(udb *unitDB) {
	if udb == nil {
		return
	}

	u.nTotal = udb.NTotal
	u.nResult = make([]uint64, resultLast)
	copy(u.nResult, udb.NResult)
	u.domains = convertSliceToMap(udb.Domains)
	u.blockedDomains = convertSliceToMap(udb.BlockedDomains)
	u.clients = convertSliceToMap(udb.Clients)
	u.upstreamsResponses = convertSliceToMap(udb.UpstreamsResponses)
	u.upstreamsTimeSum = convertSliceToMap(udb.UpstreamsTimeSum)
	u.timeSum = udb.TimeSumUs
}

// add adds new data to u.  It's safe for concurrent use.
func (u *unit) add(e *Entry) {
	u.nResult[e.Result]++
	if e.Result == RNotFiltered {
		u.domains[e.Domain]++
	} else {
		u.blockedDomains[e.Domain]++
	}

	u.clients[e.Client]++
	pt := uint64(e.ProcessingTime.Microseconds())
	u.timeSum += pt
	u.nTotal++

	for _, s := range e.UpstreamStats {
		if s.IsCached || s.Error != nil {
			continue
		}

		addr := s.Address
		u.upstreamsResponses[addr]++
		u.upstreamsTimeSum[addr] += uint64(s.QueryDuration.Microseconds())
	}
}

func convertTopSlice(a []countPair) (m []map[string]uint64) {
	m = make([]map[string]uint64, 0, len(a))
	for _, it := range a {
		m = append(m, map[string]uint64{it.Name: it.Count})
	}

	return m
}

// pairsGetter is a signature for topsCollector argument.
type pairsGetter func(u *unitDB) (pairs []countPair)

// topsCollector collects statistics about highest values from the given *unitDB
// slice using pg to retrieve data.
func topsCollector(units []*unitDB, max int, ignored *aghnet.IgnoreEngine, pg pairsGetter) []map[string]uint64 {
	m := map[string]uint64{}
	for _, u := range units {
		for _, cp := range pg(u) {
			if !ignored.Has(cp.Name) {
				m[cp.Name] += cp.Count
			}
		}
	}
	a2 := convertMapToSlice(m, max)

	return convertTopSlice(a2)
}

// getData returns the statistics data using the following algorithm:
//
//  1. Load the pre-aggregated statistics for the buckets in the
//     [curID - limit + 1, curID) range from the database, where curID is the
//     current unit's ID.  Missing buckets are treated as empty.  Merge in the
//     current unit's data.
//
//  2. Prepare an output object, including per time unit counters (DNS queries
//     per time-unit, blocked queries per time unit, etc.).  If the time unit
//     is hour, just add the per-bucket values to the slice; otherwise, the
//     time unit is day, so aggregate the per-hour data into days.
//
//     To get the top counters (queries per domain, queries per blocked
//     domain, etc.), the database returns the top pairs of the whole range,
//     which are then merged with the current unit's data.
func (s *StatsCtx) getData(ctx context.Context, limit uint32) (resp *StatsResp, ok bool) {
	if limit == 0 {
		return &StatsResp{
			TimeUnits: "days",

			TopBlocked:            []topAddrs{},
			TopClients:            []topAddrs{},
			TopQueried:            []topAddrs{},
			TopUpstreamsResponses: []topAddrs{},
			TopUpstreamsAvgTime:   []topAddrsFloat{},

			BlockedFiltering:     []uint64{},
			DNSQueries:           []uint64{},
			ReplacedParental:     []uint64{},
			ReplacedSafebrowsing: []uint64{},
		}, true
	}

	dbAgg, perBucketMap, dbTimeSumUs, curSnap, curID, ok := s.loadUnits(ctx, limit)
	if !ok {
		return &StatsResp{}, false
	}

	// Collect the per-bucket counters into an ordered series, merging the
	// current unit's data into its own bucket.
	firstID := curID - limit + 1
	perBucket := make([][resultLast]uint64, limit)
	for bucket, nResult := range perBucketMap {
		if bucket < firstID || bucket >= curID {
			// Should not happen.
			continue
		}

		copy(perBucket[bucket-firstID][:], nResult)
	}

	if curSnap != nil {
		last := &perBucket[limit-1]
		for r, count := range curSnap.NResult {
			last[r] += count
		}

		dbTimeSumUs += curSnap.TimeSumUs
	}

	return s.dataFromAggregates(dbAgg, perBucket, dbTimeSumUs, curSnap, curID), true
}

// dataFromAggregates collects and returns the statistics data.  perBucket
// contains the per-bucket result counters of the whole requested range,
// ordered from the oldest bucket to the current one, including the current
// unit's data in the last bucket.
func (s *StatsCtx) dataFromAggregates(
	dbAgg *unitDB,
	perBucket [][resultLast]uint64,
	dbTimeSumUs uint64,
	curSnap *unitDB,
	curID uint32,
) (resp *StatsResp) {
	units := []*unitDB{dbAgg, curSnap}

	topUpstreamsResponses, topUpstreamsAvgTime := topUpstreamsPairs(units)

	resp = &StatsResp{
		TopQueried:            topsCollector(units, maxDomains, s.ignored, func(u *unitDB) (pairs []countPair) { return u.Domains }),
		TopBlocked:            topsCollector(units, maxDomains, s.ignored, func(u *unitDB) (pairs []countPair) { return u.BlockedDomains }),
		TopUpstreamsResponses: topUpstreamsResponses,
		TopUpstreamsAvgTime:   topUpstreamsAvgTime,
		TopClients:            topsCollector(units, maxClients, nil, topClientPairs(s)),
	}

	s.fillCollectedStats(resp, perBucket, curID)

	// Total counters.  The total number of requests is the sum of the
	// per-result counters.
	var (
		numDNSQueries       uint64
		numBlockedFiltering uint64
		numSafebrowsing     uint64
		numSafesearch       uint64
		numParental         uint64
	)
	for _, nResult := range perBucket {
		for r, count := range nResult {
			numDNSQueries += count

			switch Result(r) {
			case RFiltered:
				numBlockedFiltering += count
			case RSafeBrowsing:
				numSafebrowsing += count
			case RSafeSearch:
				numSafesearch += count
			case RParental:
				numParental += count
			default:
				// NotFiltered isn't shown in the response.
			}
		}
	}

	resp.NumDNSQueries = numDNSQueries
	resp.NumBlockedFiltering = numBlockedFiltering
	resp.NumReplacedSafebrowsing = numSafebrowsing
	resp.NumReplacedSafesearch = numSafesearch
	resp.NumReplacedParental = numParental

	if numDNSQueries != 0 {
		resp.AvgProcessingTime = microsecondsToSeconds(float64(dbTimeSumUs) / float64(numDNSQueries))
	}

	return resp
}

// fillCollectedStats fills data with collected statistics.  perBucket must
// contain the per-bucket result counters of the whole requested range,
// ordered from the oldest bucket to the current one.
func (s *StatsCtx) fillCollectedStats(data *StatsResp, perBucket [][resultLast]uint64, curID uint32) {
	size := len(perBucket)
	data.TimeUnits = timeUnitsHours

	daysCount := size / 24
	if daysCount > 7 {
		size = daysCount
		data.TimeUnits = timeUnitsDays
	}

	data.DNSQueries = make([]uint64, size)
	data.BlockedFiltering = make([]uint64, size)
	data.ReplacedSafebrowsing = make([]uint64, size)
	data.ReplacedParental = make([]uint64, size)

	if data.TimeUnits == timeUnitsDays {
		s.fillCollectedStatsDaily(data, perBucket, curID, size)

		return
	}

	for i, nResult := range perBucket {
		data.DNSQueries[i] += sumResults(nResult[:])
		data.BlockedFiltering[i] += nResult[RFiltered]
		data.ReplacedSafebrowsing[i] += nResult[RSafeBrowsing]
		data.ReplacedParental[i] += nResult[RParental]
	}
}

// fillCollectedStatsDaily fills data with collected daily statistics.
// perBucket must contain the per-bucket result counters of the whole requested
// range, ordered from the oldest bucket to the current one.
//
// TODO(s.chzhen):  Improve collection of statistics for frontend.  Dashboard
// cards should contain statistics for the whole interval without rounding to
// days.
func (s *StatsCtx) fillCollectedStatsDaily(
	data *StatsResp,
	perBucket [][resultLast]uint64,
	curHour uint32,
	days int,
) {
	// Per time unit counters: 720 hours may span 31 days, so we skip data for
	// the first hours in this case.  align_ceil(24)
	hours := countHours(curHour, days)
	perBucket = perBucket[len(perBucket)-hours:]

	for i, nResult := range perBucket {
		day := i / 24

		data.DNSQueries[day] += sumResults(nResult[:])
		data.BlockedFiltering[day] += nResult[RFiltered]
		data.ReplacedSafebrowsing[day] += nResult[RSafeBrowsing]
		data.ReplacedParental[day] += nResult[RParental]
	}
}

// sumResults returns the sum of the per-result counters, which is the total
// number of requests of a bucket.
func sumResults(nResult []uint64) (sum uint64) {
	for _, count := range nResult {
		sum += count
	}

	return sum
}

// countHours returns the number of hours in the last days.
func countHours(curHour uint32, days int) (n int) {
	hoursInCurDay := int(curHour % 24)
	if hoursInCurDay == 0 {
		hoursInCurDay = 24
	}

	hoursInRestDays := (days - 1) * 24

	return hoursInRestDays + hoursInCurDay
}

func topClientPairs(s *StatsCtx) (pg pairsGetter) {
	return func(u *unitDB) (clients []countPair) {
		for _, c := range u.Clients {
			if c.Name != "" && !s.shouldCountClient([]string{c.Name}) {
				continue
			}

			clients = append(clients, c)
		}

		return clients
	}
}

// topUpstreamsPairs returns sorted lists of number of total responses and the
// average of processing time for each upstream.
func topUpstreamsPairs(
	units []*unitDB,
) (topUpstreamsResponses []topAddrs, topUpstreamsAvgTime []topAddrsFloat) {
	upstreamsResponses := topAddrs{}
	upstreamsTimeSum := topAddrsFloat{}

	for _, u := range units {
		for _, cp := range u.UpstreamsResponses {
			upstreamsResponses[cp.Name] += cp.Count
		}

		for _, cp := range u.UpstreamsTimeSum {
			upstreamsTimeSum[cp.Name] += float64(cp.Count)
		}
	}

	upstreamsAvgTime := topAddrsFloat{}

	for u, n := range upstreamsResponses {
		total := upstreamsTimeSum[u]

		if total != 0 {
			upstreamsAvgTime[u] = microsecondsToSeconds(total / float64(n))
		}
	}

	upstreamsPairs := convertMapToSlice(upstreamsResponses, maxUpstreams)
	topUpstreamsResponses = convertTopSlice(upstreamsPairs)

	return topUpstreamsResponses, prepareTopUpstreamsAvgTime(upstreamsAvgTime)
}

// microsecondsToSeconds converts microseconds to seconds.
//
// NOTE:  Frontend expects time duration in seconds as floating-point number
// with double precision.
func microsecondsToSeconds(n float64) (r float64) {
	const micro = 1e-6

	return n * micro
}

// prepareTopUpstreamsAvgTime returns sorted list of average processing times
// of the DNS requests from each upstream.
func prepareTopUpstreamsAvgTime(
	upstreamsAvgTime topAddrsFloat,
) (topUpstreamsAvgTime []topAddrsFloat) {
	keys := slices.SortedStableFunc(maps.Keys(upstreamsAvgTime), func(a, b string) (res int) {
		switch x, y := upstreamsAvgTime[a], upstreamsAvgTime[b]; {
		case x > y:
			return -1
		case x < y:
			return +1
		default:
			return 0
		}
	})

	topUpstreamsAvgTime = make([]topAddrsFloat, 0, len(upstreamsAvgTime))
	for _, k := range keys {
		topUpstreamsAvgTime = append(topUpstreamsAvgTime, topAddrsFloat{k: upstreamsAvgTime[k]})
	}

	return topUpstreamsAvgTime
}
