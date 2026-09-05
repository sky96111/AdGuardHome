// Package stats provides units for managing statistics of the filtering DNS
// server.
package stats

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// flushCheckIvl is the period of time between checking the need for flushing
// the current unit to the database.
const flushCheckIvl = time.Minute

// snapshotIvl is the period of time between refreshing the persisted snapshot
// of the current unit, so that a crash loses at most this much of the
// statistics.
const snapshotIvl = 5 * flushCheckIvl

// checkInterval returns true if days is valid to be used as statistics
// retention interval.  The valid values are 0, 1, 7, 30 and 90.
func checkInterval(days uint32) (ok bool) {
	return days == 0 || days == 1 || days == 7 || days == 30 || days == 90
}

// validateIvl returns an error if ivl is less than an hour or more than a
// year.
func validateIvl(ivl time.Duration) (err error) {
	if ivl < time.Hour {
		return errors.Error("less than an hour")
	}

	if ivl > timeutil.Day*365 {
		return errors.Error("more than a year")
	}

	return nil
}

// Config is the configuration structure for the statistics collecting.
//
// Do not alter any fields of this structure after using it.
type Config struct {
	// Logger is used for logging the operation of the statistics management.
	// It must not be nil.
	Logger *slog.Logger

	// UnitID is the function to generate the identifier for current unit.  If
	// nil, the default function is used, see newUnitID.
	UnitID UnitIDGenFunc

	// ConfigModifier is used to update the global configuration.  It must not
	// be nil.
	ConfigModifier agh.ConfigModifier

	// ShouldCountClient returns client's ignore setting.
	ShouldCountClient func([]string) bool

	// HTTPRegister is the function that registers handlers for the stats
	// endpoints.
	HTTPReg aghhttp.Registrar

	// Ignored contains the list of host names, which should not be counted,
	// and matches them.
	Ignored *aghnet.IgnoreEngine

	// Filename is the name of the database file.
	Filename string

	// Limit is an upper limit for collecting statistics.
	Limit time.Duration

	// Enabled tells if the statistics are enabled.
	Enabled bool
}

// Interface is the statistics interface to be used by other packages.
type Interface interface {
	// Start begins the statistics collecting.
	Start()

	io.Closer

	// Update collects the incoming statistics data.
	Update(e *Entry)

	// GetTopClientIP returns at most limit IP addresses corresponding to the
	// clients with the most number of requests.
	TopClientsIP(limit uint) []netip.Addr

	// WriteDiskConfig puts the Interface's configuration to the dc.
	WriteDiskConfig(dc *Config)

	// ShouldCount returns true if request for the host should be counted.
	ShouldCount(host string, qType, qClass uint16, ids []string) bool
}

// StatsCtx collects the statistics and flushes it to the database.  The
// statistics are pre-aggregated in memory per hour unit and stored in an
// SQLite database, see [store].
type StatsCtx struct {
	// logger is used for logging the operation of the statistics management.
	// It must not be nil.
	logger *slog.Logger

	// currMu protects curr.
	currMu *sync.RWMutex
	// curr is the actual statistics collection result.
	curr *unit

	// store is the opened statistics database, if any.
	store atomic.Pointer[store]

	// unitIDGen is the function that generates an identifier for the current
	// unit.  It's here for only testing purposes.
	unitIDGen UnitIDGenFunc

	// httpReg registers HTTP handlers.  It must not be nil.
	httpReg aghhttp.Registrar

	// configModifier is used to update the global configuration.
	configModifier agh.ConfigModifier

	// confMu protects ignored, limit, and enabled.
	confMu *sync.RWMutex

	// ignored contains the list of host names, which should not be counted,
	// and matches them.
	ignored *aghnet.IgnoreEngine

	// shouldCountClient returns client's ignore setting.
	shouldCountClient func([]string) bool

	// filename is the name of database file.
	filename string

	// limit is an upper limit for collecting statistics.
	limit time.Duration

	// enabled tells if the statistics are enabled.
	enabled bool

	// lastSnapshot is the time of the last durability snapshot of the current
	// unit.  It's only used by the flushing goroutine while holding currMu.
	lastSnapshot time.Time
}

// New creates s from conf and properly initializes it.  Don't use s before
// calling it's Start method.
func New(ctx context.Context, conf Config) (s *StatsCtx, err error) {
	defer withRecovered(&err)

	err = validateIvl(conf.Limit)
	if err != nil {
		return nil, fmt.Errorf("unsupported interval: %w", err)
	}

	if conf.ShouldCountClient == nil {
		return nil, errors.Error("should count client is unspecified")
	}

	s = &StatsCtx{
		logger:         conf.Logger,
		currMu:         &sync.RWMutex{},
		httpReg:        conf.HTTPReg,
		configModifier: conf.ConfigModifier,
		filename:       conf.Filename,

		confMu:            &sync.RWMutex{},
		ignored:           conf.Ignored,
		shouldCountClient: conf.ShouldCountClient,
		limit:             conf.Limit,
		enabled:           conf.Enabled,
	}

	if s.unitIDGen = newUnitID; conf.UnitID != nil {
		s.unitIDGen = conf.UnitID
	}

	st, err := newStore(ctx, s.logger, s.filename)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	s.store.Store(st)

	id := s.unitIDGen()
	if s.limit == 0 {
		s.curr = newUnit(id)

		return s, nil
	}

	err = st.deleteBucketsBefore(ctx, id-uint32(s.limit.Hours())+1)
	if err != nil {
		s.logger.Error("deleting old units", slogutil.KeyError, err)
	}

	// Restore the current unit, if any, to continue collecting into it.
	udb, err := st.loadUnit(ctx, id)
	if err != nil {
		s.logger.Error("loading current unit", slogutil.KeyError, err)
	} else {
		s.curr = newUnit(id)
		s.curr.deserialize(udb)
	}

	if s.curr == nil {
		s.curr = newUnit(id)
	}

	s.logger.Debug("initialized")

	return s, nil
}

// withRecovered turns the value recovered from panic if any into an error and
// combines it with the one pointed by orig.  orig must be non-nil.
func withRecovered(orig *error) {
	p := recover()
	if p == nil {
		return
	}

	var err error
	switch p := p.(type) {
	case error:
		err = fmt.Errorf("panic: %w", p)
	default:
		err = fmt.Errorf("panic: recovered value of type %[1]T: %[1]v", p)
	}

	*orig = errors.WithDeferred(*orig, err)
}

// type check
var _ Interface = (*StatsCtx)(nil)

// Start implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) Start() {
	s.initWeb()

	go s.periodicFlush()
}

// Close implements the [io.Closer] interface for *StatsCtx.  It flushes the
// current unit to the database and closes the database.
func (s *StatsCtx) Close() (err error) {
	st := s.store.Swap(nil)
	if st == nil {
		return nil
	}

	defer func() {
		cerr := st.Close(context.TODO())
		if cerr == nil {
			s.logger.Debug("database closed")
		}

		err = errors.WithDeferred(err, cerr)
	}()

	s.currMu.Lock()
	defer s.currMu.Unlock()

	if s.curr == nil {
		return nil
	}

	udb := s.curr.serialize()
	if udb.NTotal == 0 {
		return nil
	}

	// TODO(s.chzhen):  Pass context.
	//
	// The current unit's bucket isn't a part of the aggregated top counters,
	// which cover only the completed hours.
	return s.persistUnit(context.TODO(), st, s.curr.id, udb, false)
}

// persistUnit stores udb as the bucket id.
func (s *StatsCtx) persistUnit(
	ctx context.Context,
	st *store,
	id uint32,
	udb *unitDB,
	updateTops bool,
) (err error) {
	err = st.persistUnit(ctx, id, udb, updateTops)
	if err != nil {
		return fmt.Errorf("persisting unit %d: %w", id, err)
	}

	return nil
}

// Update implements the [Interface] interface for *StatsCtx.  e must not be
// nil.
func (s *StatsCtx) Update(e *Entry) {
	s.confMu.Lock()
	defer s.confMu.Unlock()

	if !s.enabled || s.limit == 0 {
		return
	}

	err := e.validate()
	if err != nil {
		s.logger.Debug("validating entry", slogutil.KeyError, err)

		return
	}

	s.currMu.Lock()
	defer s.currMu.Unlock()

	if s.curr == nil {
		s.logger.Error("current unit is nil")

		return
	}

	s.curr.add(e)
}

// WriteDiskConfig implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) WriteDiskConfig(dc *Config) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	dc.Ignored = s.ignored
	dc.Limit = s.limit
	dc.Enabled = s.enabled
}

// TopClientsIP implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) TopClientsIP(maxCount uint) (ips []netip.Addr) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	limit := uint32(s.limit.Hours())
	if !s.enabled || limit == 0 {
		return nil
	}

	s.currMu.RLock()
	cur := s.curr
	if cur == nil {
		s.currMu.RUnlock()

		return nil
	}
	curSnap := cur.serialize()
	s.currMu.RUnlock()

	st := s.store.Load()
	if st == nil {
		return nil
	}

	// TODO(s.chzhen):  Pass context.
	ctx := context.TODO()

	// The database part of the top list is exact, since any client beyond it
	// can't enter the final top list without also being in the current
	// unit's data, which is merged below.
	dbClients, err := st.loadTopClients(ctx, int(maxCount))
	if err != nil {
		s.logger.Error("loading top clients", slogutil.KeyError, err)

		return nil
	}

	m := convertSliceToMap(dbClients)
	for _, c := range curSnap.Clients {
		m[c.Name] += c.Count
	}

	a := convertMapToSlice(m, int(maxCount))
	ips = []netip.Addr{}
	for _, it := range a {
		ip, err := netip.ParseAddr(it.Name)
		if err == nil {
			ips = append(ips, ip)
		}
	}

	return ips
}

// flushTick flushes the statistics to the database, if needed.  When the
// current unit's hour has passed, the unit is persisted and replaced with an
// empty one for the new hour; otherwise, the persisted snapshot of the current
// unit is periodically refreshed to reduce the amount of statistics lost in
// case of a crash.  confMu and currMu are expected to be locked by this
// method.
func (s *StatsCtx) flushTick(now time.Time) {
	id := s.unitIDGen()

	s.confMu.Lock()
	defer s.confMu.Unlock()

	if !s.enabled || s.limit == 0 {
		return
	}

	// NOTE:  This mutex, when combined with the database transaction, is
	// required to be locked first.
	s.currMu.Lock()
	defer s.currMu.Unlock()

	ptr := s.curr
	if ptr == nil {
		return
	}

	limit := uint32(s.limit.Hours())
	if limit == 0 {
		return
	}

	st := s.store.Load()
	if st == nil {
		return
	}

	// TODO(s.chzhen):  Pass context.
	ctx := context.TODO()

	if ptr.id != id {
		// The current unit's hour has passed: persist it and start a new
		// empty unit.  The unit is complete now, so it becomes a part of the
		// aggregated top counters.
		udb := ptr.serialize()

		flushErr := s.persistUnit(ctx, st, ptr.id, udb, true)
		if flushErr != nil {
			s.logger.Error("flushing unit", slogutil.KeyError, flushErr)
		}

		s.curr = newUnit(id)

		delErr := st.deleteBucketsBefore(ctx, id-limit+1)
		if delErr != nil {
			s.logger.Error("deleting old buckets", slogutil.KeyError, delErr)
		}

		s.lastSnapshot = now

		return
	}

	if now.Sub(s.lastSnapshot) < snapshotIvl {
		return
	}

	s.lastSnapshot = now

	// Refresh the persisted snapshot of the current unit.  The top counters
	// aren't updated, since they cover only the completed hours.
	udb := ptr.serialize()
	if udb.NTotal == 0 {
		return
	}

	flushErr := s.persistUnit(ctx, st, ptr.id, udb, false)
	if flushErr != nil {
		s.logger.Error("flushing unit", slogutil.KeyError, flushErr)
	}
}

// periodicFlush periodically checks the need for flushing the unit to the
// database.  Flushing process includes:
//   - persisting the current unit once its hour has passed, replacing it with
//     a new empty one;
//   - removing the stale units from the database;
//   - refreshing the persisted snapshot of the current unit.
func (s *StatsCtx) periodicFlush() {
	ticker := time.NewTicker(flushCheckIvl)
	defer ticker.Stop()

	for now := range ticker.C {
		s.flushTick(now)
	}
}

// setLimit sets the limit.  s.lock is expected to be locked.
//
// TODO(s.chzhen):  Remove it when migration to the new API is over.
func (s *StatsCtx) setLimit(limit time.Duration) {
	if limit != 0 {
		s.enabled = true
		s.limit = limit
		s.logger.Debug("setting limit in days", "num", limit/timeutil.Day)

		return
	}

	s.enabled = false
	s.logger.Debug("disabled")

	if err := s.clear(); err != nil {
		s.logger.Error("clearing", slogutil.KeyError, err)
	}
}

// Reset counters and clear database
func (s *StatsCtx) clear() (err error) {
	defer func() { err = errors.Annotate(err, "clearing: %w") }()

	s.currMu.Lock()
	defer s.currMu.Unlock()

	// Close and remove the database file to guarantee the clean state, then
	// open a fresh one.
	if st := s.store.Swap(nil); st != nil {
		err = st.Close(context.TODO())
		if err != nil {
			s.logger.Error("closing database", slogutil.KeyError, err)
		}
	}

	for _, p := range []string{s.filename, s.filename + "-wal", s.filename + "-shm"} {
		rmErr := os.Remove(p)
		if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			s.logger.Error("removing", "file", p, slogutil.KeyError, rmErr)
		}
	}

	// TODO(s.chzhen):  Pass context.
	st, openErr := newStore(context.TODO(), s.logger, s.filename)
	if openErr != nil {
		s.logger.Error("opening database", slogutil.KeyError, openErr)

		return openErr
	}

	s.store.Store(st)

	s.curr = newUnit(s.unitIDGen())
	s.lastSnapshot = time.Time{}

	s.logger.Debug("cleared")

	return nil
}

// loadUnitSnapshot returns a serialized snapshot of the current unit along
// with its ID, if any.
func (s *StatsCtx) loadUnitSnapshot() (udb *unitDB, curID uint32) {
	s.currMu.RLock()
	defer s.currMu.RUnlock()

	cur := s.curr
	if cur == nil {
		return nil, 0
	}

	return cur.serialize(), cur.id
}

// loadAggregates loads the statistics of the buckets in the [firstID, curID)
// range from the database and returns them along with curSnap, the snapshot
// of the current unit, which isn't a part of the database data.  When windowed
// is false, the top lists are loaded from the aggregated top counters, which
// cover exactly the completed hours of the retention window; otherwise they
// are aggregated from the per-bucket rows of the requested range.
func (s *StatsCtx) loadAggregates(
	ctx context.Context,
	firstID, curID uint32,
	windowed bool,
) (dbAgg *unitDB, perBucket map[uint32][]uint64, timeSumUs uint64, err error) {
	st := s.store.Load()
	if st == nil {
		return nil, nil, 0, errors.Error("database is closed")
	}

	perBucket, err = st.loadCounters(ctx, firstID, curID)
	if err != nil {
		return nil, nil, 0, err
	}

	timeSumUs, err = st.loadTimeSumUs(ctx, firstID, curID)
	if err != nil {
		return nil, nil, 0, err
	}

	dbAgg = &unitDB{}

	if windowed {
		dbAgg.Domains, err = st.loadTopDomainsWindowed(ctx, firstID, curID, maxDomains, false)
		if err != nil {
			return nil, nil, 0, err
		}

		dbAgg.BlockedDomains, err = st.loadTopDomainsWindowed(ctx, firstID, curID, maxDomains, true)
		if err != nil {
			return nil, nil, 0, err
		}

		dbAgg.Clients, err = st.loadTopClientsWindowed(ctx, firstID, curID, maxClients)
		if err != nil {
			return nil, nil, 0, err
		}

		dbAgg.UpstreamsResponses, dbAgg.UpstreamsTimeSum, err = st.loadTopUpstreamsWindowed(
			ctx,
			firstID,
			curID,
			maxUpstreams,
		)
		if err != nil {
			return nil, nil, 0, err
		}

		return dbAgg, perBucket, timeSumUs, nil
	}

	dbAgg.Domains, err = st.loadTopDomains(ctx, maxDomains, false)
	if err != nil {
		return nil, nil, 0, err
	}

	dbAgg.BlockedDomains, err = st.loadTopDomains(ctx, maxDomains, true)
	if err != nil {
		return nil, nil, 0, err
	}

	dbAgg.Clients, err = st.loadTopClients(ctx, maxClients)
	if err != nil {
		return nil, nil, 0, err
	}

	dbAgg.UpstreamsResponses, dbAgg.UpstreamsTimeSum, err = st.loadTopUpstreams(ctx, maxUpstreams)
	if err != nil {
		return nil, nil, 0, err
	}

	return dbAgg, perBucket, timeSumUs, nil
}

// loadUnits returns the aggregates of the buckets in the
// [curID - limit + 1, curID) range along with the snapshot of the current
// unit and its ID.  ok is false if the statistics aren't available.
func (s *StatsCtx) loadUnits(limit uint32) (dbAgg *unitDB, perBucket map[uint32][]uint64, timeSumUs uint64, curSnap *unitDB, curID uint32, ok bool) {
	curSnap, curID = s.loadUnitSnapshot()
	if curSnap == nil {
		return nil, nil, 0, nil, 0, false
	}

	s.confMu.RLock()
	configured := uint32(s.limit.Hours())
	s.confMu.RUnlock()

	// The aggregated top counters cover exactly the completed hours of the
	// retention window, so they're only used when the requested window
	// matches the whole retention.  Otherwise, the custom range requested by
	// the recent parameter is aggregated from the per-bucket rows.
	windowed := limit != configured

	// TODO(s.chzhen):  Pass context.
	ctx := context.TODO()

	dbAgg, perBucket, timeSumUs, err := s.loadAggregates(ctx, curID-limit+1, curID, windowed)
	if err != nil {
		s.logger.Error("loading aggregates", slogutil.KeyError, err)

		return nil, nil, 0, nil, 0, false
	}

	return dbAgg, perBucket, timeSumUs, curSnap, curID, true
}

// ShouldCount returns true if request for the host should be counted.
func (s *StatsCtx) ShouldCount(host string, _, _ uint16, ids []string) bool {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	if !s.shouldCountClient(ids) {
		return false
	}

	return !s.isIgnored(host)
}

// isIgnored returns true if the host is in the ignored domains list.  It
// assumes that s.confMu is locked for reading.
func (s *StatsCtx) isIgnored(host string) bool {
	return s.ignored.Has(host)
}
