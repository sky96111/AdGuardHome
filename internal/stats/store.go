package stats

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghsqldb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// storeSchema is the SQL schema of the statistics database.  The bucket column
// contains the unit ID, an absolute hour number, so that the primary keys
// cover both the time range scans and the per-bucket replacements.
//
// The stats_top_* tables contain the sums of the per-name counters over all
// the live buckets.  They're incrementally updated on each bucket
// replacement, and are decremented when the buckets are removed, so that the
// top queries don't need to aggregate the whole time range.
const storeSchema = `
CREATE TABLE IF NOT EXISTS stats_counters (
	bucket INTEGER NOT NULL,
	result INTEGER NOT NULL,
	count  INTEGER NOT NULL,
	PRIMARY KEY (bucket, result)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS stats_processing (
	bucket      INTEGER NOT NULL PRIMARY KEY,
	time_sum_us INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS stats_domains (
	bucket  INTEGER NOT NULL,
	domain  TEXT    NOT NULL,
	blocked INTEGER NOT NULL,
	count   INTEGER NOT NULL,
	PRIMARY KEY (bucket, domain, blocked)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS stats_clients (
	bucket INTEGER NOT NULL,
	client TEXT    NOT NULL,
	count  INTEGER NOT NULL,
	PRIMARY KEY (bucket, client)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS stats_upstreams (
	bucket      INTEGER NOT NULL,
	upstream    TEXT    NOT NULL,
	responses   INTEGER NOT NULL,
	time_sum_us INTEGER NOT NULL,
	PRIMARY KEY (bucket, upstream)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS stats_top_domains (
	domain  TEXT    NOT NULL,
	blocked INTEGER NOT NULL,
	count   INTEGER NOT NULL,
	PRIMARY KEY (domain, blocked)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_top_domains_count
	ON stats_top_domains (blocked, count);

CREATE TABLE IF NOT EXISTS stats_top_clients (
	client TEXT    NOT NULL PRIMARY KEY,
	count  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_top_clients_count
	ON stats_top_clients (count);

CREATE TABLE IF NOT EXISTS stats_top_upstreams (
	upstream    TEXT    NOT NULL PRIMARY KEY,
	responses   INTEGER NOT NULL,
	time_sum_us INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_top_upstreams_responses
	ON stats_top_upstreams (responses);

-- stats_top_covered contains the IDs of the buckets whose data is currently
-- included in the aggregated top counters.  The durability snapshots of the
-- current unit are written without updating the top counters, so the covered
-- buckets must be tracked to subtract and add only what's actually counted.
-- See [store.rebuildTopCounters] for the startup-time recovery.
CREATE TABLE IF NOT EXISTS stats_top_covered (
	bucket INTEGER NOT NULL PRIMARY KEY
) WITHOUT ROWID;
`

// insertCountersSQL inserts a single counter row of a bucket.
const insertCountersSQL = `INSERT INTO stats_counters (bucket, result, count) VALUES (?, ?, ?)`

// insertProcessingSQL inserts the processing time sum of a bucket.
const insertProcessingSQL = `INSERT INTO stats_processing (bucket, time_sum_us) VALUES (?, ?)`

// insertDomainsSQL inserts a single per-domain counter row of a bucket.
const insertDomainsSQL = `INSERT INTO stats_domains (bucket, domain, blocked, count) VALUES (?, ?, ?, ?)`

// insertClientsSQL inserts a single per-client counter row of a bucket.
const insertClientsSQL = `INSERT INTO stats_clients (bucket, client, count) VALUES (?, ?, ?)`

// insertUpstreamsSQL inserts a single per-upstream counter row of a bucket.
const insertUpstreamsSQL = `INSERT INTO stats_upstreams (bucket, upstream, responses, time_sum_us) VALUES (?, ?, ?, ?)`

// addTopDomainsSQL adds the delta to the aggregated counter of the domain.
const addTopDomainsSQL = `INSERT INTO stats_top_domains (domain, blocked, count) VALUES (?, ?, ?)
	ON CONFLICT (domain, blocked) DO UPDATE SET count = count + excluded.count`

// addTopClientsSQL adds the delta to the aggregated counter of the client.
const addTopClientsSQL = `INSERT INTO stats_top_clients (client, count) VALUES (?, ?)
	ON CONFLICT (client) DO UPDATE SET count = count + excluded.count`

// addTopUpstreamsSQL adds the delta to the aggregated counters of the
// upstream.
const addTopUpstreamsSQL = `INSERT INTO stats_top_upstreams (upstream, responses, time_sum_us) VALUES (?, ?, ?)
	ON CONFLICT (upstream) DO UPDATE
	SET responses = responses + excluded.responses,
		time_sum_us = time_sum_us + excluded.time_sum_us`

// errLegacyDB is returned when the statistics database file is of the legacy
// bbolt format of the previous version.
var errLegacyDB errors.Error = "legacy statistics database"

// statsSchemaVersion is the current version of the statistics database schema,
// see [aghsqldb.EnsureSchemaVersion].
const statsSchemaVersion = 1

// store is a SQLite-backed storage of the statistics.  It is safe for
// concurrent use through the [sql.DB] handle.
type store struct {
	// db is the underlying database handle.  It must not be nil.
	db *sql.DB

	// logger is used for logging the operation of the store.  It must not be
	// nil.
	logger *slog.Logger

	// filename is the name of the database file.
	filename string

	// stmts contains the prepared statements of the store.  It must not be
	// nil after init.
	stmts *storeStmts
}

// storeStmts contains the prepared statements used on the hot paths.  They
// are bound to the transactions through [*sql.Tx.StmtContext].
type storeStmts struct {
	insertCounters   *sql.Stmt
	insertProcessing *sql.Stmt
	insertDomains    *sql.Stmt
	insertClients    *sql.Stmt
	insertUpstreams  *sql.Stmt

	addTopDomains   *sql.Stmt
	addTopClients   *sql.Stmt
	addTopUpstreams *sql.Stmt
}

// newStore opens the SQLite database at filename, creating it if necessary,
// and prepares it for storing the statistics.  If a legacy bbolt database of
// the previous version is found at filename, it's left untouched and an error
// prompting to delete it manually is returned.
func newStore(ctx context.Context, logger *slog.Logger, filename string) (s *store, err error) {
	defer func() { err = errors.Annotate(err, "opening stats db: %w") }()

	err = checkLegacyDB(ctx, logger, filename)
	if err != nil {
		return nil, err
	}

	db, err := aghsqldb.Open(filename)
	if err != nil {
		return nil, err
	}

	s = &store{
		db:       db,
		logger:   logger,
		filename: filename,
	}

	err = s.init(ctx)
	if err != nil {
		return nil, errors.WithDeferred(err, s.Close(ctx))
	}

	err = aghsqldb.ChmodFiles(filename)
	if err != nil {
		return nil, errors.WithDeferred(err, s.Close(ctx))
	}

	return s, nil
}

// init creates the schema and prepares the hot statements.
func (s *store) init(ctx context.Context) (err error) {
	_, err = s.db.ExecContext(ctx, storeSchema)
	if err != nil {
		return fmt.Errorf("creating schema: %w", err)
	}

	err = aghsqldb.EnsureSchemaVersion(ctx, s.db, statsSchemaVersion, nil)
	if err != nil {
		return fmt.Errorf("checking schema version: %w", err)
	}

	s.stmts = &storeStmts{}
	for _, p := range []struct {
		stmt **sql.Stmt
		sql  string
	}{{
		stmt: &s.stmts.insertCounters,
		sql:  insertCountersSQL,
	}, {
		stmt: &s.stmts.insertProcessing,
		sql:  insertProcessingSQL,
	}, {
		stmt: &s.stmts.insertDomains,
		sql:  insertDomainsSQL,
	}, {
		stmt: &s.stmts.insertClients,
		sql:  insertClientsSQL,
	}, {
		stmt: &s.stmts.insertUpstreams,
		sql:  insertUpstreamsSQL,
	}, {
		stmt: &s.stmts.addTopDomains,
		sql:  addTopDomainsSQL,
	}, {
		stmt: &s.stmts.addTopClients,
		sql:  addTopClientsSQL,
	}, {
		stmt: &s.stmts.addTopUpstreams,
		sql:  addTopUpstreamsSQL,
	}} {
		*p.stmt, err = s.db.PrepareContext(ctx, p.sql)
		if err != nil {
			return fmt.Errorf("preparing statement: %w", err)
		}
	}

	return nil
}

// magicOffset is the offset of the magic field of the bbolt meta page.  The
// bbolt file format starts with a 16-byte page header, followed by the meta
// structure, whose first field is the magic value, stored in the native byte
// order of the machine that created the file.
//
// See https://github.com/etcd-io/bbolt.
const magicOffset = 16

// bboltMagic is the marker value of a bbolt database file.
const bboltMagic uint32 = 0xED0CDAED

// checkLegacyDB returns an error if the file at filename is a legacy bbolt
// database of the previous version, leaving it untouched.  The user must
// delete such a file manually to reset the statistics.
func checkLegacyDB(ctx context.Context, logger *slog.Logger, filename string) (err error) {
	f, err := os.Open(filename)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.ErrorContext(ctx, "opening database", slogutil.KeyError, err)
		}

		// A missing file is not an error; a new database is created below.
		return nil
	}
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	var head [magicOffset + 4]byte
	_, err = io.ReadFull(f, head[:])
	if err != nil {
		// The file is too short to be a bbolt database.
		return nil
	}

	magic := binary.BigEndian.Uint32(head[magicOffset:])
	if magic != bboltMagic {
		magic = binary.LittleEndian.Uint32(head[magicOffset:])
		if magic != bboltMagic {
			return nil
		}
	}

	const lines = `AdGuard Home cannot use the statistics database of the previous version.
Please delete or rename the following file manually to reset the statistics,
then start AdGuard Home again.
`

	slogutil.PrintLines(
		ctx,
		logger,
		slog.LevelError,
		"legacy statistics database",
		lines,
	)

	return fmt.Errorf("legacy statistics database %q: %w", filename, errLegacyDB)
}

// Close closes the store.  The store must not be used after that.
func (s *store) Close(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "closing stats db: %w") }()

	if s.stmts != nil {
		for _, stmt := range []*sql.Stmt{
			s.stmts.insertCounters,
			s.stmts.insertProcessing,
			s.stmts.insertDomains,
			s.stmts.insertClients,
			s.stmts.insertUpstreams,
			s.stmts.addTopDomains,
			s.stmts.addTopClients,
			s.stmts.addTopUpstreams,
		} {
			if stmt != nil {
				err = errors.WithDeferred(err, stmt.Close())
			}
		}

		s.stmts = nil
	}

	return errors.WithDeferred(err, s.db.Close())
}

// persistUnit replaces the rows of the bucket id with the data of udb, which
// must not be nil.  When updateTops is true, the aggregated top counters are
// updated to include the bucket; it must only be set for the buckets of the
// completed hours, since the top counters cover exactly those.  The data
// beyond the capped top lists of udb is discarded.
func (s *store) persistUnit(ctx context.Context, id uint32, udb *unitDB, updateTops bool) (err error) {
	defer func() { err = errors.Annotate(err, "persisting unit: %w") }()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, tx.Rollback())
		}
	}()

	// The bucket may be written more than once, e.g. by the durability
	// snapshots of its hour followed by the completion write, or by a
	// snapshot after the system clock jumped backwards and its hour
	// reoccurred.  Remove the contribution of the previous data of the bucket
	// if it's actually counted in the aggregated top counters.
	covered, err := removeTopContribution(ctx, tx, s.stmts, id)
	if err != nil {
		return err
	}

	err = clearBucket(ctx, tx, id)
	if err != nil {
		return err
	}

	err = insertBucket(ctx, tx, s.stmts, id, udb)
	if err != nil {
		return err
	}

	// Add the new data of the bucket to the aggregated top counters if it's
	// covered, so that the counters stay equal to the sum of the covered
	// buckets, or if this is a completion write.
	if covered || updateTops {
		err = updateTopCounters(ctx, tx, s.stmts, udb, +1)
		if err != nil {
			return err
		}

		// The counters of the removed names reached zero and are no longer
		// needed.
		err = removeEmptyTopCounters(ctx, tx)
		if err != nil {
			return err
		}
	}

	if updateTops {
		err = markTopCovered(ctx, tx, id)
		if err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// removeTopContribution subtracts the contribution of the bucket id from the
// aggregated top counters if it's currently covered.  It returns whether the
// bucket was covered.
func removeTopContribution(
	ctx context.Context,
	tx *sql.Tx,
	stmts *storeStmts,
	id uint32,
) (covered bool, err error) {
	covered, err = isTopCovered(ctx, tx, id)
	if err != nil || !covered {
		return covered, err
	}

	old, err := loadUnitTx(ctx, tx, id)
	if err != nil {
		return false, err
	}

	err = updateTopCounters(ctx, tx, stmts, old, -1)
	if err != nil {
		return false, err
	}

	return true, nil
}

// rebuildTopCounters recomputes the aggregated top counters and the covered
// bucket set from the per-bucket rows of all the completed hours, discarding
// whatever the previous process left there.  It makes the top counters
// self-healing: the buckets written by the durability snapshots of a previous
// process are adopted into the top counters, whether or not the previous
// process counted them, so a crash or a restart can't skew them.
func (s *store) rebuildTopCounters(ctx context.Context, curID uint32) (err error) {
	defer func() { err = errors.Annotate(err, "rebuilding top counters: %w") }()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, tx.Rollback())
		}
	}()

	bucket := int64(curID)

	for _, q := range []struct{ reset, rebuild string }{{
		reset: `DELETE FROM stats_top_domains`,
		rebuild: `INSERT INTO stats_top_domains (domain, blocked, count)
			SELECT domain, blocked, SUM(count) FROM stats_domains
			WHERE bucket < ? GROUP BY domain, blocked`,
	}, {
		reset: `DELETE FROM stats_top_clients`,
		rebuild: `INSERT INTO stats_top_clients (client, count)
			SELECT client, SUM(count) FROM stats_clients
			WHERE bucket < ? GROUP BY client`,
	}, {
		reset: `DELETE FROM stats_top_upstreams`,
		rebuild: `INSERT INTO stats_top_upstreams (upstream, responses, time_sum_us)
			SELECT upstream, SUM(responses), SUM(time_sum_us) FROM stats_upstreams
			WHERE bucket < ? GROUP BY upstream`,
	}, {
		reset: `DELETE FROM stats_top_covered`,
		rebuild: `INSERT INTO stats_top_covered (bucket)
			SELECT DISTINCT bucket FROM stats_counters WHERE bucket < ?`,
	}} {
		_, err = tx.ExecContext(ctx, q.reset)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, q.rebuild, bucket)
		if err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// isTopCovered returns true if the data of the bucket id is currently
// included in the aggregated top counters.
func isTopCovered(ctx context.Context, tx *sql.Tx, id uint32) (covered bool, err error) {
	err = tx.QueryRowContext(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM stats_top_covered WHERE bucket = ?)`,
		int64(id),
	).Scan(&covered)
	if err != nil {
		return false, fmt.Errorf("checking top coverage: %w", err)
	}

	return covered, nil
}

// markTopCovered records that the data of the bucket id is included in the
// aggregated top counters.
func markTopCovered(ctx context.Context, tx *sql.Tx, id uint32) (err error) {
	// Ignore the conflict, since the bucket may already be covered, e.g.
	// after the system clock jumped backwards and its hour reoccurred.
	_, err = tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO stats_top_covered (bucket) VALUES (?)`,
		int64(id),
	)
	if err != nil {
		return fmt.Errorf("marking top coverage: %w", err)
	}

	return nil
}

// deleteBucketsBefore removes all the buckets older than firstID, keeping the
// aggregated top counters in sync, and reclaims their space.  firstID must be
// the first bucket of the retention window, so that the top counters keep
// covering exactly the completed hours of the window.
func (s *store) deleteBucketsBefore(ctx context.Context, firstID uint32) (err error) {
	defer func() { err = errors.Annotate(err, "deleting old buckets: %w") }()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, tx.Rollback())
		}
	}()

	bucket := int64(firstID)

	// The covered-bucket condition guards against subtracting the data of
	// the buckets that were written by the durability snapshots and thus
	// never entered the top counters.  Normally, all the buckets older than
	// the retention window are covered.
	//
	// Collect the contribution of the covered removed buckets to subtract it
	// from the aggregated top counters.
	var old unitDB

	err = queryRows(ctx, tx, `SELECT domain, blocked, SUM(count) FROM stats_domains
WHERE bucket < ? AND bucket IN (SELECT bucket FROM stats_top_covered)
GROUP BY domain, blocked`, func(rows *sql.Rows) (err error) {
		var name string
		var blocked bool
		var count int64
		err = rows.Scan(&name, &blocked, &count)
		if err != nil {
			return err
		}

		if blocked {
			old.BlockedDomains = append(old.BlockedDomains, countPair{Name: name, Count: uint64(count)})
		} else {
			old.Domains = append(old.Domains, countPair{Name: name, Count: uint64(count)})
		}

		return nil
	}, bucket)
	if err != nil {
		return err
	}

	err = queryRows(ctx, tx, `SELECT client, SUM(count) FROM stats_clients
WHERE bucket < ? AND bucket IN (SELECT bucket FROM stats_top_covered)
GROUP BY client`, func(rows *sql.Rows) (err error) {
		var name string
		var count int64
		err = rows.Scan(&name, &count)
		if err != nil {
			return err
		}

		old.Clients = append(old.Clients, countPair{Name: name, Count: uint64(count)})

		return nil
	}, bucket)
	if err != nil {
		return err
	}

	err = queryRows(ctx, tx, `SELECT upstream, SUM(responses), SUM(time_sum_us) FROM stats_upstreams
WHERE bucket < ? AND bucket IN (SELECT bucket FROM stats_top_covered)
GROUP BY upstream`, func(rows *sql.Rows) (err error) {
		var name string
		var respCount, timeSum int64
		err = rows.Scan(&name, &respCount, &timeSum)
		if err != nil {
			return err
		}

		old.UpstreamsResponses = append(old.UpstreamsResponses, countPair{
			Name:  name,
			Count: uint64(respCount),
		})
		old.UpstreamsTimeSum = append(old.UpstreamsTimeSum, countPair{
			Name:  name,
			Count: uint64(timeSum),
		})

		return nil
	}, bucket)
	if err != nil {
		return err
	}

	err = updateTopCounters(ctx, tx, s.stmts, &old, -1)
	if err != nil {
		return err
	}

	for _, table := range []string{
		"stats_counters",
		"stats_processing",
		"stats_domains",
		"stats_clients",
		"stats_upstreams",
	} {
		_, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE bucket < ?", bucket)
		if err != nil {
			return fmt.Errorf("clearing %s: %w", table, err)
		}
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM stats_top_covered WHERE bucket < ?", bucket)
	if err != nil {
		return fmt.Errorf("clearing covered buckets: %w", err)
	}

	err = removeEmptyTopCounters(ctx, tx)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	// Reclaim the space of the deleted pages.  It's a no-op when there is
	// nothing to reclaim.
	_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")

	return err
}

// clearBucket removes the rows of the bucket.
func clearBucket(ctx context.Context, tx *sql.Tx, id uint32) (err error) {
	bucket := int64(id)
	for _, table := range []string{
		"stats_counters",
		"stats_processing",
		"stats_domains",
		"stats_clients",
		"stats_upstreams",
	} {
		_, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE bucket = ?", bucket)
		if err != nil {
			return fmt.Errorf("clearing %s: %w", table, err)
		}
	}

	return nil
}

// insertBucket inserts the rows of udb for the bucket id using the prepared
// statements of stmts.  Zero counters are skipped.
func insertBucket(
	ctx context.Context,
	tx *sql.Tx,
	stmts *storeStmts,
	id uint32,
	udb *unitDB,
) (err error) {
	bucket := int64(id)

	for res, count := range udb.NResult {
		if count == 0 {
			continue
		}

		_, err = tx.StmtContext(ctx, stmts.insertCounters).ExecContext(ctx, bucket, res, int64(count))
		if err != nil {
			return fmt.Errorf("inserting counter: %w", err)
		}
	}

	if udb.TimeSumUs != 0 {
		_, err = tx.StmtContext(ctx, stmts.insertProcessing).ExecContext(ctx, bucket, int64(udb.TimeSumUs))
		if err != nil {
			return fmt.Errorf("inserting processing time: %w", err)
		}
	}

	insDomains := tx.StmtContext(ctx, stmts.insertDomains)
	for _, p := range udb.Domains {
		_, err = insDomains.ExecContext(ctx, bucket, p.Name, false, int64(p.Count))
		if err != nil {
			return fmt.Errorf("inserting domain: %w", err)
		}
	}

	for _, p := range udb.BlockedDomains {
		_, err = insDomains.ExecContext(ctx, bucket, p.Name, true, int64(p.Count))
		if err != nil {
			return fmt.Errorf("inserting blocked domain: %w", err)
		}
	}

	insClients := tx.StmtContext(ctx, stmts.insertClients)
	for _, p := range udb.Clients {
		_, err = insClients.ExecContext(ctx, bucket, p.Name, int64(p.Count))
		if err != nil {
			return fmt.Errorf("inserting client: %w", err)
		}
	}

	insUpstreams := tx.StmtContext(ctx, stmts.insertUpstreams)

	timeSums := convertSliceToMap(udb.UpstreamsTimeSum)
	for _, p := range udb.UpstreamsResponses {
		_, err = insUpstreams.ExecContext(
			ctx,
			bucket,
			p.Name,
			int64(p.Count),
			int64(timeSums[p.Name]),
		)
		if err != nil {
			return fmt.Errorf("inserting upstream: %w", err)
		}
	}

	return nil
}

// updateTopCounters adds the per-name counters of udb to the aggregated top
// counters, multiplying them by sign, which must be either 1 or -1.  udb may
// be nil.
func updateTopCounters(
	ctx context.Context,
	tx *sql.Tx,
	stmts *storeStmts,
	udb *unitDB,
	sign int,
) (err error) {
	if udb == nil {
		return nil
	}

	insDomains := tx.StmtContext(ctx, stmts.addTopDomains)
	for _, p := range udb.Domains {
		_, err = insDomains.ExecContext(ctx, p.Name, false, int64(p.Count)*int64(sign))
		if err != nil {
			return fmt.Errorf("updating top domain: %w", err)
		}
	}

	for _, p := range udb.BlockedDomains {
		_, err = insDomains.ExecContext(ctx, p.Name, true, int64(p.Count)*int64(sign))
		if err != nil {
			return fmt.Errorf("updating top blocked domain: %w", err)
		}
	}

	insClients := tx.StmtContext(ctx, stmts.addTopClients)
	for _, p := range udb.Clients {
		_, err = insClients.ExecContext(ctx, p.Name, int64(p.Count)*int64(sign))
		if err != nil {
			return fmt.Errorf("updating top client: %w", err)
		}
	}

	insUpstreams := tx.StmtContext(ctx, stmts.addTopUpstreams)

	timeSums := convertSliceToMap(udb.UpstreamsTimeSum)
	for _, p := range udb.UpstreamsResponses {
		_, err = insUpstreams.ExecContext(
			ctx,
			p.Name,
			int64(p.Count)*int64(sign),
			int64(timeSums[p.Name])*int64(sign),
		)
		if err != nil {
			return fmt.Errorf("updating top upstream: %w", err)
		}
	}

	return nil
}

// removeEmptyTopCounters removes the aggregated counters that reached zero,
// e.g. after the retention of the old buckets.
func removeEmptyTopCounters(ctx context.Context, tx *sql.Tx) (err error) {
	for _, query := range []string{
		"DELETE FROM stats_top_domains WHERE count <= 0",
		"DELETE FROM stats_top_clients WHERE count <= 0",
		"DELETE FROM stats_top_upstreams WHERE responses <= 0",
	} {
		_, err = tx.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("removing empty counters: %w", err)
		}
	}

	return nil
}

// loadUnit loads the bucket id from the database.  It returns nil if the
// bucket doesn't exist.
func (s *store) loadUnit(ctx context.Context, id uint32) (udb *unitDB, err error) {
	defer func() { err = errors.Annotate(err, "loading unit: %w") }()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, tx.Rollback())
		}
	}()

	udb, err = loadUnitTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}

	return udb, tx.Commit()
}

// checkCount returns an error if count is negative, since converting a
// negative int64 to uint64 would wrap around.
func checkCount(count int64) (err error) {
	if count < 0 {
		return fmt.Errorf("negative count %d", count)
	}

	return nil
}

// loadUnitTx loads the bucket id from the database using tx.  It returns nil
// if the bucket doesn't exist.
func loadUnitTx(ctx context.Context, tx *sql.Tx, id uint32) (udb *unitDB, err error) {
	udb = &unitDB{
		NResult: make([]uint64, resultLast),
	}

	bucket := int64(id)

	err = queryRows(ctx, tx, `SELECT result, count FROM stats_counters WHERE bucket = ?`,
		func(rows *sql.Rows) (err error) {
			var res, count int64
			err = rows.Scan(&res, &count)
			if err != nil {
				return err
			}

			if res < 0 || res >= int64(resultLast) {
				return fmt.Errorf("invalid result code %d", res)
			}

			if err = checkCount(count); err != nil {
				return err
			}

			udb.NResult[res] += uint64(count)

			return nil
		}, bucket)
	if err != nil {
		return nil, err
	}

	err = tx.QueryRowContext(ctx, `SELECT time_sum_us FROM stats_processing WHERE bucket = ?`, bucket).
		Scan(&udb.TimeSumUs)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	udb.Domains, err = loadDomainPairsTx(ctx, tx, bucket, false)
	if err != nil {
		return nil, err
	}

	udb.BlockedDomains, err = loadDomainPairsTx(ctx, tx, bucket, true)
	if err != nil {
		return nil, err
	}

	udb.Clients, err = loadClientPairsTx(ctx, tx, bucket)
	if err != nil {
		return nil, err
	}

	udb.UpstreamsResponses, udb.UpstreamsTimeSum, err = loadUpstreamPairsTx(ctx, tx, bucket)
	if err != nil {
		return nil, err
	}

	for _, count := range udb.NResult {
		udb.NTotal += count
	}

	if udb.NTotal == 0 && len(udb.Domains) == 0 && len(udb.BlockedDomains) == 0 &&
		len(udb.Clients) == 0 && len(udb.UpstreamsResponses) == 0 {
		return nil, nil
	}

	return udb, nil
}

// loadDomainPairsTx loads the per-domain counters of the bucket.  blocked
// selects the blocked domains; otherwise the allowed ones are loaded.
func loadDomainPairsTx(
	ctx context.Context,
	tx *sql.Tx,
	bucket int64,
	blocked bool,
) (pairs []countPair, err error) {
	err = queryRows(ctx, tx, `SELECT domain, count FROM stats_domains WHERE bucket = ? AND blocked = ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, bucket, blocked)

	return pairs, err
}

// loadClientPairsTx loads the per-client counters of the bucket.
func loadClientPairsTx(ctx context.Context, tx *sql.Tx, bucket int64) (pairs []countPair, err error) {
	err = queryRows(ctx, tx, `SELECT client, count FROM stats_clients WHERE bucket = ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, bucket)

	return pairs, err
}

// loadUpstreamPairsTx loads the per-upstream counters of the bucket.
func loadUpstreamPairsTx(
	ctx context.Context,
	tx *sql.Tx,
	bucket int64,
) (responses, timeSums []countPair, err error) {
	err = queryRows(ctx, tx, `SELECT upstream, responses, time_sum_us FROM stats_upstreams WHERE bucket = ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var respCount, timeSum int64
			err = rows.Scan(&name, &respCount, &timeSum)
			if err != nil {
				return err
			}

			if err = checkCount(respCount); err != nil {
				return err
			}

			if err = checkCount(timeSum); err != nil {
				return err
			}

			responses = append(responses, countPair{Name: name, Count: uint64(respCount)})
			timeSums = append(timeSums, countPair{Name: name, Count: uint64(timeSum)})

			return nil
		}, bucket)

	return responses, timeSums, err
}

// scanRows runs f for every row and closes rows afterwards.
func scanRows(rows *sql.Rows, f func(rows *sql.Rows) (err error)) (err error) {
	defer func() { err = errors.WithDeferred(err, rows.Close()) }()

	for rows.Next() {
		err = f(rows)
		if err != nil {
			return err
		}
	}

	return rows.Err()
}

// sqlQuery is the subset of the [*sql.Tx] and [*sql.DB] methods used for
// querying.
type sqlQuery interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// queryRows runs the query with args and passes the rows to f.
func queryRows(
	ctx context.Context,
	q sqlQuery,
	query string,
	f func(rows *sql.Rows) (err error),
	args ...any,
) (err error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}

	return scanRows(rows, f)
}

// loadCounters loads the per-bucket result counters of the buckets in the
// [firstID, curID) range.  The missing buckets aren't presented in the
// returned map.
func (s *store) loadCounters(
	ctx context.Context,
	firstID, curID uint32,
) (perBucket map[uint32][]uint64, err error) {
	defer func() { err = errors.Annotate(err, "loading counters: %w") }()

	perBucket = map[uint32][]uint64{}

	err = queryRows(ctx, s.db, `SELECT bucket, result, count FROM stats_counters WHERE bucket >= ? AND bucket < ?`,
		func(rows *sql.Rows) (err error) {
			var bucketID, res, count int64
			err = rows.Scan(&bucketID, &res, &count)
			if err != nil {
				return err
			}

			if res < 0 || res >= int64(resultLast) {
				return fmt.Errorf("invalid result code %d", res)
			}

			if err = checkCount(count); err != nil {
				return err
			}

			bucket := uint32(bucketID)
			if perBucket[bucket] == nil {
				perBucket[bucket] = make([]uint64, resultLast)
			}
			perBucket[bucket][res] += uint64(count)

			return nil
		}, int64(firstID), int64(curID))

	return perBucket, err
}

// loadTimeSumUs loads the total processing time sum, in microseconds, of the
// buckets in the [firstID, curID) range.
func (s *store) loadTimeSumUs(ctx context.Context, firstID, curID uint32) (timeSumUs uint64, err error) {
	defer func() { err = errors.Annotate(err, "loading time sums: %w") }()

	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(time_sum_us), 0) FROM stats_processing WHERE bucket >= ? AND bucket < ?`,
		int64(firstID), int64(curID)).
		Scan(&timeSumUs)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}

	return timeSumUs, err
}

// loadTopDomains loads at most limit the most requested domains of the whole
// retention range from the aggregated top counters.  blocked selects the
// blocked domains; otherwise the allowed ones are loaded.
func (s *store) loadTopDomains(
	ctx context.Context,
	limit int,
	blocked bool,
) (pairs []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading top domains: %w") }()

	err = queryRows(ctx, s.db, `SELECT domain, count FROM stats_top_domains WHERE blocked = ? ORDER BY count DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, blocked, limit)

	return pairs, err
}

// loadTopClients loads at most limit the clients with the most requests within
// the whole retention range.
func (s *store) loadTopClients(ctx context.Context, limit int) (pairs []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading top clients: %w") }()

	err = queryRows(ctx, s.db, `SELECT client, count FROM stats_top_clients ORDER BY count DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, limit)

	return pairs, err
}

// loadTopUpstreams loads at most limit the upstreams with the most responses
// within the whole retention range, along with their processing time sums.
func (s *store) loadTopUpstreams(
	ctx context.Context,
	limit int,
) (responses, timeSums []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading top upstreams: %w") }()

	err = queryRows(ctx, s.db, `SELECT upstream, responses, time_sum_us FROM stats_top_upstreams ORDER BY responses DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var respCount, timeSum int64
			err = rows.Scan(&name, &respCount, &timeSum)
			if err != nil {
				return err
			}

			if err = checkCount(respCount); err != nil {
				return err
			}

			if err = checkCount(timeSum); err != nil {
				return err
			}

			responses = append(responses, countPair{Name: name, Count: uint64(respCount)})
			timeSums = append(timeSums, countPair{Name: name, Count: uint64(timeSum)})

			return nil
		}, limit)

	return responses, timeSums, err
}

// loadTopDomainsWindowed loads at most limit the most requested domains within
// the buckets in the [firstID, curID) range.  Unlike [store.loadTopDomains], it
// aggregates the per-bucket rows, and it's used for the custom, non-retention
// time ranges requested through the recent parameter.  blocked selects the
// blocked domains; otherwise the allowed ones are loaded.
func (s *store) loadTopDomainsWindowed(
	ctx context.Context,
	firstID, curID uint32,
	limit int,
	blocked bool,
) (pairs []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading windowed top domains: %w") }()

	err = queryRows(ctx, s.db, `SELECT domain, SUM(count) AS c FROM stats_domains
WHERE bucket >= ? AND bucket < ? AND blocked = ? GROUP BY domain ORDER BY c DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, int64(firstID), int64(curID), blocked, limit)

	return pairs, err
}

// loadTopClientsWindowed loads at most limit the clients with the most
// requests within the buckets in the [firstID, curID) range.
func (s *store) loadTopClientsWindowed(
	ctx context.Context,
	firstID, curID uint32,
	limit int,
) (pairs []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading windowed top clients: %w") }()

	err = queryRows(ctx, s.db, `SELECT client, SUM(count) AS c FROM stats_clients
WHERE bucket >= ? AND bucket < ? GROUP BY client ORDER BY c DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var count int64
			err = rows.Scan(&name, &count)
			if err != nil {
				return err
			}

			if err = checkCount(count); err != nil {
				return err
			}

			pairs = append(pairs, countPair{Name: name, Count: uint64(count)})

			return nil
		}, int64(firstID), int64(curID), limit)

	return pairs, err
}

// loadTopUpstreamsWindowed loads at most limit the upstreams with the most
// responses within the buckets in the [firstID, curID) range, along with their
// processing time sums.
func (s *store) loadTopUpstreamsWindowed(
	ctx context.Context,
	firstID, curID uint32,
	limit int,
) (responses, timeSums []countPair, err error) {
	defer func() { err = errors.Annotate(err, "loading windowed top upstreams: %w") }()

	err = queryRows(ctx, s.db, `SELECT upstream, SUM(responses) AS r, SUM(time_sum_us) AS t FROM stats_upstreams
WHERE bucket >= ? AND bucket < ? GROUP BY upstream ORDER BY r DESC LIMIT ?`,
		func(rows *sql.Rows) (err error) {
			var name string
			var respCount, timeSum int64
			err = rows.Scan(&name, &respCount, &timeSum)
			if err != nil {
				return err
			}

			if err = checkCount(respCount); err != nil {
				return err
			}

			if err = checkCount(timeSum); err != nil {
				return err
			}

			responses = append(responses, countPair{Name: name, Count: uint64(respCount)})
			timeSums = append(timeSums, countPair{Name: name, Count: uint64(timeSum)})

			return nil
		}, int64(firstID), int64(curID), limit)

	return responses, timeSums, err
}
