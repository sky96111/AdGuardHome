package querylog

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/AdguardTeam/AdGuardHome/internal/aghsqldb"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/ncruces/go-sqlite3/ext/fts5"
)

// querylogDBFileName is the name of the SQLite database file containing the
// query log.
const querylogDBFileName = "querylog.db"

// querylogSchemaVersion is the current version of the query log database
// schema, see [aghsqldb.EnsureSchemaVersion].
const querylogSchemaVersion = 1

// storeSchema is the SQL schema of the query log database.  The reason and
// is_filtered columns are denormalized copies of the fields of the result
// column, so that they can be used in the search predicates and indexes.
//
// The querylog_fts virtual table mirrors the columns that the free-text search
// matches against.  It uses the trigram tokenizer to support case-insensitive
// substring matching, and it's kept in sync with the querylog table by the
// triggers below.
const storeSchema = `
CREATE TABLE IF NOT EXISTS querylog (
	id           INTEGER PRIMARY KEY,
	time         INTEGER NOT NULL,
	host         TEXT    NOT NULL,
	qtype        TEXT    NOT NULL,
	qclass       TEXT    NOT NULL,
	client_ip    TEXT    NOT NULL,
	client_proto TEXT    NOT NULL,
	client_id    TEXT    NOT NULL,
	ecs          TEXT    NOT NULL,
	upstream     TEXT    NOT NULL,
	elapsed      INTEGER NOT NULL,
	reason       INTEGER NOT NULL,
	is_filtered  INTEGER NOT NULL,
	result       TEXT    NOT NULL,
	answer       BLOB,
	orig_answer  BLOB,
	cached       INTEGER NOT NULL,
	ad           INTEGER NOT NULL
);

-- The idx_querylog_time index also lists the id column explicitly, although
-- it's redundant, because the rowid is the implicit last column of every
-- index, so (time, id) and (time) are equivalent.  It makes the keyset
-- pagination predicate, which compares the (time, id) pairs, explicit.  The
-- predicate returns the entries from newest to oldest without losing the
-- entries sharing a timestamp at a page boundary.
CREATE INDEX IF NOT EXISTS idx_querylog_time ON querylog (time, id);
CREATE INDEX IF NOT EXISTS idx_querylog_host ON querylog (host);
CREATE INDEX IF NOT EXISTS idx_querylog_client_ip ON querylog (client_ip);
CREATE INDEX IF NOT EXISTS idx_querylog_client_id ON querylog (client_id COLLATE NOCASE);

CREATE VIRTUAL TABLE IF NOT EXISTS querylog_fts USING fts5 (
	host,
	client_ip,
	client_id,
	content='querylog',
	content_rowid='id',
	tokenize='trigram'
);

CREATE TRIGGER IF NOT EXISTS querylog_fts_insert AFTER INSERT ON querylog BEGIN
	INSERT INTO querylog_fts (rowid, host, client_ip, client_id)
	VALUES (new.id, new.host, new.client_ip, new.client_id);
END;

CREATE TRIGGER IF NOT EXISTS querylog_fts_delete AFTER DELETE ON querylog BEGIN
	INSERT INTO querylog_fts (querylog_fts, rowid, host, client_ip, client_id)
	VALUES ('delete', old.id, old.host, old.client_ip, old.client_id);
END;
`

// insertEntrySQL inserts a single log entry.  The column order must match the
// one in [entryToArgs].
const insertEntrySQL = `INSERT INTO querylog (
	time, host, qtype, qclass, client_ip, client_proto, client_id, ecs,
	upstream, elapsed, reason, is_filtered, result, answer, orig_answer,
	cached, ad
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// selectEntrySQL is the beginning of the entry search query.  The column order
// must match the one in [scanLogEntry].
const selectEntrySQL = `SELECT
	id, time, host, qtype, qclass, client_ip, client_proto, client_id, ecs,
	upstream, elapsed, reason, is_filtered, result, answer, orig_answer,
	cached, ad
FROM querylog`

// trigramMinRunes is the minimum length of a search term that the trigram
// tokenizer of the FTS index can match.  Shorter terms fall back to scanning.
const trigramMinRunes = 3

// store is a SQLite-backed storage of the query log entries.  It is not safe
// for concurrent use, except for the methods that use the [sql.DB] handle,
// which are.
type store struct {
	// db is the underlying database handle.  It must not be nil.
	db *sql.DB

	// logger is used for logging the operation of the store.  It must not be
	// nil.
	logger *slog.Logger

	// insertStmt is the prepared statement used to insert the entries in a
	// batch.  It must not be nil after init.
	insertStmt *sql.Stmt

	// stmtsMu protects stmts and closed.
	stmtsMu sync.Mutex

	// stmts contains the prepared search statements by their query text.
	// The query text only varies by the combination of the applied filters,
	// since the varying-width ID lists are bound through the json_each
	// table-valued function and the reason lists are bounded by the number of
	// the reasons, so the cache is bounded and small.
	stmts map[string]*sql.Stmt

	// closed is true after Close.  It's protected by stmtsMu.
	closed bool
}

// newStore opens the SQLite database at dbPath, creating it if necessary, and
// prepares it for storing the query log entries.
func newStore(ctx context.Context, logger *slog.Logger, dbPath string) (s *store, err error) {
	defer func() { err = errors.Annotate(err, "opening querylog db: %w") }()

	db, err := aghsqldb.Open(dbPath, fts5.Register)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s = &store{
		db:     db,
		logger: logger,
		stmts:  map[string]*sql.Stmt{},
	}

	err = s.init(ctx)
	if err != nil {
		return nil, errors.WithDeferred(err, s.Close(ctx))
	}

	// The WAL and SHM files are created by the first query, so make sure
	// their permissions are fixed after the initialization as well.
	err = aghsqldb.ChmodFiles(dbPath)
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

	err = aghsqldb.EnsureSchemaVersion(ctx, s.db, querylogSchemaVersion, nil)
	if err != nil {
		return fmt.Errorf("checking schema version: %w", err)
	}

	// Check the FTS index consistency, but don't rebuild it automatically,
	// since a rebuild is expensive for large databases.  A mismatch is
	// reported to the operator instead.
	s.checkFTSIntegrity(ctx)

	s.insertStmt, err = s.db.PrepareContext(ctx, insertEntrySQL)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}

	return nil
}

// checkFTSIntegrity checks the consistency of the FTS index with the content
// table and logs an error if it's inconsistent.  It doesn't return an error,
// since the query log remains usable even with a stale free-text index.
func (s *store) checkFTSIntegrity(ctx context.Context) {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO querylog_fts (querylog_fts) VALUES ('integrity-check')`,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "checking querylog fts index", slogutil.KeyError, err)
	}
}

// Close closes the store.  The store must not be used after that.
func (s *store) Close(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "closing querylog db: %w") }()

	s.stmtsMu.Lock()
	if s.closed {
		s.stmtsMu.Unlock()

		return nil
	}

	s.closed = true

	// Update the query planner statistics before closing, as recommended by
	// the SQLite documentation.  Ignore the error, since there is nothing to
	// do about it at this point.
	_, _ = s.db.ExecContext(ctx, "PRAGMA optimize")

	for _, stmt := range s.stmts {
		err = errors.WithDeferred(err, stmt.Close())
	}
	s.stmts = nil
	s.stmtsMu.Unlock()

	if s.insertStmt != nil {
		err = errors.WithDeferred(err, s.insertStmt.Close())
		s.insertStmt = nil
	}

	return errors.WithDeferred(err, s.db.Close())
}

// insertBatch inserts all the entries in a single transaction.  On error, the
// entries are considered lost, unless the caller returns them to the buffer,
// see [queryLog.flushLogBuffer].
func (s *store) insertBatch(ctx context.Context, entries []*logEntry) (err error) {
	defer func() { err = errors.Annotate(err, "inserting entries: %w") }()

	s.stmtsMu.Lock()
	if s.closed || s.insertStmt == nil {
		s.stmtsMu.Unlock()

		return errors.Error("store is closed")
	}

	stmt := s.insertStmt
	s.stmtsMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, tx.Rollback())
		}
	}()

	txStmt := tx.StmtContext(ctx, stmt)

	for i, e := range entries {
		var args []any
		args, err = entryToArgs(e)
		if err != nil {
			return fmt.Errorf("encoding entry #%d: %w", i, err)
		}

		_, err = txStmt.ExecContext(ctx, args...)
		if err != nil {
			return fmt.Errorf("inserting entry #%d: %w", i, err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// search performs the search query and decodes the found entries.  The entries
// are returned from newest to oldest.
func (s *store) search(ctx context.Context, sq *searchQuery, limit, offset int) (entries []*logEntry, err error) {
	defer func() { err = errors.Annotate(err, "searching querylog db: %w") }()

	cond := ""
	if len(sq.conds) > 0 {
		cond = " WHERE " + strings.Join(sq.conds, " AND ")
	}

	// The time index is walked in reverse to return the entries from newest
	// to oldest, stopping as soon as enough of them is found.
	query := selectEntrySQL + cond + " ORDER BY time DESC, id DESC LIMIT ? OFFSET ?"
	args := append(sq.args, limit, offset)

	stmt, err := s.stmt(query)
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.WithDeferred(err, rows.Close()) }()

	for rows.Next() {
		var e *logEntry
		e, err = scanLogEntry(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scanning entry: %w", err)
		}

		entries = append(entries, e)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// deleteChunkSize is the maximum number of the entries removed by a single
// delete statement.  Batching prevents the retention and clear operations
// from holding the SQLite write lock for a long time while the per-row FTS
// triggers fire.
const deleteChunkSize = 1000

// deleteOlderThan removes the entries older than cutoff and returns the number
// of the removed entries.
func (s *store) deleteOlderThan(ctx context.Context, cutoff time.Time) (n int64, err error) {
	defer func() { err = errors.Annotate(err, "deleting old entries: %w") }()

	n, err = s.deleteChunks(ctx, "time < ?", []any{cutoff.UnixNano()})
	if err != nil {
		return n, err
	}

	if n > 0 {
		// Reclaim the space of the deleted pages and update the query
		// planner statistics.  Both statements are cheap no-ops when there
		// is nothing to do.
		_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")
		if err != nil {
			return n, err
		}

		_, err = s.db.ExecContext(ctx, "PRAGMA optimize")
	}

	return n, err
}

// deleteChunks removes the entries matching cond in batches of
// [deleteChunkSize], returning the total number of the removed entries.  cond
// is an SQL predicate referencing the querylog table and args are its
// arguments.
func (s *store) deleteChunks(ctx context.Context, cond string, args []any) (n int64, err error) {
	var lastID int64
	for {
		if err = ctx.Err(); err != nil {
			return n, err
		}

		var ids []int64
		ids, err = s.selectDeleteIDs(ctx, cond, args, lastID)
		if err != nil {
			return n, err
		}

		if len(ids) == 0 {
			return n, nil
		}

		lastID = ids[len(ids)-1]

		delArgs := make([]any, len(ids))
		for i, id := range ids {
			delArgs[i] = id
		}

		_, err = s.db.ExecContext(
			ctx,
			"DELETE FROM querylog WHERE id IN ("+placeholders(len(ids))+")",
			delArgs...,
		)
		if err != nil {
			return n, err
		}

		n += int64(len(ids))
	}
}

// selectDeleteIDs returns up to [deleteChunkSize] identifiers of the entries
// matching cond, in ascending ID order, starting after afterID.  cond is an SQL
// predicate referencing the querylog table and args are its arguments.
func (s *store) selectDeleteIDs(
	ctx context.Context,
	cond string,
	args []any,
	afterID int64,
) (ids []int64, err error) {
	query := "SELECT id FROM querylog WHERE id > ? AND (" + cond + ") ORDER BY id LIMIT ?"

	queryArgs := make([]any, 0, len(args)+2)
	queryArgs = append(queryArgs, afterID)
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, deleteChunkSize)

	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.WithDeferred(err, rows.Close()) }()

	for rows.Next() {
		var id int64
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return ids, nil
}

// clear removes all the entries and reclaims their space.
func (s *store) clear(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "clearing querylog db: %w") }()

	_, err = s.deleteChunks(ctx, "1", nil)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, "VACUUM")

	return err
}

// stmt returns a prepared statement for the query, preparing and caching it if
// necessary.
func (s *store) stmt(query string) (stmt *sql.Stmt, err error) {
	s.stmtsMu.Lock()
	defer s.stmtsMu.Unlock()

	if s.closed {
		return nil, errors.Error("store is closed")
	}

	if stmt, ok := s.stmts[query]; ok {
		return stmt, nil
	}

	stmt, err = s.db.Prepare(query)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	s.stmts[query] = stmt

	return stmt, nil
}

// entryToArgs encodes the entry into the list of arguments for
// [insertEntrySQL].
func entryToArgs(e *logEntry) (args []any, err error) {
	var resultJSON []byte
	resultJSON, err = json.Marshal(e.Result)
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}

	return []any{
		e.Time.UnixNano(),
		e.QHost,
		e.QType,
		e.QClass,
		e.IP.String(),
		string(e.ClientProto),
		e.ClientID,
		e.ReqECS,
		e.Upstream,
		int64(e.Elapsed),
		int(e.Result.Reason),
		e.Result.IsFiltered,
		string(resultJSON),
		e.Answer,
		e.OrigAnswer,
		e.Cached,
		e.AuthenticatedData,
	}, nil
}

// scanLogEntry decodes an entry from the row produced by [selectEntrySQL].
func scanLogEntry(scan func(dest ...any) error) (e *logEntry, err error) {
	var (
		id         int64
		timeNano   int64
		elapsed    int64
		clientIP   string
		proto      string
		reason     int
		isFiltered int
		resultJSON string
		cached     int
		ad         int
	)

	e = &logEntry{}
	err = scan(
		&id,
		&timeNano,
		&e.QHost,
		&e.QType,
		&e.QClass,
		&clientIP,
		&proto,
		&e.ClientID,
		&e.ReqECS,
		&e.Upstream,
		&elapsed,
		&reason,
		&isFiltered,
		&resultJSON,
		&e.Answer,
		&e.OrigAnswer,
		&cached,
		&ad,
	)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	e.id = id
	e.Time = time.Unix(0, timeNano)
	e.IP = net.ParseIP(clientIP)
	e.ClientProto = ClientProto(proto)
	e.Elapsed = time.Duration(elapsed)
	e.Cached = cached != 0
	e.AuthenticatedData = ad != 0

	if resultJSON != "" {
		err = json.Unmarshal([]byte(resultJSON), &e.Result)
		if err != nil {
			return nil, fmt.Errorf("decoding result: %w", err)
		}
	}

	e.Result.Reason = filtering.Reason(reason)
	e.Result.IsFiltered = isFiltered != 0

	// Convert the IP addresses of the DNS rewrite result from strings into
	// net.IP values, just like the previous storage did when decoding.
	if e.Result.DNSRewriteResult != nil {
		e.parseDNSRewriteResultIPs()
	}

	return e, nil
}

// searchQuery is a partially constructed SQL search query over the query log
// entries.
type searchQuery struct {
	// conds are the WHERE conditions joined by AND.
	conds []string

	// args are the arguments bound to conds.
	args []any
}

// add appends the condition and its arguments to the query.
func (sq *searchQuery) add(cond string, args ...any) {
	sq.conds = append(sq.conds, cond)
	sq.args = append(sq.args, args...)
}

// buildSearchQuery translates the search parameters into an SQL query.
// lists must contain the client IDs resolved for the free-text search term of
// the parameters, if any.
func buildSearchQuery(params *searchParams, lists clientIDLists) (sq *searchQuery) {
	sq = &searchQuery{}

	if !params.olderThan.IsZero() {
		if params.olderThanID != 0 {
			// The keyset predicate continues the pagination exactly after the
			// entry identified by the (time, id) pair of the cursor, so that
			// the entries sharing the cursor's timestamp aren't skipped.
			sq.add("(time, id) < (?, ?)",
				params.olderThan.UnixNano(),
				params.olderThanID,
			)
		} else {
			sq.add("time < ?", params.olderThan.UnixNano())
		}
	}

	for i, c := range params.searchCriteria {
		switch c.criterionType {
		case ctTerm:
			addTermCriterion(sq, &params.searchCriteria[i], lists.byName)
		case ctFilteringStatus:
			addFilteringStatusCriterion(sq, c.value)
		case ctReason:
			addReasonCriterion(sq, c.values)
		default:
			// The criterion types are validated during parsing.  Go on.
		}
	}

	if len(lists.ignored) > 0 {
		// Hide the entries of the clients that must not be logged.
		ignored := jsonIDs(lists.ignored)
		sq.add("client_ip NOT IN (SELECT value FROM json_each(?))", ignored)
		sq.add("client_id COLLATE NOCASE NOT IN (SELECT value FROM json_each(?))", ignored)
	}

	return sq
}

// addTermCriterion adds the free-text search criterion c to the query.
// idsByName contains the IDs of the clients whose names match the value of the
// criterion, if any.
func addTermCriterion(sq *searchQuery, c *searchCriterion, idsByName []string) {
	if strings.TrimSpace(c.value) == "" {
		// A blank term matches everything.
		return
	}

	if c.strict {
		addStrictTermCriterion(sq, c, idsByName)
	} else {
		addNonStrictTermCriterion(sq, c, idsByName)
	}
}

// idBranch is one index-driven branch of an entry-ID set subquery.
type idBranch struct {
	subquery string

	args []any
}

// addIDSetCriterion adds a criterion matching the entries whose ID appears in
// the union of the given branches.  The outer query walks the time index and
// probes the materialized ID set, so it stops as soon as enough of the entries
// is found.
func addIDSetCriterion(sq *searchQuery, branches []idBranch) {
	parts := make([]string, 0, len(branches))
	args := make([]any, 0, 2*len(branches))
	for _, b := range branches {
		parts = append(parts, b.subquery)
		args = append(args, b.args...)
	}

	sq.add("id IN ("+strings.Join(parts, " UNION ")+")", args...)
}

// addStrictTermCriterion adds an exact-match criterion over the domain name,
// the client IP address, the client ID, and the client name.
func addStrictTermCriterion(sq *searchQuery, c *searchCriterion, idsByName []string) {
	// The stored domain names are lowercase.
	branches := []idBranch{{
		subquery: "SELECT id FROM querylog WHERE host = ?",
		args:     []any{strings.ToLower(c.value)},
	}, {
		subquery: "SELECT id FROM querylog WHERE client_ip = ?",
		args:     []any{c.value},
	}, {
		subquery: "SELECT id FROM querylog WHERE client_id COLLATE NOCASE = ?",
		args:     []any{c.value},
	}}

	if c.asciiVal != "" {
		branches = append(branches, idBranch{
			subquery: "SELECT id FROM querylog WHERE host = ?",
			args:     []any{c.asciiVal},
		})
	}

	branches = appendClientIDBranches(branches, idsByName)

	addIDSetCriterion(sq, branches)
}

// addNonStrictTermCriterion adds a substring-match criterion over the domain
// name, the client IP address, the client ID, and the client name.  Terms long
// enough are matched through the trigram FTS index, the short ones fall back
// to scanning.
func addNonStrictTermCriterion(sq *searchQuery, c *searchCriterion, idsByName []string) {
	if maxRunes(c.value, c.asciiVal) >= trigramMinRunes {
		addFTSTermCriterion(sq, c, idsByName)

		return
	}

	conds := []string{
		"host LIKE ? ESCAPE '\\'",
		"client_ip LIKE ? ESCAPE '\\'",
		"client_id LIKE ? ESCAPE '\\'",
	}
	args := []any{
		likePattern(c.value),
		likePattern(c.value),
		likePattern(c.value),
	}

	if c.asciiVal != "" {
		conds = append(conds, "host LIKE ? ESCAPE '\\'")
		args = append(args, likePattern(c.asciiVal))
	}

	if len(idsByName) > 0 {
		ids := jsonIDs(idsByName)
		conds = append(conds,
			"client_ip IN (SELECT value FROM json_each(?))",
			"client_id COLLATE NOCASE IN (SELECT value FROM json_each(?))",
		)
		args = append(args, ids, ids)
	}

	sq.add("("+strings.Join(conds, " OR ")+")", args...)
}

// addFTSTermCriterion adds a substring-match criterion that uses the trigram
// FTS index.  idsByName contains the IDs of the clients whose names match the
// value of the criterion, if any.
func addFTSTermCriterion(sq *searchQuery, c *searchCriterion, idsByName []string) {
	terms := []string{c.value}
	if c.asciiVal != "" {
		terms = append(terms, c.asciiVal)
	}

	branches := []idBranch{{
		subquery: "SELECT rowid FROM querylog_fts WHERE querylog_fts MATCH ?",
		args:     []any{ftsMatchQuery(terms...)},
	}}

	branches = appendClientIDBranches(branches, idsByName)

	addIDSetCriterion(sq, branches)
}

// appendClientIDBranches appends the branches matching the client IP address
// and client ID columns against ids, if any.
func appendClientIDBranches(branches []idBranch, ids []string) []idBranch {
	if len(ids) == 0 {
		return branches
	}

	idsJSON := jsonIDs(ids)

	return append(branches,
		idBranch{
			subquery: "SELECT id FROM querylog WHERE client_ip IN (SELECT value FROM json_each(?))",
			args:     []any{idsJSON},
		}, idBranch{
			subquery: "SELECT id FROM querylog WHERE client_id COLLATE NOCASE IN (SELECT value FROM json_each(?))",
			args:     []any{idsJSON},
		},
	)
}

// addFilteringStatusCriterion adds the filtering status criterion to the
// query.  val must be one of the [filteringStatusValues].
func addFilteringStatusCriterion(sq *searchQuery, val string) {
	switch val {
	case filteringStatusAll:
		// No predicate.
	case filteringStatusFiltered:
		sq.add("(is_filtered = 1 OR reason IN (?, ?, ?, ?))",
			filtering.NotFilteredAllowList,
			filtering.Rewritten,
			filtering.RewrittenAutoHosts,
			filtering.RewrittenRule,
		)
	case filteringStatusWhitelisted:
		sq.add("reason = ?", filtering.NotFilteredAllowList)
	case filteringStatusBlocked:
		sq.add("is_filtered = 1 AND reason IN (?, ?)",
			filtering.FilteredBlockList,
			filtering.FilteredBlockedService,
		)
	case filteringStatusBlockedService:
		sq.add("reason = ?", filtering.FilteredBlockedService)
	case filteringStatusBlockedSafebrowsing:
		sq.add("reason = ?", filtering.FilteredSafeBrowsing)
	case filteringStatusBlockedParental:
		sq.add("reason = ?", filtering.FilteredParental)
	case filteringStatusSafeSearch:
		sq.add("reason = ?", filtering.FilteredSafeSearch)
	case filteringStatusRewritten:
		sq.add("reason IN (?, ?, ?)",
			filtering.Rewritten,
			filtering.RewrittenAutoHosts,
			filtering.RewrittenRule,
		)
	case filteringStatusProcessed:
		sq.add("reason NOT IN (?, ?, ?)",
			filtering.NotFilteredAllowList,
			filtering.FilteredBlockList,
			filtering.FilteredBlockedService,
		)
	default:
		panic(fmt.Errorf("%w: %q", errors.ErrBadEnumValue, val))
	}
}

// addReasonCriterion adds the reason criterion to the query.  values must only
// contain the valid reason names, as validated during parsing.
func addReasonCriterion(sq *searchQuery, values []string) {
	args := make([]any, 0, len(values))
	for _, v := range values {
		r, ok := filtering.ReasonByName[v]
		if !ok {
			panic(fmt.Errorf("%w: %q", errors.ErrBadEnumValue, v))
		}

		args = append(args, int(r))
	}

	sq.add("reason IN ("+placeholders(len(args))+")", args...)
}

// ftsMatchQuery builds the FTS5 MATCH expression matching any of the terms as
// a case-insensitive substring in any of the indexed columns.
func ftsMatchQuery(terms ...string) (query string) {
	quoted := make([]string, 0, len(terms))
	for _, t := range terms {
		quoted = append(quoted, `"`+strings.ReplaceAll(t, `"`, `""`)+`"`)
	}

	return strings.Join(quoted, " OR ")
}

// likePattern converts the value into a LIKE pattern matching it as a
// substring.
func likePattern(val string) (pat string) {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(val) + "%"
}

// jsonIDs encodes ids into a JSON array to be bound as the argument of the
// json_each table-valued function of the search queries.  Passing the ID lists
// as a single bound argument keeps the SQL text of the queries independent of
// the number of the IDs, so that the prepared statements stay bounded.  The
// encoding of a string slice never fails.
func jsonIDs(ids []string) (s string) {
	b, _ := json.Marshal(ids)

	return string(b)
}

// placeholders returns an SQL list of n bound-parameter placeholders, e.g.
// "?, ?, ?".
func placeholders(n int) (ph string) {
	if n <= 0 {
		return ""
	}

	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// maxRunes returns the maximum rune length of the non-empty values.
func maxRunes(vals ...string) (n int) {
	for _, v := range vals {
		if l := utf8.RuneCountInString(v); l > n {
			n = l
		}
	}

	return n
}
