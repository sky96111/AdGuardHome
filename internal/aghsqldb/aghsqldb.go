// Package aghsqldb provides helpers shared by the SQLite-backed storages of
// AdGuard Home.
package aghsqldb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

// dataPragmas are the URL query parameters setting the PRAGMA statements
// suitable for the AdGuard Home database workloads:
//
//   - busy_timeout(10000) makes the writers wait for the lock instead of
//     failing immediately;
//   - auto_vacuum(INCREMENTAL) allows reclaiming the space of the deleted
//     entries without rewriting the whole database.  It must come before
//     journal_mode(WAL), because switching to WAL initializes the database
//     header and makes later auto_vacuum changes ineffective for new
//     databases;
//   - journal_mode(WAL) allows reading while writing;
//   - synchronous(NORMAL) is the recommended synchronous setting for WAL,
//     since it doesn't fsync on each commit;
//   - temp_store(MEMORY) keeps the temporary tables and indices off the disk.
//
// The _txlock query parameter makes the driver begin the write transactions
// with BEGIN IMMEDIATE, so that concurrent writers wait for the write lock up
// to busy_timeout instead of failing with SQLITE_BUSY when a deferred
// transaction is upgraded.
const dataPragmas = "_pragma=busy_timeout(10000)" +
	"&_pragma=auto_vacuum(INCREMENTAL)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=temp_store(MEMORY)" +
	"&_txlock=immediate"

// Open opens the SQLite database at dbPath, creating it if necessary, using
// the pure-Go driver with the [dataPragmas].  setupConn, if any, is invoked
// for every opened connection, e.g. to register the extensions.
func Open(dbPath string, setupConn ...func(conn *sqlite3.Conn) (err error)) (db *sql.DB, err error) {
	defer func() { err = errors.Annotate(err, "opening sqlite db: %w") }()

	u := &url.URL{
		Scheme:   "file",
		Path:     uriPath(dbPath),
		RawQuery: dataPragmas,
	}

	db, err = driver.Open(u.String(), setupConn...)
	if err != nil {
		return nil, err
	}

	// Each connection of the pure-Go driver needs its own memory sandbox,
	// which is especially scarce on 32-bit platforms, so cap the pool.
	n := maxOpenConns()
	db.SetMaxOpenConns(n)
	db.SetMaxIdleConns(n)

	return db, nil
}

// uriPath converts the platform-specific file path into the path component of
// an SQLite URI filename.
func uriPath(dbPath string) (p string) {
	p = filepath.ToSlash(dbPath)
	if runtime.GOOS != "windows" || !filepath.IsAbs(dbPath) {
		return p
	}

	if !isUNCPath(p) {
		// "C:\dir\file.db" -> "/C:/dir/file.db", which is the form SQLite
		// expects in URI filenames.
		p = "/" + p
	}

	// A UNC path is kept as "//server/share/file.db"; [*url.URL.String] adds
	// the empty authority to it, producing the "file:////server/share/file.db"
	// form documented by SQLite.

	return p
}

// isUNCPath returns true if the slash-separated absolute path is a UNC path,
// e.g. "//server/share/file.db".
func isUNCPath(p string) (ok bool) {
	return len(p) > 1 && p[0] == '/' && p[1] == '/'
}

// maxOpenConns returns the database connection pool size.
func maxOpenConns() (n int) {
	switch runtime.GOARCH {
	case "386", "arm", "mips", "mipsle":
		return 2
	default:
		return 4
	}
}

// ChmodFiles makes sure the database files are only accessible by the owner.
// SQLite creates the files with the mode of 0666 masked by the process umask.
func ChmodFiles(dbPath string) (err error) {
	defer func() { err = errors.Annotate(err, "setting db file permissions: %w") }()

	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		err = os.Chmod(p, aghos.DefaultPermFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// Migration is a single schema migration of the database from the version
// equal to its index to the next one.
type Migration func(ctx context.Context, db *sql.DB) (err error)

// EnsureSchemaVersion ensures that the schema version of the database is want,
// using [PRAGMA user_version] as the version source.  migrations[i] migrates
// the schema from version i to version i+1; a nil entry means that the step
// requires no changes.  It returns an error if the database schema is newer
// than want, so that an old binary never silently operates on a newer
// database.
func EnsureSchemaVersion(
	ctx context.Context,
	db *sql.DB,
	want uint32,
	migrations []Migration,
) (err error) {
	defer func() { err = errors.Annotate(err, "ensuring schema version: %w") }()

	var got int64
	err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&got)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	if got < 0 {
		return fmt.Errorf("invalid schema version %d", got)
	}

	if uint64(got) > uint64(want) {
		return fmt.Errorf(
			"database schema version %d is newer than supported version %d",
			got,
			want,
		)
	}

	for v := uint32(got); v < want; v++ {
		i := int(v)
		if i < len(migrations) && migrations[i] != nil {
			err = migrations[i](ctx, db)
			if err != nil {
				return fmt.Errorf("migrating from version %d: %w", v, err)
			}
		}
	}

	// The pragma value can't be bound as a parameter, but want is an unsigned
	// integer, so it's safe to format it into the statement.
	_, err = db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", want))
	if err != nil {
		return fmt.Errorf("writing schema version: %w", err)
	}

	return nil
}
