// Package aghsqldb provides helpers shared by the SQLite-backed storages of
// AdGuard Home.
package aghsqldb

import (
	"database/sql"
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
//   - journal_mode(WAL) allows reading while writing;
//   - synchronous(NORMAL) is the recommended synchronous setting for WAL,
//     since it doesn't fsync on each commit;
//   - auto_vacuum(INCREMENTAL) allows reclaiming the space of the deleted
//     entries without rewriting the whole database;
//   - temp_store(MEMORY) keeps the temporary tables and indices off the disk.
const dataPragmas = "_pragma=busy_timeout(10000)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=temp_store(MEMORY)" +
	"&_pragma=auto_vacuum(INCREMENTAL)"

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
