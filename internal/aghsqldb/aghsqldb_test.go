package aghsqldb

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ncruces/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	// The write transactions must use BEGIN IMMEDIATE to avoid the deferred
	// lock upgrade busy errors.
	assert.Contains(t, dataPragmas, "_txlock=immediate")

	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(dbPath)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, db.Close)

	// The pool must be capped, since each connection of the pure-Go driver
	// needs its own memory sandbox.
	assert.Positive(t, db.Stats().MaxOpenConnections)
	assert.LessOrEqual(t, db.Stats().MaxOpenConnections, 4)

	// The data pragmas must be applied and the database must be usable.
	_, err = db.ExecContext(context.Background(),
		`CREATE TABLE t (v INTEGER); INSERT INTO t (v) VALUES (42)`)
	require.NoError(t, err)

	var got int
	err = db.QueryRowContext(context.Background(), `SELECT v FROM t`).Scan(&got)
	require.NoError(t, err)
	assert.Equal(t, 42, got)

	// The journal mode must be WAL.
	var journal string
	err = db.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journal)
	require.NoError(t, err)
	assert.Equal(t, "wal", journal)

	// The auto-vacuum mode must be incremental (2).  It only takes effect for
	// the databases created after the pragma is applied, so the newly created
	// database must report it.
	var autoVacuum int
	err = db.QueryRowContext(context.Background(), `PRAGMA auto_vacuum`).Scan(&autoVacuum)
	require.NoError(t, err)
	assert.Equal(t, 2, autoVacuum)
}

func TestOpen_setupConn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(dbPath, func(conn *sqlite3.Conn) (err error) {
		return errors.Error("setup error")
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, db.Close)

	// The setup failure must surface on the first query through any
	// connection.
	_, err = db.ExecContext(context.Background(), `SELECT 1`)
	require.Error(t, err)
}

func TestChmodFiles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(dbPath)
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, db.Close)

	_, err = db.ExecContext(context.Background(), `SELECT 1`)
	require.NoError(t, err)

	err = ChmodFiles(dbPath)
	require.NoError(t, err)
}

func TestIsUNCPath(t *testing.T) {
	assert.False(t, isUNCPath(""))
	assert.False(t, isUNCPath("/"))
	assert.False(t, isUNCPath("/C:/dir/test.db"))
	assert.True(t, isUNCPath("//server/share/test.db"))
	assert.True(t, isUNCPath("///server/share/test.db"))
}

func TestEnsureSchemaVersion(t *testing.T) {
	ctx := context.Background()

	newDB := func(t *testing.T) (db *sql.DB) {
		t.Helper()

		db, err := Open(filepath.Join(t.TempDir(), "test.db"))
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, db.Close)

		return db
	}

	userVersion := func(t *testing.T, db *sql.DB) (v int64) {
		t.Helper()

		require.NoError(t, db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v))

		return v
	}

	t.Run("fresh", func(t *testing.T) {
		db := newDB(t)

		err := EnsureSchemaVersion(ctx, db, 1, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(1), userVersion(t, db))
	})

	t.Run("newer", func(t *testing.T) {
		db := newDB(t)

		_, err := db.ExecContext(ctx, "PRAGMA user_version = 2")
		require.NoError(t, err)

		err = EnsureSchemaVersion(ctx, db, 1, nil)
		require.Error(t, err)
		assert.Equal(t, int64(2), userVersion(t, db))
	})

	t.Run("migrations", func(t *testing.T) {
		db := newDB(t)

		var calls []uint32
		migrations := make([]Migration, 3)
		for i := range migrations {
			i := uint32(i)
			migrations[i] = func(ctx context.Context, db *sql.DB) (err error) {
				calls = append(calls, i)

				return nil
			}
		}

		err := EnsureSchemaVersion(ctx, db, 3, migrations)
		require.NoError(t, err)
		assert.Equal(t, []uint32{0, 1, 2}, calls)
		assert.Equal(t, int64(3), userVersion(t, db))

		// A second call with the same version must not run the migrations
		// again.
		calls = nil
		err = EnsureSchemaVersion(ctx, db, 3, migrations)
		require.NoError(t, err)
		assert.Empty(t, calls)
	})

	t.Run("migration_error", func(t *testing.T) {
		db := newDB(t)

		wantErr := errors.Error("migration failed")
		migrations := []Migration{
			func(ctx context.Context, db *sql.DB) (err error) { return wantErr },
		}

		err := EnsureSchemaVersion(ctx, db, 1, migrations)
		require.ErrorIs(t, err, wantErr)
		assert.Equal(t, int64(0), userVersion(t, db))
	})
}
