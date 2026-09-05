package aghsqldb

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/ncruces/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
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
