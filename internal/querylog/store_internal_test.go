package querylog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDBQueryLog returns a new *queryLog with the database storage in
// baseDir and a memory buffer large enough to hold all the test entries until
// they are flushed manually.
func newTestDBQueryLog(tb testing.TB, baseDir string, confMod func(c *Config)) (l *queryLog) {
	tb.Helper()

	conf := Config{
		Logger:            testLogger,
		BaseDir:           baseDir,
		RotationIvl:       timeutil.Day,
		MemSize:           100,
		Enabled:           true,
		FileEnabled:       true,
		AnonymizeClientIP: false,
	}
	if confMod != nil {
		confMod(&conf)
	}

	l, err := newQueryLog(testutil.ContextWithTimeout(tb, testTimeout), conf)
	require.NoError(tb, err)

	tb.Cleanup(func() {
		require.NoError(tb, l.Shutdown(testutil.ContextWithTimeout(tb, testTimeout)))
	})

	return l
}

// mustPack packs msg, failing the test on error.
func mustPack(tb testing.TB, msg *dns.Msg) (data []byte) {
	tb.Helper()

	data, err := msg.Pack()
	require.NoError(tb, err)

	return data
}

// newFullTestEntry returns an entry with all the fields set.
func newFullTestEntry(tb testing.TB, ts time.Time, host string, ip net.IP) (e *logEntry) {
	q := dns.Msg{
		Question: []dns.Question{{
			Name:   host + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	a := dns.Msg{
		Question: q.Question,
		Answer: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: net.IPv4(192, 0, 2, 1),
		}},
	}

	return &logEntry{
		Time: ts,

		QHost:  host,
		QType:  "A",
		QClass: "IN",

		ReqECS: "203.0.113.0/24",

		ClientID:    "test-client-id",
		ClientProto: ClientProtoDoH,

		Upstream: "https://dns.example.org/dns-query",

		Answer:     mustPack(tb, &a),
		OrigAnswer: mustPack(tb, &a),

		IP: ip,

		Result: filtering.Result{
			DNSRewriteResult: &filtering.DNSRewriteResult{
				Response: filtering.DNSRewriteResultResponse{
					dns.TypeA: {"192.0.2.1"},
				},
			},
			ServiceName: "SomeService",
			Rules: []*filtering.ResultRule{{
				Text:         "||example.org^",
				FilterListID: 1,
			}},
			Reason:     filtering.FilteredBlockList,
			IsFiltered: true,
		},

		Elapsed: 123456789,

		Cached:            true,
		AuthenticatedData: true,
	}
}

func TestStore_SchemaVersion(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	var v int64
	err := l.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	require.NoError(t, err)
	assert.Equal(t, int64(querylogSchemaVersion), v)
}

func TestStore_EntryFidelity(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	time0 := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	e := newFullTestEntry(t, time0, "example.org", net.IPv4(203, 0, 113, 1))

	err := l.store.insertBatch(ctx, []*logEntry{e})
	require.NoError(t, err)

	params := newSearchParams()
	got, oldest, _, _ := l.search(ctx, params)
	require.Len(t, got, 1)
	assert.True(t, time0.Equal(oldest))

	g := got[0]
	assert.Nil(t, g.client)

	assert.True(t, e.Time.Equal(g.Time))
	assert.Equal(t, e.QHost, g.QHost)
	assert.Equal(t, e.QType, g.QType)
	assert.Equal(t, e.QClass, g.QClass)
	assert.Equal(t, e.ReqECS, g.ReqECS)
	assert.Equal(t, e.ClientID, g.ClientID)
	assert.Equal(t, e.ClientProto, g.ClientProto)
	assert.Equal(t, e.Upstream, g.Upstream)
	assert.Equal(t, e.IP, g.IP)
	assert.Equal(t, e.Elapsed, g.Elapsed)
	assert.Equal(t, e.Cached, g.Cached)
	assert.Equal(t, e.AuthenticatedData, g.AuthenticatedData)

	assert.Equal(t, e.Result.Reason, g.Result.Reason)
	assert.Equal(t, e.Result.IsFiltered, g.Result.IsFiltered)
	assert.Equal(t, e.Result.ServiceName, g.Result.ServiceName)
	require.Len(t, g.Result.Rules, len(e.Result.Rules))
	assert.Equal(t, e.Result.Rules[0].Text, g.Result.Rules[0].Text)
	assert.Equal(t, e.Result.Rules[0].FilterListID, g.Result.Rules[0].FilterListID)

	require.NotNil(t, g.Result.DNSRewriteResult)
	require.Len(t, g.Result.DNSRewriteResult.Response, 1)
	// The IPs of the DNS rewrite result are parsed into net.IP values.
	assert.Equal(t, net.ParseIP("192.0.2.1"), g.Result.DNSRewriteResult.Response[dns.TypeA][0])

	msg := &dns.Msg{}
	require.NoError(t, msg.Unpack(g.Answer))
	require.Len(t, msg.Answer, 1)
	assert.True(t, net.IPv4(192, 0, 2, 1).Equal(msg.Answer[0].(*dns.A).A))

	msg = &dns.Msg{}
	require.NoError(t, msg.Unpack(g.OrigAnswer))
	require.Len(t, msg.Answer, 1)
}

func TestStore_CursorPagination(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// The entries are made in pairs sharing a timestamp to make sure that the
	// keyset pagination doesn't skip the entries at a page boundary.
	const entNum = 20

	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	entries := make([]*logEntry, 0, entNum)
	for i := range entNum {
		entries = append(entries, &logEntry{
			Time:  start.Add(time.Duration(i/2) * time.Minute),
			QHost: fmt.Sprintf("host%d.example.org", i),
			QType: "A",
			// Only the entries without the question are skipped by the
			// search, so add a dummy one.
			QClass: "IN",
			IP:     testClientIPv4,
		})
	}

	err := l.store.insertBatch(ctx, entries)
	require.NoError(t, err)

	// Page through all the entries using the keyset cursor, like the frontend
	// does.
	var (
		got      []string
		oldest   time.Time
		oldestID int64
		pageSize = 6
	)

	params := newSearchParams()
	params.limit = pageSize

	for range 10 {
		var page []*logEntry
		page, oldest, oldestID, _ = l.search(ctx, params)
		require.NotEmpty(t, page)

		for _, e := range page {
			got = append(got, e.QHost)
		}

		if len(page) < pageSize {
			break
		}

		// The next page contains the entries strictly preceding the oldest
		// entry of the current page in the (time, id) order.
		params.olderThan = oldest
		params.olderThanID = oldestID
	}

	require.Len(t, got, entNum)
	for i, host := range got {
		want := fmt.Sprintf("host%d.example.org", entNum-1-i)
		assert.Equal(t, want, host)
	}
}

func TestStore_FilteringStatus(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	entries := []*logEntry{{
		Time:  start,
		QHost: "allowed.example.org",
		QType: "A",
		IP:    testClientIPv4,
		Result: filtering.Result{
			Reason:     filtering.NotFilteredAllowList,
			IsFiltered: false,
		},
	}, {
		Time:  start.Add(time.Minute),
		QHost: "blocked.example.org",
		QType: "A",
		IP:    testClientIPv4,
		Result: filtering.Result{
			Reason:     filtering.FilteredBlockList,
			IsFiltered: true,
		},
	}, {
		Time:  start.Add(2 * time.Minute),
		QHost: "rewritten.example.org",
		QType: "A",
		IP:    testClientIPv4,
		Result: filtering.Result{
			Reason:     filtering.Rewritten,
			IsFiltered: false,
		},
	}, {
		Time:  start.Add(3 * time.Minute),
		QHost: "notfound.example.org",
		QType: "A",
		IP:    testClientIPv4,
		Result: filtering.Result{
			Reason:     filtering.NotFilteredNotFound,
			IsFiltered: false,
		},
	}}

	err := l.store.insertBatch(ctx, entries)
	require.NoError(t, err)

	hosts := func(criteria ...searchCriterion) (res []string) {
		params := newSearchParams()
		params.searchCriteria = criteria

		found, _, _, _ := l.search(ctx, params)
		for _, e := range found {
			res = append(res, e.QHost)
		}

		return res
	}

	statusCrit := func(val string) (c searchCriterion) {
		return searchCriterion{
			value:         val,
			criterionType: ctFilteringStatus,
		}
	}

	testCases := []struct {
		name string
		val  string
		want []string
	}{{
		name: "all",
		val:  "all",
		want: []string{
			"notfound.example.org",
			"rewritten.example.org",
			"blocked.example.org",
			"allowed.example.org",
		},
	}, {
		name: "filtered",
		val:  "filtered",
		want: []string{"rewritten.example.org", "blocked.example.org", "allowed.example.org"},
	}, {
		name: "blocked",
		val:  "blocked",
		want: []string{"blocked.example.org"},
	}, {
		name: "whitelisted",
		val:  "whitelisted",
		want: []string{"allowed.example.org"},
	}, {
		name: "rewritten",
		val:  "rewritten",
		want: []string{"rewritten.example.org"},
	}, {
		name: "processed",
		val:  "processed",
		want: []string{"notfound.example.org", "rewritten.example.org"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hosts(statusCrit(tc.val)))
		})
	}

	t.Run("reason", func(t *testing.T) {
		got := hosts(searchReason([]string{filtering.FilteredBlockList.String()}))
		assert.Equal(t, []string{"blocked.example.org"}, got)
	})
}

func TestStore_TermSearch(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	entries := []*logEntry{{
		Time:  start,
		QHost: "example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 10),
	}, {
		Time:  start.Add(time.Minute),
		QHost: "sub.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 11),
	}, {
		Time:  start.Add(2 * time.Minute),
		QHost: "example.com",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 12),
	}, {
		Time:  start.Add(3 * time.Minute),
		QHost: "пример.рф",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 13),
	}, {
		Time:  start.Add(4 * time.Minute),
		QHost: "other.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 14),

		ClientID: "user-1",
	}}

	err := l.store.insertBatch(ctx, entries)
	require.NoError(t, err)

	hosts := func(criteria ...searchCriterion) (res []string) {
		params := newSearchParams()
		params.searchCriteria = criteria

		found, _, _, _ := l.search(ctx, params)
		for _, e := range found {
			res = append(res, e.QHost)
		}

		return res
	}

	testCases := []struct {
		name string
		val  string
		want []string
	}{{
		name: "strict_domain_case_insensitive",
		val:  `"EXAMPLE.ORG"`,
		want: []string{"example.org"},
	}, {
		name: "non-strict_domain",
		val:  "example.org",
		want: []string{"other.example.org", "sub.example.org", "example.org"},
	}, {
		name: "non-strict_domain_short_term",
		val:  "sub",
		want: []string{"sub.example.org"},
	}, {
		name: "non-strict_domain_idna",
		val:  "пример",
		want: []string{"пример.рф"},
	}, {
		name: "strict_client_ip",
		val:  `"192.0.2.10"`,
		want: []string{"example.org"},
	}, {
		name: "non-strict_client_ip_substring",
		val:  "192.0.2.1",
		want: []string{"other.example.org", "пример.рф", "example.com", "sub.example.org", "example.org"},
	}, {
		name: "strict_client_id",
		val:  `"user-1"`,
		want: []string{"other.example.org"},
	}, {
		name: "non-strict_client_id",
		val:  "user",
		want: []string{"other.example.org"},
	}, {
		name: "percent_wildcard_is_literal",
		val:  `100%`,
		want: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := parseTermCriterion(t, l, tc.val)

			assert.Equal(t, tc.want, hosts(c))
		})
	}
}

// parseTermCriterion parses a term criterion from the raw URL parameter value
// using the production parsing path.
func parseTermCriterion(tb testing.TB, l *queryLog, rawVal string) (c searchCriterion) {
	tb.Helper()

	q := url.Values{"search": []string{rawVal}}

	ok, c, err := l.parseSearchCriterion(
		testutil.ContextWithTimeout(tb, testTimeout),
		q,
		"search",
		ctTerm,
	)
	require.NoError(tb, err)
	require.True(tb, ok)

	return c
}

func TestStore_ClientNameAndIgnore(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.FindClients = func() (cs []*Client) {
			return []*Client{{
				Name: "Alice",
				IDs:  []string{"192.0.2.10", "alice-id"},
			}, {
				Name:           "Bob",
				IDs:            []string{"192.0.2.20"},
				IgnoreQueryLog: true,
			}, {
				Name: "Carol-Phone",
				IDs:  []string{"192.0.2.30"},
			}}
		}
	})
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	entries := []*logEntry{{
		Time:  start,
		QHost: "alice.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 10),
	}, {
		Time:  start.Add(time.Minute),
		QHost: "bob.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 20),
	}, {
		Time:  start.Add(2 * time.Minute),
		QHost: "carol.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 30),
	}, {
		Time:  start.Add(3 * time.Minute),
		QHost: "unknown.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 40),
	}, {
		Time:  start.Add(4 * time.Minute),
		QHost: "alice-id.example.org",
		QType: "A",
		IP:    net.IPv4(192, 0, 2, 50),

		ClientID: "alice-id",
	}}

	err := l.store.insertBatch(ctx, entries)
	require.NoError(t, err)

	hosts := func(rawTerm string) (res []string) {
		params := newSearchParams()
		params.searchCriteria = []searchCriterion{parseTermCriterion(t, l, rawTerm)}

		found, _, _, _ := l.search(ctx, params)
		for _, e := range found {
			res = append(res, e.QHost)
		}

		return res
	}

	testCases := []struct {
		name string
		term string
		want []string
	}{{
		name: "client_name_non-strict",
		term: "alice",
		want: []string{"alice-id.example.org", "alice.example.org"},
	}, {
		name: "client_name_strict",
		term: `"Carol-Phone"`,
		want: []string{"carol.example.org"},
	}, {
		name: "ignored_client_is_hidden",
		term: "example.org",
		want: []string{
			"alice-id.example.org",
			"unknown.example.org",
			"carol.example.org",
			"alice.example.org",
		},
	}, {
		name: "client_id_matched_by_name",
		term: "Alice",
		want: []string{"alice-id.example.org", "alice.example.org"},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hosts(tc.term))
		})
	}
}

func TestStore_RetentionAndClear(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.RotationIvl = 90 * time.Minute
	})
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	now := time.Now()

	err := l.store.insertBatch(ctx, []*logEntry{{
		Time:  now.Add(-2 * time.Hour),
		QHost: "old.example.org",
		QType: "A",
		IP:    testClientIPv4,
	}, {
		Time:  now.Add(-30 * time.Minute),
		QHost: "kept.example.org",
		QType: "A",
		IP:    testClientIPv4,
	}})
	require.NoError(t, err)

	// The database files must only be accessible by the owner, since the
	// entries contain the full client IP addresses.
	for _, p := range []string{"querylog.db", "querylog.db-wal", "querylog.db-shm"} {
		fi, err := os.Stat(filepath.Join(l.conf.BaseDir, p))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, aghos.DefaultPermFile, fi.Mode().Perm(), p)
	}

	l.deleteOldEntries(ctx)

	params := newSearchParams()
	found, _, _, _ := l.search(ctx, params)
	require.Len(t, found, 1)
	assert.Equal(t, "kept.example.org", found[0].QHost)

	// The FTS index must stay consistent after the delete.
	params.searchCriteria = []searchCriterion{{
		value:         "old.example",
		criterionType: ctTerm,
	}}
	found, _, _, _ = l.search(ctx, params)
	assert.Empty(t, found)

	params.searchCriteria = []searchCriterion{{
		value:         "kept.example",
		criterionType: ctTerm,
	}}
	found, _, _, _ = l.search(ctx, params)
	require.Len(t, found, 1)

	require.NoError(t, l.clear(ctx))

	params.searchCriteria = nil
	found, _, _, _ = l.search(ctx, params)
	assert.Empty(t, found)
}

func TestStore_RetentionAndClearBatched(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.RotationIvl = 90 * time.Minute
	})
	ctx := testutil.ContextWithTimeout(t, time.Minute)

	now := time.Now()

	// Use more entries than a single delete batch to exercise the chunked
	// deletion, which must keep the FTS index in sync.
	const (
		oldNum = deleteChunkSize + 10
		newNum = deleteChunkSize/2 + 7
	)

	entries := make([]*logEntry, 0, oldNum+newNum)
	for i := range oldNum {
		entries = append(entries, &logEntry{
			Time:  now.Add(-2 * time.Hour),
			QHost: fmt.Sprintf("old%d.example.org", i),
			QType: "A",
			IP:    testClientIPv4,
		})
	}

	for i := range newNum {
		entries = append(entries, &logEntry{
			Time:  now.Add(-30 * time.Minute),
			QHost: fmt.Sprintf("kept%d.example.org", i),
			QType: "A",
			IP:    testClientIPv4,
		})
	}

	require.NoError(t, l.store.insertBatch(ctx, entries))

	n, err := l.store.deleteOlderThan(ctx, now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(oldNum), n)

	// All the kept entries and none of the removed ones must remain.
	params := newSearchParams()
	params.limit = oldNum + newNum
	found, _, _, err := l.search(ctx, params)
	require.NoError(t, err)
	require.Len(t, found, newNum)

	// The FTS index must stay consistent after the batched delete.
	params = newSearchParams()
	params.limit = oldNum + newNum
	params.searchCriteria = []searchCriterion{{
		value:         "old.example",
		criterionType: ctTerm,
	}}
	found, _, _, err = l.search(ctx, params)
	require.NoError(t, err)
	assert.Empty(t, found)

	// Clear must remove the rest in batches as well.
	require.NoError(t, l.clear(ctx))

	params = newSearchParams()
	params.limit = oldNum + newNum
	found, _, _, err = l.search(ctx, params)
	require.NoError(t, err)
	assert.Empty(t, found)
}

func TestQueryLog_MemoryOnlyLimit(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.FileEnabled = false
		c.MemSize = 10
	})
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	for i := range 5 {
		addTestEntry(
			l,
			fmt.Sprintf("host%d.example.org", i),
			testAnswerIPv4,
			testClientIPv4,
			filtering.Rewritten,
		)
	}

	params := newSearchParams()
	params.limit = 3

	found, _, _, err := l.search(ctx, params)
	require.NoError(t, err)
	assert.Len(t, found, params.limit)
}

func TestQueryLog_SearchDBError(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), nil)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Close the database behind the store to force a search failure.
	require.NoError(t, l.store.db.Close())

	_, _, _, err := l.search(ctx, newSearchParams())
	require.Error(t, err)
}

func TestQueryLog_ConcurrentAddSearch(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		// Make the buffer large enough to hold all the entries until they
		// are flushed, so that none of them is evicted.
		c.MemSize = 1000
	})
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Trigger the search before the concurrent part to make sure the lazy
	// initialization, if any, is done.
	_, _, _, _ = l.search(ctx, newSearchParams())

	const (
		goroutineNum = 4
		entNum       = 50
	)

	wg := &sync.WaitGroup{}
	wg.Add(goroutineNum)
	for i := range goroutineNum {
		go func() {
			defer wg.Done()

			for range entNum {
				l.Add(&AddParams{
					Question: &dns.Msg{
						Question: []dns.Question{{
							Name:  fmt.Sprintf("host%d.example.org", i),
							Qtype: dns.TypeA,
						}},
					},
					ClientIP: testClientIPv4,
					Result:   &filtering.Result{},
				})
			}
		}()
	}

	for range 10 {
		params := newSearchParams()
		params.limit = 10

		entries, _, _, _ := l.search(ctx, params)
		assert.LessOrEqual(t, len(entries), 10)
	}

	wg.Wait()

	require.NoError(t, l.flushLogBuffer(ctx))

	params := newSearchParams()
	params.limit = goroutineNum * entNum
	entries, _, _, _ := l.search(ctx, params)
	assert.Len(t, entries, goroutineNum*entNum)
}

func TestFTSMatchQuery(t *testing.T) {
	testCases := []struct {
		terms []string
		want  string
	}{{
		terms: []string{"example.org"},
		want:  `"example.org"`,
	}, {
		terms: []string{`ex"ample`},
		want:  `"ex""ample"`,
	}, {
		terms: []string{"пример", "xn--e1afmkfd"},
		want:  `"пример" OR "xn--e1afmkfd"`,
	}}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, ftsMatchQuery(tc.terms...))
		})
	}
}

func TestLikePattern(t *testing.T) {
	assert.Equal(t, "%100\\%%", likePattern("100%"))
	assert.Equal(t, "%a\\_b%", likePattern("a_b"))
	assert.Equal(t, "%a\\\\b%", likePattern(`a\b`))
}

func BenchmarkSearch(b *testing.B) {
	l := newTestDBQueryLog(b, b.TempDir(), func(c *Config) {
		c.MemSize = 10000
	})

	// The default test timeout is too short for preparing a large database.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const entNum = 100_000

	entries := make([]*logEntry, 0, entNum)
	base := time.Now().Add(-time.Duration(entNum) * time.Second)
	for i := range entNum {
		entries = append(entries, &logEntry{
			Time:  base.Add(time.Duration(i) * time.Second),
			QHost: fmt.Sprintf("host%d.example.org", i%1000),
			QType: "A",
			IP:    net.IPv4(192, 0, 2, byte(i%253)+1),
			Result: filtering.Result{
				Reason:     filtering.Reason(i % 12),
				IsFiltered: i%2 == 0,
			},
		})
	}

	err := l.store.insertBatch(ctx, entries)
	require.NoError(b, err)

	termCrit := func(val string, strict bool) searchCriterion {
		return searchCriterion{
			value:         val,
			criterionType: ctTerm,
			strict:        strict,
		}
	}

	benchCases := []struct {
		name string
		want func(p *searchParams)
	}{{
		name: "latest",
		want: func(_ *searchParams) {},
	}, {
		name: "domain_strict",
		want: func(p *searchParams) {
			p.searchCriteria = []searchCriterion{termCrit("host500.example.org", true)}
		},
	}, {
		name: "domain_fts",
		want: func(p *searchParams) {
			p.searchCriteria = []searchCriterion{termCrit("host500", false)}
		},
	}, {
		name: "reason",
		want: func(p *searchParams) {
			p.searchCriteria = []searchCriterion{searchReason([]string{
				filtering.FilteredBlockList.String(),
			})}
		},
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				params := newSearchParams()
				params.limit = 500
				bc.want(params)

				entries, _, _, _ := l.search(ctx, params)
				if len(entries) == 0 {
					b.Fatal("no entries found")
				}
			}
		})
	}
}

func TestSearchMemoryWithCriteria(t *testing.T) {
	l := newTestDBQueryLog(t, t.TempDir(), func(c *Config) {
		c.FileEnabled = false
		c.MemSize = 10
	})
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	addTestEntry(l, "example.org", testAnswerIPv4, testClientIPv4, filtering.Rewritten)
	addTestEntry(l, "blocked.example.org", testAnswerIPv4, testClientIPv4, filtering.FilteredBlockList)

	params := newSearchParams()
	params.searchCriteria = []searchCriterion{{
		value:         "blocked",
		criterionType: ctTerm,
	}}

	entries, _, _, _ := l.search(ctx, params)
	require.Len(t, entries, 1)
	assert.Equal(t, "blocked.example.org", entries[0].QHost)
}
