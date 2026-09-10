package querylog

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/stringutil"
)

// client finds the client info, if any, by its ClientID and IP address,
// optionally checking the provided cache.  It will use the IP address
// regardless of if the IP anonymization is enabled now, because the
// anonymization could have been disabled in the past, and client will try to
// find those records as well.
func (l *queryLog) client(clientID, ip string, cache clientCache) (c *Client, err error) {
	cck := clientCacheKey{clientID: clientID, ip: ip}

	var ok bool
	if c, ok = cache[cck]; ok {
		return c, nil
	}

	var ids []string
	if clientID != "" {
		ids = append(ids, clientID)
	}

	if ip != "" {
		ids = append(ids, ip)
	}

	c, err = l.findClient(ids)
	if err != nil {
		return nil, err
	}

	// Cache all results, including negative ones, to prevent excessive and
	// expensive client searching.
	cache[cck] = c

	return c, nil
}

// searchMemory looks up log records which are currently in the in-memory
// buffer.  It optionally uses the client cache, if provided.  It also returns
// the total amount of records in the buffer at the moment of searching.
// l.confMu is expected to be locked.
func (l *queryLog) searchMemory(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, total int) {
	// Check memory size, as the buffer can contain a single log record.  See
	// [newQueryLog].
	if l.conf.MemSize == 0 {
		return nil, 0
	}

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.ReverseRange(func(entry *logEntry) (cont bool) {
		// A shallow clone is enough, since the only thing that this loop
		// modifies is the client field.
		e := entry.shallowClone()

		var err error
		e.client, err = l.client(e.ClientID, e.IP.String(), cache)
		if err != nil {
			l.logger.ErrorContext(
				ctx,
				"enriching memory record",
				"at", e.Time,
				"client_ip", e.IP,
				"client_id", e.ClientID,
				slogutil.KeyError, err,
			)

			// Go on and try to match anyway.
		}

		if params.match(e) {
			entries = append(entries, e)
		}

		return true
	})

	return entries, int(l.buffer.Len())
}

// search searches log entries in the database, or in the memory buffer if the
// query log works in the memory-only mode, using the specified parameters and
// returns the list of the entries found, the time of the oldest returned
// entry, and its database row ID, which is zero in the memory-only mode.
// l.confMu is expected to be locked.
func (l *queryLog) search(
	ctx context.Context,
	params *searchParams,
) (entries []*logEntry, oldest time.Time, oldestID int64, err error) {
	start := time.Now()

	if params.limit == 0 {
		return []*logEntry{}, time.Time{}, 0, nil
	}

	if l.store == nil {
		cache := clientCache{}

		memoryEntries, _ := l.searchMemory(ctx, params, cache)
		entries, oldest = l.finalizeSearchResults(memoryEntries, params, time.Time{})
	} else {
		// Make sure that all the buffered entries are in the store, so that
		// the search covers them as well.  A flush failure is logged but not
		// fatal, since the search may still return the persisted entries.
		flushErr := l.flushLogBuffer(ctx)
		if flushErr != nil {
			l.logger.ErrorContext(ctx, "flushing buffer before search", slogutil.KeyError, flushErr)
		}

		entries, oldest, oldestID, err = l.searchStore(ctx, params)
		if err != nil {
			return nil, time.Time{}, 0, err
		}
	}

	l.logger.DebugContext(
		ctx,
		"prepared data",
		"count", len(entries),
		"older_than", params.olderThan,
		"elapsed", time.Since(start),
	)

	return entries, oldest, oldestID, nil
}

// searchStore searches the database using the specified parameters.  The
// returned entries are enriched with the client information.
func (l *queryLog) searchStore(
	ctx context.Context,
	params *searchParams,
) (entries []*logEntry, oldest time.Time, oldestID int64, err error) {
	term, strict := searchTerm(params)
	lists := l.clientIDLists(ctx, term, strict)

	sq := buildSearchQuery(params, lists)

	entries, err = l.store.search(ctx, sq, params.limit, params.offset)
	if err != nil {
		return nil, time.Time{}, 0, err
	}

	cache := clientCache{}
	for _, e := range entries {
		e.client, err = l.client(e.ClientID, e.IP.String(), cache)
		if err != nil {
			l.logger.ErrorContext(
				ctx,
				"enriching record",
				"at", e.Time,
				"client_ip", e.IP,
				"client_id", e.ClientID,
				slogutil.KeyError, err,
			)

			// Go on anyway.
		}
	}

	if len(entries) > 0 {
		oldest = entries[len(entries)-1].Time
		oldestID = entries[len(entries)-1].id
	}

	return entries, oldest, oldestID, nil
}

// finalizeSearchResults sorts entries and applies offset and limit trimming,
// and updates the oldest timestamp.  params must not be nil.
func (l *queryLog) finalizeSearchResults(
	entries []*logEntry,
	params *searchParams,
	oldest time.Time,
) (res []*logEntry, t time.Time) {
	// Resort entries on start time to partially mitigate query log looking
	// weird on the frontend.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2293.
	slices.SortStableFunc(entries, func(a, b *logEntry) (res int) {
		return -a.Time.Compare(b.Time)
	})

	if params.offset > 0 {
		if len(entries) > params.offset {
			entries = entries[params.offset:]
		} else {
			return nil, time.Time{}
		}
	}

	// The database path already applies the LIMIT clause, while the
	// memory-only path must trim the entries here.
	if params.limit > 0 && len(entries) > params.limit {
		entries = entries[:params.limit]
	}

	if len(entries) > 0 {
		// Update oldest after merging in the memory buffer.
		oldest = entries[len(entries)-1].Time
	}

	return entries, oldest
}

// searchTerm returns the free-text search term of the parameters, if any,
// along with its strictness.
func searchTerm(params *searchParams) (term string, strict bool) {
	for _, c := range params.searchCriteria {
		if c.criterionType == ctTerm {
			return c.value, c.strict
		}
	}

	return "", false
}

// clientIDLists contains the client IDs used to push the client-name search
// criterion and the per-client ignore settings down to the database.
type clientIDLists struct {
	// byName contains the IDs of the clients whose names match the free-text
	// search term of the search, if any.
	byName []string

	// ignored contains the IDs of the clients that must not be logged.
	ignored []string
}

// clientIDLists resolves the client IDs used to push the client-name search
// criterion and the per-client ignore settings down to the database.  term may
// be empty, in which case byName is empty.
func (l *queryLog) clientIDLists(ctx context.Context, term string, strict bool) (lists clientIDLists) {
	if l.findClients == nil {
		return clientIDLists{}
	}

	for _, c := range l.findClients() {
		if c.IgnoreQueryLog {
			lists.ignored = append(lists.ignored, nonEmptyIDs(c)...)
		}

		if term != "" && nameMatchesTerm(c.Name, term, strict) {
			lists.byName = append(lists.byName, nonEmptyIDs(c)...)
		}
	}

	return lists
}

// nameMatchesTerm returns true if the client name matches the search term.
func nameMatchesTerm(name, term string, strict bool) (ok bool) {
	if strict {
		return strings.EqualFold(name, term)
	}

	return stringutil.ContainsFold(name, term)
}

// nonEmptyIDs returns the non-empty identifiers of the client.
func nonEmptyIDs(c *Client) (ids []string) {
	for _, id := range c.IDs {
		if id != "" {
			ids = append(ids, id)
		}
	}

	return ids
}
