// Package querylog provides query log functions and interfaces.
package querylog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
)

// queryLog is a structure that writes and reads the DNS query log.
type queryLog struct {
	// logger is used for logging the operation of the query log.  It must not
	// be nil.
	logger *slog.Logger

	// confMu protects conf.
	confMu *sync.RWMutex

	conf       *Config
	anonymizer *aghnet.IPMut

	findClient func(ids []string) (c *Client, err error)

	// findClients returns information about all the known clients, if any.
	// It is used to push the client-name search criteria and the per-client
	// ignore settings down to the database.
	findClients func() (cs []*Client)

	// buffer contains recent log entries.  The entries in this buffer must not
	// be modified.
	buffer *container.RingBuffer[*logEntry]

	// bufferSize is the capacity of buffer.  It's kept separately, because the
	// ring buffer implementation doesn't expose it.
	bufferSize uint

	// store is the SQLite-backed storage of the query log.  It is nil if the
	// query log works in the memory-only mode, i.e. FileEnabled is false.
	store *store

	// bufferLock protects buffer.
	bufferLock sync.RWMutex

	// flushLock synchronizes a flushing goroutine with searching and
	// clearing.
	flushLock sync.Mutex

	// retentionWG tracks the periodic-retention goroutine, so that Shutdown
	// waits for it to exit before closing the store.
	retentionWG sync.WaitGroup

	// flushCtx is the context of the periodic-retention goroutine.  It's
	// created in Start and canceled in Shutdown.
	flushCtx context.Context

	// flushCancel cancels flushCtx.
	flushCancel context.CancelFunc

	flushPending bool
}

// ClientProto values are names of the client protocols.
type ClientProto string

// Client protocol names.
const (
	ClientProtoDoH      ClientProto = "doh"
	ClientProtoDoQ      ClientProto = "doq"
	ClientProtoDoT      ClientProto = "dot"
	ClientProtoDNSCrypt ClientProto = "dnscrypt"
	ClientProtoPlain    ClientProto = ""
)

// NewClientProto validates that the client protocol name is valid and returns
// the name as a ClientProto.
func NewClientProto(s string) (cp ClientProto, err error) {
	switch cp = ClientProto(s); cp {
	case
		ClientProtoDoH,
		ClientProtoDoQ,
		ClientProtoDoT,
		ClientProtoDNSCrypt,
		ClientProtoPlain:

		return cp, nil
	default:
		return "", fmt.Errorf("invalid client proto: %q", s)
	}
}

// type check
var _ QueryLog = (*queryLog)(nil)

// Start implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Start(ctx context.Context) (err error) {
	if l.conf.HTTPReg != nil {
		l.initWeb()
	}

	l.flushCtx, l.flushCancel = context.WithCancel(ctx)

	l.retentionWG.Add(1)
	go l.periodicRetention(l.flushCtx)

	return nil
}

// Shutdown implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Shutdown(ctx context.Context) (err error) {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	// Stop the periodic-retention goroutine and wait for it, so that it
	// doesn't race with the store closure.
	if l.flushCancel != nil {
		l.flushCancel()
	}
	l.retentionWG.Wait()

	if l.store == nil {
		return nil
	}

	// The store must be closed even if the final flush fails, to perform the
	// WAL checkpoint and release the resources.
	defer func() {
		cerr := l.store.Close(ctx)
		err = errors.WithDeferred(err, cerr)
	}()

	err = l.flushLogBuffer(ctx)

	return err
}

func checkInterval(ivl time.Duration) (ok bool) {
	// The constants for possible values of query log's rotation interval.
	const (
		quarterDay  = timeutil.Day / 4
		day         = timeutil.Day
		week        = timeutil.Day * 7
		month       = timeutil.Day * 30
		threeMonths = timeutil.Day * 90
	)

	return ivl == quarterDay || ivl == day || ivl == week || ivl == month || ivl == threeMonths
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

// WriteDiskConfig implements the [QueryLog] interface for *queryLog.
func (l *queryLog) WriteDiskConfig(c *Config) {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	*c = *l.conf
}

// newLogEntry creates an instance of logEntry from parameters.
func newLogEntry(ctx context.Context, logger *slog.Logger, params *AddParams) (entry *logEntry) {
	q := params.Question.Question[0]
	qHost := aghnet.NormalizeDomain(q.Name)

	entry = &logEntry{
		// TODO(d.kolyshev): Export this timestamp to func params.
		Time:   time.Now(),
		QHost:  qHost,
		QType:  dns.Type(q.Qtype).String(),
		QClass: dns.Class(q.Qclass).String(),

		ClientID:    params.ClientID,
		ClientProto: params.ClientProto,

		Result:   *params.Result,
		Upstream: params.Upstream,

		IP: params.ClientIP,

		Elapsed: params.Elapsed,

		Cached:            params.Cached,
		AuthenticatedData: params.AuthenticatedData,
	}

	if params.ReqECS != nil {
		entry.ReqECS = params.ReqECS.String()
	}

	entry.addResponse(ctx, logger, params.Answer, false)
	entry.addResponse(ctx, logger, params.OrigAnswer, true)

	return entry
}

// Add implements the [QueryLog] interface for *queryLog.
func (l *queryLog) Add(params *AddParams) {
	var isEnabled, fileIsEnabled bool
	var memSize uint
	func() {
		l.confMu.RLock()
		defer l.confMu.RUnlock()

		isEnabled, fileIsEnabled = l.conf.Enabled, l.conf.FileEnabled
		memSize = l.conf.MemSize
	}()

	if !isEnabled {
		return
	}

	// TODO(s.chzhen):  Pass context.
	ctx := context.TODO()

	err := params.validate()
	if err != nil {
		l.logger.ErrorContext(ctx, "adding record", slogutil.KeyError, err)

		return
	}

	if params.Result == nil {
		params.Result = &filtering.Result{}
	}

	entry := newLogEntry(ctx, l.logger, params)

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.Push(entry)

	if !l.flushPending && fileIsEnabled && l.buffer.Len() >= memSize {
		l.flushPending = true

		// TODO(s.chzhen):  Fix occasional rewrite of entires.
		go func() {
			flushErr := l.flushLogBuffer(ctx)
			if flushErr != nil {
				l.logger.ErrorContext(ctx, "flushing after adding", slogutil.KeyError, flushErr)
			}
		}()
	}
}

// ShouldLog returns true if request for the host should be logged.
func (l *queryLog) ShouldLog(host string, _, _ uint16, ids []string) bool {
	l.confMu.RLock()
	defer l.confMu.RUnlock()

	c, err := l.findClient(ids)
	if err != nil {
		// TODO(s.chzhen):  Pass context.
		l.logger.ErrorContext(context.TODO(), "finding client", slogutil.KeyError, err)
	}

	if c != nil && c.IgnoreQueryLog {
		return false
	}

	return !l.isIgnored(host)
}

// isIgnored returns true if the host is in the ignored domains list.  It
// assumes that l.confMu is locked for reading.
func (l *queryLog) isIgnored(host string) bool {
	return l.conf.Ignored.Has(host)
}
