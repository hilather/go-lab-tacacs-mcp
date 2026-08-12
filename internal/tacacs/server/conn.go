package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
)

type packet struct {
	hdr  codec.Header
	body []byte
}

type outgoing struct {
	hdr      codec.Header
	body     []byte
	terminal bool
}

type session struct {
	id    uint32
	typ   byte
	seq   *codec.Sequence
	in    chan packet
	done  chan struct{}
	close sync.Once
}

var connSeq atomic.Uint64

type connState struct {
	pio      PacketIO
	id       Identity
	lim      Limits
	h        Handler
	connKey  uint64
	sc       codec.SingleConnect
	sessions map[uint32]*session
	mu       sync.Mutex
	writeMu  sync.Mutex
	drain    atomic.Bool
	closed   atomic.Bool
	started  time.Time
	lastAct  atomic.Int64
	wg       sync.WaitGroup
}

// ServeConn reads packets from pio, demultiplexes by session ID, and writes
// replies. The first request/reply pair negotiates single-connect; later
// flag bits are ignored. If single-connect is not established the TCP
// session is closed after the first TACACS session completes.
func ServeConn(ctx context.Context, pio PacketIO, id Identity, lim Limits, h Handler) error {
	if pio == nil {
		return errors.New("packet io is required")
	}
	if h == nil {
		h = Stub{}
	}
	lim = lim.normalized()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer pio.Close()

	cs := &connState{
		pio:      pio,
		id:       id,
		lim:      lim,
		h:        h,
		connKey:  connSeq.Add(1),
		sessions: make(map[uint32]*session),
		started:  time.Now(),
	}
	cs.lastAct.Store(time.Now().UnixNano())
	defer cs.shutdownSessions(lim.ShutdownGrace)
	return cs.readLoop(ctx)
}

func (cs *connState) readLoop(ctx context.Context) error {
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cs.lim.MaxLifetime > 0 && time.Since(cs.started) >= cs.lim.MaxLifetime {
			return nil
		}
		if cs.drain.Load() && cs.sessionCount() == 0 {
			return nil
		}

		hdr, body, err := cs.pio.Read(ctx, cs.lim.MaxPacketBodyBytes, cs.readDeadline(first))
		if err != nil {
			cont, herr := cs.handleReadError(ctx, hdr, err)
			first = false
			if !cont {
				return herr
			}
			if cs.shouldClose() {
				return nil
			}
			continue
		}
		cs.lastAct.Store(time.Now().UnixNano())

		if err := cs.handlePacket(ctx, hdr, body, first); err != nil {
			return err
		}
		first = false

		if cs.shouldClose() {
			return nil
		}
	}
}

func (cs *connState) shouldClose() bool {
	if cs.sc.Pending() {
		return false
	}
	if !cs.sc.Negotiated() && cs.sessionCount() == 0 {
		return true
	}
	return cs.drain.Load() && cs.sessionCount() == 0
}

func (cs *connState) readDeadline(first bool) time.Time {
	now := time.Now()
	dl := now.Add(cs.lim.ReadTimeout)
	if first {
		hs := now.Add(cs.lim.HandshakeTimeout)
		if hs.Before(dl) {
			dl = hs
		}
		return dl
	}
	last := time.Unix(0, cs.lastAct.Load())
	idle := last.Add(cs.lim.IdleTimeout)
	if idle.Before(dl) {
		dl = idle
	}
	if cs.lim.MaxLifetime > 0 {
		life := cs.started.Add(cs.lim.MaxLifetime)
		if life.Before(dl) {
			dl = life
		}
	}
	return dl
}

func (cs *connState) handleReadError(ctx context.Context, hdr codec.Header, err error) (cont bool, out error) {
	switch {
	case errors.Is(err, ErrUnencrypted):
		cs.replyError(ctx, hdr)
		cs.drain.Store(true)
		return true, nil
	case errors.Is(err, codec.ErrBodyTooLarge):
		if hdr.KnownType() {
			cs.replyError(ctx, hdr)
		}
		cs.drain.Store(true)
		return false, err
	default:
		return false, err
	}
}

func (cs *connState) handlePacket(ctx context.Context, hdr codec.Header, body []byte, first bool) error {
	if first {
		cs.sc.OnClientFirst(hdr.Flags)
	}
	if !hdr.KnownType() {
		reply, err := hdr.UnknownTypeReply()
		if err != nil {
			cs.drain.Store(true)
			return err
		}
		if !cs.sc.Complete() && first {
			cs.sc.OnServerFirst(reply.Flags)
		}
		_ = cs.write(ctx, reply, nil)
		cs.drain.Store(true)
		return nil
	}
	if err := hdr.Validate(); err != nil {
		cs.replyError(ctx, hdr)
		cs.drain.Store(true)
		return nil
	}

	cs.mu.Lock()
	sess, existing := cs.sessions[hdr.SessionID]
	cs.mu.Unlock()
	if existing {
		if sess.typ != hdr.Type {
			cs.replyError(ctx, hdr)
			cs.dropSession(sess)
			return nil
		}
		if !sess.offer(ctx, packet{hdr: hdr, body: body}) {
			cs.replyError(ctx, hdr)
		}
		return nil
	}

	if cs.drain.Load() {
		cs.replyError(ctx, hdr)
		return nil
	}
	// The first session is the negotiation pair; later sessions must wait.
	if !first {
		if err := cs.sc.AllowNewSession(); err != nil {
			cs.replyError(ctx, hdr)
			return nil
		}
	}
	if cs.sessionCount() >= cs.lim.MaxSessionsPerConnection {
		cs.replyError(ctx, hdr)
		return nil
	}

	sess = newSession(hdr.SessionID, hdr.Type)
	cs.mu.Lock()
	cs.sessions[hdr.SessionID] = sess
	cs.mu.Unlock()

	if first {
		return cs.processFirst(ctx, sess, hdr, body)
	}

	cs.wg.Add(1)
	go cs.runSession(ctx, sess)
	if !sess.offer(ctx, packet{hdr: hdr, body: body}) {
		cs.replyError(ctx, hdr)
		cs.dropSession(sess)
	}
	return nil
}

func newSession(id uint32, typ byte) *session {
	return &session{
		id:   id,
		typ:  typ,
		seq:  codec.NewSequence(id, typ),
		in:   make(chan packet, 1),
		done: make(chan struct{}),
	}
}

func (s *session) offer(ctx context.Context, p packet) bool {
	select {
	case <-ctx.Done():
		return false
	case <-s.done:
		return false
	case s.in <- p:
		return true
	default:
		return false
	}
}

func (s *session) stop() {
	s.close.Do(func() {
		close(s.done)
		s.seq.Close()
	})
}

func (cs *connState) processFirst(ctx context.Context, sess *session, hdr codec.Header, body []byte) error {
	out, err := cs.dispatch(ctx, sess, hdr, body)
	if err != nil {
		if errors.Is(err, ErrSecretMismatch) {
			cs.replyError(ctx, hdr)
			cs.drain.Store(true)
			cs.dropSession(sess)
			return ErrSecretMismatch
		}
		cs.replyError(ctx, hdr)
		cs.dropSession(sess)
		return nil
	}
	out.hdr.Flags = cs.negotiateFlags()
	if err := cs.write(ctx, out.hdr, out.body); err != nil {
		cs.dropSession(sess)
		return err
	}
	if out.terminal || sess.seq.Closed() {
		cs.dropSession(sess)
		return nil
	}
	cs.wg.Add(1)
	go cs.runSession(ctx, sess)
	return nil
}

func (cs *connState) runSession(ctx context.Context, sess *session) {
	defer cs.wg.Done()
	defer cs.dropSession(sess)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.done:
			return
		case pkt, ok := <-sess.in:
			if !ok {
				return
			}
			out, err := cs.dispatch(ctx, sess, pkt.hdr, pkt.body)
			if err != nil {
				if errors.Is(err, ErrSecretMismatch) {
					cs.replyError(ctx, pkt.hdr)
					cs.drain.Store(true)
					return
				}
				cs.replyError(ctx, pkt.hdr)
				return
			}
			if err := cs.write(ctx, out.hdr, out.body); err != nil {
				return
			}
			if out.terminal || sess.seq.Closed() {
				return
			}
		}
	}
}

func (cs *connState) negotiateFlags() byte {
	var flags byte
	if cs.lim.SingleConnectEnabled {
		flags = codec.FlagSingleConnect
	}
	cs.sc.OnServerFirst(flags)
	if cs.sc.Negotiated() {
		return codec.FlagSingleConnect
	}
	return 0
}

func (cs *connState) dispatch(ctx context.Context, sess *session, hdr codec.Header, body []byte) (outgoing, error) {
	if err := sess.seq.CheckRequest(hdr); err != nil {
		return outgoing{}, err
	}
	rh, err := sess.seq.NextReply(0)
	if err != nil {
		return outgoing{}, err
	}
	rh.Version = hdr.Version
	rh.Flags = 0

	env := Env{Identity: cs.id, SessionID: hdr.SessionID, ConnKey: cs.connKey}
	switch hdr.Type {
	case codec.TypeAuthen:
		return cs.dispatchAuthen(ctx, env, hdr, rh, body)
	case codec.TypeAuthor:
		return cs.dispatchAuthor(ctx, env, hdr, rh, body)
	case codec.TypeAcct:
		return cs.dispatchAcct(ctx, env, hdr, rh, body)
	default:
		return outgoing{}, codec.ErrUnknownType
	}
}

func (cs *connState) dispatchAuthen(ctx context.Context, env Env, hdr, rh codec.Header, body []byte) (outgoing, error) {
	if hdr.SeqNo == 1 {
		start, err := codec.DecodeAuthenStart(body)
		if err != nil {
			return outgoing{}, mapDecodeErr(cs.id.Transport, err)
		}
		_, disp := codec.ClassifyAuthenStart(hdr.Minor(), start)
		if disp != codec.DispositionAccept {
			return encodeAuthen(rh, codec.AuthenReply{Status: disp.AuthenStatus()}, true)
		}
		reply, err := cs.h.AuthenStart(ctx, env, start)
		if err != nil {
			return encodeAuthen(rh, codec.AuthenReply{Status: codec.AuthenStatusError}, true)
		}
		return encodeAuthen(rh, reply, authenTerminal(reply.Status))
	}
	cont, err := codec.DecodeAuthenContinue(body)
	if err != nil {
		return outgoing{}, mapDecodeErr(cs.id.Transport, err)
	}
	reply, err := cs.h.AuthenContinue(ctx, env, cont)
	if err != nil {
		return encodeAuthen(rh, codec.AuthenReply{Status: codec.AuthenStatusError}, true)
	}
	return encodeAuthen(rh, reply, authenTerminal(reply.Status) || cont.Abort())
}

func (cs *connState) dispatchAuthor(ctx context.Context, env Env, hdr, rh codec.Header, body []byte) (outgoing, error) {
	if codec.ClassifyAuthorMinor(hdr.Minor()) != codec.DispositionAccept {
		return encodeAuthor(rh, codec.AuthorResponse{Status: codec.AuthorStatusError})
	}
	req, err := codec.DecodeAuthorRequest(body)
	if err != nil {
		return outgoing{}, mapDecodeErr(cs.id.Transport, err)
	}
	reply, err := cs.h.Authorize(ctx, env, req)
	if err != nil {
		return encodeAuthor(rh, codec.AuthorResponse{Status: codec.AuthorStatusError})
	}
	return encodeAuthor(rh, reply)
}

func (cs *connState) dispatchAcct(ctx context.Context, env Env, hdr, rh codec.Header, body []byte) (outgoing, error) {
	if codec.ClassifyAcctMinor(hdr.Minor()) != codec.DispositionAccept {
		return encodeAcct(rh, codec.AcctReply{Status: codec.AcctStatusError})
	}
	req, err := codec.DecodeAcctRequest(body)
	if err != nil {
		if errors.Is(err, codec.ErrAcctFlags) {
			return encodeAcct(rh, codec.AcctReply{Status: codec.AcctStatusError})
		}
		return outgoing{}, mapDecodeErr(cs.id.Transport, err)
	}
	reply, err := cs.h.Account(ctx, env, req)
	if err != nil {
		return encodeAcct(rh, codec.AcctReply{Status: codec.AcctStatusError})
	}
	return encodeAcct(rh, reply)
}

func mapDecodeErr(tr domain.Transport, err error) error {
	if errors.Is(err, codec.ErrLengthMismatch) && tr == domain.TransportLegacy {
		return ErrSecretMismatch
	}
	return err
}

func authenTerminal(status byte) bool {
	switch status {
	case codec.AuthenStatusPass, codec.AuthenStatusFail, codec.AuthenStatusRestart, codec.AuthenStatusError:
		return true
	default:
		return false
	}
}

func encodeAuthen(h codec.Header, r codec.AuthenReply, terminal bool) (outgoing, error) {
	body, err := r.Encode()
	if err != nil {
		return outgoing{}, err
	}
	h.Length = uint32(len(body))
	return outgoing{hdr: h, body: body, terminal: terminal}, nil
}

func encodeAuthor(h codec.Header, r codec.AuthorResponse) (outgoing, error) {
	body, err := r.Encode()
	if err != nil {
		return outgoing{}, err
	}
	h.Length = uint32(len(body))
	return outgoing{hdr: h, body: body, terminal: true}, nil
}

func encodeAcct(h codec.Header, r codec.AcctReply) (outgoing, error) {
	body, err := r.Encode()
	if err != nil {
		return outgoing{}, err
	}
	h.Length = uint32(len(body))
	return outgoing{hdr: h, body: body, terminal: true}, nil
}

func (cs *connState) replyError(ctx context.Context, req codec.Header) {
	if !req.KnownType() {
		return
	}
	seq, err := codec.NextSeq(req.SeqNo)
	if err != nil {
		if req.SeqNo != 0 {
			return
		}
		seq = 1
	}
	h := codec.Header{
		Version:   req.Version,
		Type:      req.Type,
		SeqNo:     seq,
		SessionID: req.SessionID,
	}
	if !cs.sc.Complete() {
		h.Flags = cs.negotiateFlags()
	}
	var body []byte
	switch req.Type {
	case codec.TypeAuthen:
		body, _ = codec.AuthenReply{Status: codec.AuthenStatusError}.Encode()
	case codec.TypeAuthor:
		body, _ = codec.AuthorResponse{Status: codec.AuthorStatusError}.Encode()
	case codec.TypeAcct:
		body, _ = codec.AcctReply{Status: codec.AcctStatusError}.Encode()
	}
	h.Length = uint32(len(body))
	_ = cs.write(ctx, h, body)
}

func (cs *connState) write(ctx context.Context, h codec.Header, body []byte) error {
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	if cs.closed.Load() {
		return io.ErrClosedPipe
	}
	deadline := time.Now().Add(cs.lim.WriteTimeout)
	return cs.pio.Write(ctx, h, body, deadline)
}

func (cs *connState) dropSession(s *session) {
	if s == nil {
		return
	}
	s.stop()
	cs.mu.Lock()
	if cur, ok := cs.sessions[s.id]; ok && cur == s {
		delete(cs.sessions, s.id)
	}
	cs.mu.Unlock()
	cs.endAAA(s.id)
}

func (cs *connState) endAAA(sessionID uint32) {
	f, ok := cs.h.(SessionFinalizer)
	if !ok {
		return
	}
	f.EndSession(context.Background(), Env{Identity: cs.id, SessionID: sessionID, ConnKey: cs.connKey})
}

func (cs *connState) sessionCount() int {
	cs.mu.Lock()
	n := len(cs.sessions)
	cs.mu.Unlock()
	return n
}

func (cs *connState) shutdownSessions(grace time.Duration) {
	cs.closed.Store(true)
	cs.mu.Lock()
	for _, s := range cs.sessions {
		s.stop()
	}
	cs.mu.Unlock()
	done := make(chan struct{})
	go func() {
		cs.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}
