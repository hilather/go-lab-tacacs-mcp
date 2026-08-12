package server

import "time"

const (
	defaultMaxSessions   = 1024
	defaultShutdownGrace = 15 * time.Second
)

// Limits are per-listener connection and session bounds.
type Limits struct {
	MaxConnections           int
	MaxSessionsPerConnection int
	MaxPacketBodyBytes       uint32
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
	IdleTimeout              time.Duration
	HandshakeTimeout         time.Duration
	SingleConnectEnabled     bool
	MaxLifetime              time.Duration
	ShutdownGrace            time.Duration
}

func (l Limits) normalized() Limits {
	if l.MaxConnections < 0 {
		l.MaxConnections = 0
	}
	if l.MaxSessionsPerConnection <= 0 {
		l.MaxSessionsPerConnection = defaultMaxSessions
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = 15 * time.Second
	}
	if l.WriteTimeout <= 0 {
		l.WriteTimeout = 15 * time.Second
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = 60 * time.Second
	}
	if l.HandshakeTimeout <= 0 {
		l.HandshakeTimeout = 10 * time.Second
	}
	if l.ShutdownGrace <= 0 {
		l.ShutdownGrace = defaultShutdownGrace
	}
	return l
}
