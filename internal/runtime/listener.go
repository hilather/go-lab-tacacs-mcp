package runtime

import (
	"context"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

// Stable listener IDs match configuration keys and operations.Listener*.
const (
	IDLegacyTACACS = "legacy_tacacs"
	IDSecureTACACS = "secure_tacacs"
)

// Descriptor is static listener identity. Carrier is the wire binding;
// do not put radius_udp on domain.Transport.
type Descriptor struct {
	ID       string
	Protocol domain.Protocol
	Carrier  domain.Carrier
	Roles    []domain.ListenerRole
	Bind     string
	Required bool
}

// Status is live listener inventory. LastErrorCode is bounded and must
// not include peer or user identifiers.
type Status struct {
	Descriptor
	Enabled       bool
	Ready         bool
	Inflight      int
	QueueDepth    int
	LastErrorCode string
}

// Listener is a managed process socket. Protocol packages implement this;
// they do not import cmd/taclabd. Carrier is the wire binding — Transport
// remains TACACS legacy/tls only.
type Listener interface {
	ID() string
	Protocol() domain.Protocol
	Carrier() domain.Carrier
	Role() domain.ListenerRole
	Start(context.Context) error
	Ready() bool
	Drain(context.Context) error
	Close() error
	Status() Status
}

// ManagedListener is the design name for Listener.
type ManagedListener = Listener
