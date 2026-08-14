package runtime

// StatusProvider is the live listener inventory. operations.Deps.Runtime
// holds this; system.status.get still lists the three named sockets.
type StatusProvider interface {
	Statuses() []Status
	Ready() bool
}
