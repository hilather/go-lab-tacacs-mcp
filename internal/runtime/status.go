package runtime

// StatusProvider is the live listener inventory. operations.Deps.Runtime
// overlays ready/inflight/queue_depth onto system.status.get.
type StatusProvider interface {
	Statuses() []Status
	Ready() bool
}
