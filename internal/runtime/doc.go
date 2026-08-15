// Package runtime is the composition-root listener inventory.
//
// Protocol packages implement Listener. This package must not import
// TACACS, RADIUS, HTTP adapters, config, or state. RADIUS UDP listeners
// are registered from cmd/taclabd, not from this package.
package runtime
