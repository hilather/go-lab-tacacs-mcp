// Package runtime is the composition-root listener inventory.
//
// Protocol packages implement Listener. This package must not import
// TACACS, RADIUS, HTTP adapters, config, or state. RADIUS UDP is not
// started from here.
package runtime
