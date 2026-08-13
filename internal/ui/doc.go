// Package ui embeds the production React build (or a compile-time stub)
// and serves it with SPA fallback. Production files are copied into dist/
// by `make web-build`; go:embed cannot reach web/ because of web/go.mod.
package ui
