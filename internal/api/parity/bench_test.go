package parity

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
)

func BenchmarkDirectStatus(b *testing.B) {
	w := newWorld(b, "direct", allScopes, "")
	snap := w.Mgr.Snapshot()
	in := operations.Input{Actor: w.Actor, Request: operations.GetStatusRequest{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Registry.Invoke(context.Background(), operations.IDSystemStatusGet, snap, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRESTStatus(b *testing.B) {
	w := newWorld(b, "rest", allScopes, "rest")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}

func BenchmarkMCPStatus(b *testing.B) {
	w := newWorld(b, "mcp", allScopes, "mcp")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDSystemStatusGet, operations.GetStatusRequest{}, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}

func BenchmarkDirectEvaluate(b *testing.B) {
	w := newWorld(b, "direct", allScopes, "")
	req := operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show"}
	snap := w.Mgr.Snapshot()
	in := operations.Input{Actor: w.Actor, Request: req}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Registry.Invoke(context.Background(), operations.IDPolicyEvaluate, snap, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRESTEvaluate(b *testing.B) {
	w := newWorld(b, "rest", allScopes, "rest")
	req := operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDPolicyEvaluate, req, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}

func BenchmarkMCPEvaluate(b *testing.B) {
	w := newWorld(b, "mcp", allScopes, "mcp")
	req := operations.EvaluatePolicyRequest{UserID: "alice", ClientID: "sw", Service: "shell", Cmd: "show"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDPolicyEvaluate, req, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}

func BenchmarkDirectUsersGet(b *testing.B) {
	w := newWorld(b, "direct", allScopes, "")
	req := operations.GetUserRequest{ID: "alice"}
	snap := w.Mgr.Snapshot()
	in := operations.Input{Actor: w.Actor, Request: req}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Registry.Invoke(context.Background(), operations.IDUsersGet, snap, in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRESTUsersGet(b *testing.B) {
	w := newWorld(b, "rest", allScopes, "rest")
	req := operations.GetUserRequest{ID: "alice"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDUsersGet, req, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}

func BenchmarkMCPUsersGet(b *testing.B) {
	w := newWorld(b, "mcp", allScopes, "mcp")
	req := operations.GetUserRequest{ID: "alice"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := invoke(b, w, operations.IDUsersGet, req, callOpts{})
		if out.Code != "" {
			b.Fatal(out.Code)
		}
	}
}
