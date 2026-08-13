package mcp

import "testing"

func BenchmarkDiscover(b *testing.B) {
	h := mcpHarness(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := mcpRPC(b, h.HTTP, h.Token, "server/discover", nil, nil)
		if got.StatusCode != 200 {
			b.Fatalf("status=%d", got.StatusCode)
		}
	}
}

func BenchmarkStatusTool(b *testing.B) {
	h := mcpHarness(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := mcpRPC(b, h.HTTP, h.Token, "tools/call", map[string]any{
			"name":      "taclab.system.status.get",
			"arguments": map[string]any{},
		}, nil)
		if got.StatusCode != 200 || got.Err != nil {
			b.Fatalf("status=%d err=%+v", got.StatusCode, got.Err)
		}
	}
}
