package aaa

import "testing"

func TestAccountingDictionaryComplete(t *testing.T) {
	t.Parallel()
	want := []string{
		"task_id", "start_time", "stop_time", "elapsed_time", "timezone",
		"event", "reason", "bytes", "bytes_in", "bytes_out",
		"paks", "paks_in", "paks_out", "err_msg",
	}
	got := KnownAccountingArgs()
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, n := range want {
		if got[i] != n || !AccountingOnlyName(n) {
			t.Fatalf("missing %q", n)
		}
	}
	if AccountingOnlyName("service") || AccountingOnlyName("cmd") || AccountingOnlyName("cisco-av-pair") {
		t.Fatal("authorization/vendor names must not be accounting-only")
	}
}
