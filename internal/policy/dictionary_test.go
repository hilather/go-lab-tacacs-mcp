package policy

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestKnownDictionaryComplete(t *testing.T) {
	t.Parallel()
	want := []string{
		"service", "protocol", "cmd", "cmd-arg", "acl", "inacl", "outacl",
		"addr", "addr-pool", "timeout", "idletime", "autocmd", "noescape",
		"nohangup", "priv-lvl",
	}
	got := map[string]ArgSpec{}
	for _, s := range KnownArgs() {
		got[s.Name] = s
	}
	for _, name := range want {
		if !got[name].Known {
			t.Fatalf("missing dictionary entry %q", name)
		}
	}
	if LookupArg("cisco-av-pair").Known {
		t.Fatal("vendor names must remain unknown")
	}
	if !LookupArg("cmd-arg").Repeatable {
		t.Fatal("cmd-arg is repeatable")
	}
}

func TestValidateValueEncodings(t *testing.T) {
	t.Parallel()
	ok := []domain.AVPair{
		av("service", '=', "shell"),
		av("cmd", '=', ""),
		av("cmd-arg", '=', "show=more*x"),
		av("priv-lvl", '=', "0"),
		av("priv-lvl", '=', "15"),
		av("noescape", '=', "true"),
		av("nohangup", '*', "false"),
		av("timeout", '=', "30"),
		av("acl", '=', "0"),
		av("addr", '=', "192.0.2.1"),
		av("addr", '=', "2001:db8::1"),
		av("timezone", '=', "UTC"),
		av("timezone", '=', "-05:00"),
		av("start_time", '=', "1755000000"),
		av("cisco-av-pair", '=', "shell:roles=admin"),
	}
	for _, p := range ok {
		if err := ValidatePair(p); err != nil {
			t.Fatalf("ValidatePair(%+v): %v", p, err)
		}
	}
	bad := []domain.AVPair{
		av("priv-lvl", '=', "16"),
		av("priv-lvl", '=', "-1"),
		av("noescape", '=', "yes"),
		av("timeout", '=', "18446744073709551616"),
		av("timeout", '=', "1e2"),
		av("addr", '=', "not-an-ip"),
		av("timezone", '=', "Not/AZone++"),
	}
	for _, p := range bad {
		if err := ValidatePair(p); err == nil {
			t.Fatalf("expected error for %+v", p)
		}
	}
}

func TestNumericLengthCheckedBeforeParse(t *testing.T) {
	t.Parallel()
	long := make([]byte, 64)
	for i := range long {
		long[i] = '9'
	}
	if err := ValidateValue("timeout", string(long)); err == nil {
		t.Fatal("oversized numeric must fail before conversion")
	}
}

func TestEpochUTCUnlessTimezone(t *testing.T) {
	t.Parallel()
	utc, err := ParseEpochSeconds("0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if utc.Location() != time.UTC || utc.Unix() != 0 {
		t.Fatalf("default UTC: %v", utc)
	}
	loc, err := LoadLocation("-05:00")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEpochSeconds("3600", loc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Location() == time.UTC {
		t.Fatal("explicit timezone must apply")
	}
	if _, off := got.Zone(); off != -5*3600 {
		t.Fatalf("offset=%d", off)
	}
}

func TestPrivilegeBounds(t *testing.T) {
	t.Parallel()
	for i := 0; i <= 15; i++ {
		if _, err := domain.ParsePrivilegeLevel(i); err != nil {
			t.Fatalf("priv %d: %v", i, err)
		}
	}
	if err := ValidateValue("priv-lvl", "16"); err == nil {
		t.Fatal("priv 16")
	}
}
