package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAVPairFirstSeparator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		name    string
		sep     byte
		value   string
		present bool
	}{
		{in: "cmd=show", name: "cmd", sep: '=', value: "show", present: true},
		{in: "cmd*show", name: "cmd", sep: '*', value: "show", present: true},
		{in: "cmd=show=more", name: "cmd", sep: '=', value: "show=more", present: true},
		{in: "cmd*show=more", name: "cmd", sep: '*', value: "show=more", present: true},
		{in: "cmd=show*more", name: "cmd", sep: '=', value: "show*more", present: true},
		{in: "priv-lvl=15", name: "priv-lvl", sep: '=', value: "15", present: true},
		{in: "a=", name: "a", sep: '=', value: "", present: true},
		{in: "a*", name: "a", sep: '*', value: "", present: true},
		{in: "", present: false},
	}
	for _, tc := range tests {
		p, present, err := ParseAVPair(tc.in)
		if err != nil {
			t.Fatalf("ParseAVPair(%q): %v", tc.in, err)
		}
		if present != tc.present {
			t.Fatalf("ParseAVPair(%q) present=%v, want %v", tc.in, present, tc.present)
		}
		if !present {
			if p != (AVPair{}) {
				t.Fatalf("absent pair must be zero, got %+v", p)
			}
			continue
		}
		if p.Name != tc.name || p.Separator != tc.sep || p.Value != tc.value {
			t.Fatalf("ParseAVPair(%q)=%+v, want name=%q sep=%q value=%q", tc.in, p, tc.name, tc.sep, tc.value)
		}
		enc, err := p.Encode()
		if err != nil {
			t.Fatalf("Encode(%q): %v", tc.in, err)
		}
		if enc != tc.in {
			t.Fatalf("round-trip %q -> %q", tc.in, enc)
		}
	}
}

func TestParseAVPairRejectsNoSeparator(t *testing.T) {
	t.Parallel()
	if _, _, err := ParseAVPair("cmd"); err == nil {
		t.Fatal("expected error for missing separator")
	}
}

func TestParseAVPairRejectsEmptyName(t *testing.T) {
	t.Parallel()
	if _, _, err := ParseAVPair("=value"); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, _, err := ParseAVPair("*value"); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestAVPairEncodeBounds(t *testing.T) {
	t.Parallel()

	minPair := AVPair{Name: "a", Separator: '=', Value: ""}
	if minPair.EncodedLen() != AVPairMinEncodedLen {
		t.Fatalf("min EncodedLen=%d, want %d", minPair.EncodedLen(), AVPairMinEncodedLen)
	}
	if _, err := minPair.Encode(); err != nil {
		t.Fatalf("min pair encode: %v", err)
	}
	if _, present, err := ParseAVPair("a="); err != nil || !present {
		t.Fatalf("parse min pair: present=%v err=%v", present, err)
	}

	maxVal := strings.Repeat("v", AVPairMaxEncodedLen-2) // "x=" + 253 = 255
	maxPair := AVPair{Name: "x", Separator: '=', Value: maxVal}
	if maxPair.EncodedLen() != AVPairMaxEncodedLen {
		t.Fatalf("max EncodedLen=%d, want %d", maxPair.EncodedLen(), AVPairMaxEncodedLen)
	}
	enc, err := maxPair.Encode()
	if err != nil {
		t.Fatalf("max pair encode: %v", err)
	}
	if len(enc) != AVPairMaxEncodedLen {
		t.Fatalf("encoded len=%d, want %d", len(enc), AVPairMaxEncodedLen)
	}
	got, present, err := ParseAVPair(enc)
	if err != nil || !present || got != maxPair {
		t.Fatalf("parse max pair: present=%v err=%v got=%+v", present, err, got)
	}

	over := AVPair{Name: "x", Separator: '=', Value: maxVal + "y"}
	if over.EncodedLen() != AVPairMaxEncodedLen+1 {
		t.Fatalf("over EncodedLen=%d", over.EncodedLen())
	}
	if _, err := over.Encode(); err == nil {
		t.Fatal("expected encode error for 256-byte pair")
	}
	if _, _, err := ParseAVPair(enc + "y"); err == nil {
		t.Fatal("expected parse error for 256-byte pair")
	}

	if _, _, err := ParseAVPair("="); err == nil {
		t.Fatal("expected parse error for 1-byte input")
	}
}

func TestAVPairNameMustNotContainSeparator(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"a=b", "a*b"} {
		p := AVPair{Name: name, Separator: '=', Value: "x"}
		if err := p.Validate(); err == nil {
			t.Fatalf("expected error for name %q", name)
		}
	}
}

func TestAVPairInvalidSeparator(t *testing.T) {
	t.Parallel()
	p := AVPair{Name: "cmd", Separator: ':', Value: "show"}
	if _, err := p.Encode(); err == nil {
		t.Fatal("expected error for invalid separator")
	}
}

func TestAVPairsPreserveOrderAndDuplicates(t *testing.T) {
	t.Parallel()
	raw := []string{"service=shell", "cmd=show", "cmd-arg=ip", "cmd-arg=ip", "vendor*foo=bar"}
	ps, err := ParseAVPairs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 5 {
		t.Fatalf("len=%d, want 5", len(ps))
	}
	if ps[0].Name != "service" || ps[2].Name != "cmd-arg" || ps[3].Name != "cmd-arg" {
		t.Fatalf("order lost: %+v", ps)
	}
	if ps[2] != ps[3] {
		t.Fatalf("duplicate pairs not preserved: %+v vs %+v", ps[2], ps[3])
	}
	if ps[4].Separator != '*' || ps[4].Value != "foo=bar" {
		t.Fatalf("vendor pair: %+v", ps[4])
	}
	enc, err := ps.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != len(raw) {
		t.Fatalf("encoded len=%d", len(enc))
	}
	for i := range raw {
		if enc[i] != raw[i] {
			t.Fatalf("enc[%d]=%q, want %q", i, enc[i], raw[i])
		}
	}
	clone := ps.Clone()
	if !clone.Equal(ps) {
		t.Fatal("clone mismatch")
	}
	clone[0].Value = "mutated"
	if ps[0].Value == "mutated" {
		t.Fatal("clone shared storage")
	}
}

func TestParseAVPairsSkipsAbsent(t *testing.T) {
	t.Parallel()
	ps, err := ParseAVPairs([]string{"", "cmd=show", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name != "cmd" {
		t.Fatalf("got %+v", ps)
	}
}

func TestAVPairErrorIsInvalidArgument(t *testing.T) {
	t.Parallel()
	_, err := AVPair{Name: "", Separator: '='}.Encode()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, NewError(CodeInvalidArgument, "")) {
		t.Fatalf("errors.Is Code: %v", err)
	}
}
