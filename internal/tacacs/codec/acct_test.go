package codec

import (
	"errors"
	"testing"
)

func TestAcctFlagTable(t *testing.T) {
	t.Parallel()
	valid := []byte{AcctFlagStart, AcctFlagStop, AcctFlagWatchdog, AcctFlagWatchdogUpdate}
	for _, f := range valid {
		if !ValidAcctFlags(f) {
			t.Fatalf("valid %#x rejected", f)
		}
		raw, err := (AcctRequest{Flags: f, AuthenMethod: AuthenMethodTACACS, User: []byte("u")}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeAcctRequest(raw)
		if err != nil || got.Flags != f {
			t.Fatalf("flags=%#x got %#v err=%v", f, got, err)
		}
	}
	invalid := []byte{0, AcctFlagStart | AcctFlagStop, AcctFlagWatchdog | AcctFlagStop, 0xff}
	for _, f := range invalid {
		if ValidAcctFlags(f) {
			t.Fatalf("invalid %#x accepted", f)
		}
		if _, err := (AcctRequest{Flags: f}).Encode(); !errors.Is(err, ErrAcctFlags) {
			t.Fatalf("encode %#x: %v", f, err)
		}
	}
}

func TestAcctWatchdogIgnoresArgsOnEncode(t *testing.T) {
	t.Parallel()
	in := AcctRequest{
		Flags:        AcctFlagWatchdog,
		AuthenMethod: AuthenMethodTACACS,
		User:         []byte("u"),
		Args:         []Argument{{Name: "task_id", Separator: '=', Value: "x"}},
	}
	raw, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAcctRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.UseArguments() {
		t.Fatal("watchdog should ignore arguments")
	}
	if len(got.Args) != 0 {
		t.Fatalf("encoded watchdog still has args: %v", got.Args)
	}
}

func TestAcctReplyAndFollow(t *testing.T) {
	t.Parallel()
	raw, err := (AcctReply{Status: AcctStatusSuccess, ServerMsg: []byte("ok")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAcctReply(raw)
	if err != nil || got.Status != AcctStatusSuccess {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := (AcctReply{Status: AcctStatusFollow}).Encode(); !errors.Is(err, ErrFollow) {
		t.Fatalf("follow: %v", err)
	}
}

func TestClassifyAcctAuthorMinor(t *testing.T) {
	t.Parallel()
	if ClassifyAcctMinor(0) != DispositionAccept || ClassifyAuthorMinor(0) != DispositionAccept {
		t.Fatal("minor 0")
	}
	if ClassifyAcctMinor(1) != DispositionError || ClassifyAuthorMinor(1) != DispositionError {
		t.Fatal("minor 1 must ERROR")
	}
}
