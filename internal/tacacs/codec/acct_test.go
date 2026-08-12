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

func TestAcctReplyRFC8907FieldOrder(t *testing.T) {
	t.Parallel()
	empty, err := (AcctReply{Status: AcctStatusSuccess}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != string([]byte{0, 0, 0, 0, AcctStatusSuccess}) {
		t.Fatalf("empty SUCCESS %x", empty)
	}
	raw, err := (AcctReply{Status: AcctStatusError, ServerMsg: []byte("no"), Data: []byte("log")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0 || raw[1] != 2 || raw[2] != 0 || raw[3] != 3 || raw[4] != AcctStatusError {
		t.Fatalf("prefix %x is not server_msg_len||data_len||status", raw[:5])
	}
	got, err := DecodeAcctReply(raw)
	if err != nil || string(got.ServerMsg) != "no" || string(got.Data) != "log" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := (AcctReply{Status: AcctStatusSuccess, Data: []byte{0x01}}).Encode(); !errors.Is(err, ErrNonPrintable) {
		t.Fatalf("data encode: %v", err)
	}
	if _, err := DecodeAcctReply([]byte{0, 0, 0, 1, AcctStatusSuccess, 0x01}); !errors.Is(err, ErrNonPrintable) {
		t.Fatalf("data decode: %v", err)
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
