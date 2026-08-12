package codec

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthenStartRoundTrip(t *testing.T) {
	t.Parallel()
	in := AuthenStart{
		Action:  AuthenActionLogin,
		PrivLvl: 1,
		Type:    AuthenTypeASCII,
		Service: AuthenServiceLogin,
		User:    []byte("admin"),
		Port:    []byte("tty"),
		RemAddr: []byte("127.0.0.1"),
		Data:    []byte{0x00, 0x7f},
	}
	raw, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuthenStart(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != in.Action || got.Type != in.Type || got.Service != in.Service {
		t.Fatalf("hdr %#v", got)
	}
	if !bytes.Equal(got.User, in.User) || !bytes.Equal(got.Data, in.Data) {
		t.Fatalf("user/data %#v", got)
	}
}

func TestAuthenStartRejectsNonPrintablePort(t *testing.T) {
	t.Parallel()
	in := AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceLogin, Port: []byte{'t', 0x01}}
	if _, err := in.Encode(); !errors.Is(err, ErrNonPrintable) {
		t.Fatalf("encode: %v", err)
	}
	raw := []byte{1, 0, 1, 1, 0, 2, 0, 0, 't', 0x01}
	if _, err := DecodeAuthenStart(raw); !errors.Is(err, ErrNonPrintable) {
		t.Fatalf("decode: %v", err)
	}
}

func TestAuthenStartLengthMismatch(t *testing.T) {
	t.Parallel()
	if _, err := DecodeAuthenStart([]byte{1, 0, 1, 1, 1, 0, 0, 0}); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("short: %v", err)
	}
	raw := []byte{1, 0, 1, 1, 0, 0, 0, 0, 0xff}
	if _, err := DecodeAuthenStart(raw); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("extra: %v", err)
	}
}

func TestAuthenContinueAbortAndReply(t *testing.T) {
	t.Parallel()
	c := AuthenContinue{Flags: ContinueFlagAbort | 0x80, UserMsg: []byte("x")}
	raw, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if raw[4] != ContinueFlagAbort {
		t.Fatalf("unknown continue flag written: %#x", raw[4])
	}
	got, err := DecodeAuthenContinue(raw)
	if err != nil || !got.Abort() || !bytes.Equal(got.UserMsg, []byte("x")) {
		t.Fatalf("got %#v err=%v", got, err)
	}

	r := AuthenReply{Status: AuthenStatusGetPass, Flags: ReplyFlagNoEcho | 0x40, ServerMsg: []byte("Password:")}
	rb, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if rb[1] != ReplyFlagNoEcho {
		t.Fatalf("flags=%#x", rb[1])
	}
	gr, err := DecodeAuthenReply(rb)
	if err != nil || gr.Status != AuthenStatusGetPass || !bytes.Equal(gr.ServerMsg, r.ServerMsg) {
		t.Fatalf("reply %#v err=%v", gr, err)
	}
}

func TestAuthenReplyFollow(t *testing.T) {
	t.Parallel()
	if _, err := (AuthenReply{Status: AuthenStatusFollow}).Encode(); !errors.Is(err, ErrFollow) {
		t.Fatalf("encode: %v", err)
	}
	raw := []byte{AuthenStatusFollow, 0, 0, 0, 0, 0}
	got, err := DecodeAuthenReply(raw)
	if err != nil || got.Status != AuthenStatusFollow {
		t.Fatalf("decode %#v err=%v", got, err)
	}
	if NormalizeAuthenStatus(got.Status) != AuthenStatusFail {
		t.Fatal("FOLLOW must map to FAIL")
	}
}

func TestZeroLengthFieldsAbsent(t *testing.T) {
	t.Parallel()
	raw, err := (AuthenStart{Action: AuthenActionLogin, Type: AuthenTypeASCII, Service: AuthenServiceLogin}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuthenStart(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.User != nil || got.Port != nil || got.Data != nil {
		t.Fatalf("zero-length not absent: %#v", got)
	}
}
