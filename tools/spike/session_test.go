package spike

import (
	"errors"
	"testing"
)

func TestNextSeq(t *testing.T) {
	t.Parallel()
	got, err := NextSeq(1)
	if err != nil || got != 2 {
		t.Fatalf("NextSeq(1)=%d,%v", got, err)
	}
	if _, err := NextSeq(0); !errors.Is(err, ErrSeqZero) {
		t.Fatalf("zero: %v", err)
	}
	if _, err := NextSeq(255); !errors.Is(err, ErrSeqWrap) {
		t.Fatalf("wrap: %v", err)
	}
}

func TestSeqParity(t *testing.T) {
	t.Parallel()
	if !ClientSeq(1) || ServerSeq(1) {
		t.Fatal("seq 1 is client")
	}
	if !ServerSeq(2) || ClientSeq(2) {
		t.Fatal("seq 2 is server")
	}
	if ClientSeq(0) || ServerSeq(0) {
		t.Fatal("seq 0 is neither")
	}
}

func TestNegotiateSingleConnect(t *testing.T) {
	t.Parallel()
	if !NegotiateSingleConnect(true, FlagSingleConnect, FlagSingleConnect) {
		t.Fatal("both flags on first pair")
	}
	if NegotiateSingleConnect(true, FlagSingleConnect, 0) {
		t.Fatal("server declined")
	}
	if NegotiateSingleConnect(false, FlagSingleConnect, FlagSingleConnect) {
		t.Fatal("flag after first pair is ignored")
	}
}
