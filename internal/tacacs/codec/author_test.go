package codec

import (
	"errors"
	"testing"
)

func TestAuthorRequestArgsOrder(t *testing.T) {
	t.Parallel()
	in := AuthorRequest{
		AuthenMethod: AuthenMethodTACACS,
		PrivLvl:      1,
		AuthenType:   AuthenTypeASCII,
		Service:      AuthenServiceLogin,
		User:         []byte("admin"),
		Port:         []byte("tty"),
		Args: []Argument{
			{Name: "service", Separator: ArgSepMandatory, Value: "shell"},
			{Name: "service", Separator: ArgSepMandatory, Value: "shell"},
			{Name: "id", Separator: ArgSepOptional, Value: "1"},
		},
	}
	raw, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuthorRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Args) != 3 {
		t.Fatalf("args=%d", len(got.Args))
	}
	if got.Args[0].Name != "service" || got.Args[2].Separator != ArgSepOptional {
		t.Fatalf("args=%v", got.Args)
	}
}

func TestAuthorResponseStatuses(t *testing.T) {
	t.Parallel()
	for _, st := range []byte{AuthorStatusPassAdd, AuthorStatusPassRepl, AuthorStatusFail, AuthorStatusError} {
		raw, err := (AuthorResponse{Status: st, Args: []Argument{{Name: "priv-lvl", Separator: '=', Value: "15"}}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeAuthorResponse(raw)
		if err != nil || got.Status != st || len(got.Args) != 1 {
			t.Fatalf("status=%d got %#v err=%v", st, got, err)
		}
	}
	if _, err := (AuthorResponse{Status: AuthorStatusFollow}).Encode(); !errors.Is(err, ErrFollow) {
		t.Fatalf("follow: %v", err)
	}
}

func TestAuthorArgOverflowAndMismatch(t *testing.T) {
	t.Parallel()
	tooMany := make([]Argument, 256)
	for i := range tooMany {
		tooMany[i] = Argument{Name: "a", Separator: '=', Value: "b"}
	}
	if _, err := (AuthorRequest{Args: tooMany}).Encode(); !errors.Is(err, ErrTooManyArgs) {
		t.Fatalf("encode: %v", err)
	}
	// arg_cnt=1 but no length byte
	if _, err := DecodeAuthorRequest([]byte{6, 1, 1, 1, 0, 0, 0, 1}); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("short lens: %v", err)
	}
}

func TestParseArgument(t *testing.T) {
	t.Parallel()
	a, ok, err := ParseArgument([]byte("cmd*configure"))
	if err != nil || !ok || a.Name != "cmd" || a.Separator != '*' || a.Value != "configure" {
		t.Fatalf("%#v ok=%v err=%v", a, ok, err)
	}
	if _, ok, err := ParseArgument(nil); err != nil || ok {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	if _, _, err := ParseArgument([]byte("nosep")); !errors.Is(err, ErrArgument) {
		t.Fatalf("nosep: %v", err)
	}
}
