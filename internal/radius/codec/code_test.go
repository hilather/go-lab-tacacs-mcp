package codec

import "testing"

func TestCodeClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code       Code
		known      bool
		advertised bool
		access     bool
		accounting bool
	}{
		{CodeAccessRequest, true, true, true, false},
		{CodeAccessAccept, true, true, true, false},
		{CodeAccessReject, true, true, true, false},
		{CodeAccountingRequest, true, true, false, true},
		{CodeAccountingResponse, true, true, false, true},
		{CodeAccessChallenge, true, false, true, false},
		{0, false, false, false, false},
		{12, false, false, false, false},
		{43, false, false, false, false},
	}
	for _, tc := range cases {
		if tc.code.Known() != tc.known || tc.code.Advertised() != tc.advertised {
			t.Fatalf("%d known=%v advertised=%v", tc.code, tc.code.Known(), tc.code.Advertised())
		}
		if tc.code.AccessFamily() != tc.access || tc.code.AccountingFamily() != tc.accounting {
			t.Fatalf("%d access=%v acct=%v", tc.code, tc.code.AccessFamily(), tc.code.AccountingFamily())
		}
	}
	if CodeAccessChallenge.Advertised() {
		t.Fatal("Access-Challenge must not be advertised")
	}
	if CodeAccessChallenge.String() == "" {
		t.Fatal("challenge needs a discard-trace name")
	}
}
