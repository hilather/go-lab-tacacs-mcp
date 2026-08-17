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
		dynauth    bool
	}{
		{CodeAccessRequest, true, true, true, false, false},
		{CodeAccessAccept, true, true, true, false, false},
		{CodeAccessReject, true, true, true, false, false},
		{CodeAccountingRequest, true, true, false, true, false},
		{CodeAccountingResponse, true, true, false, true, false},
		{CodeAccessChallenge, true, false, true, false, false},
		{CodeDisconnectRequest, true, true, false, false, true},
		{CodeDisconnectACK, true, true, false, false, true},
		{CodeDisconnectNAK, true, true, false, false, true},
		{CodeCoARequest, true, true, false, false, true},
		{CodeCoAACK, true, true, false, false, true},
		{CodeCoANAK, true, true, false, false, true},
		{0, false, false, false, false, false},
		{12, false, false, false, false, false},
		{46, false, false, false, false, false},
	}
	for _, tc := range cases {
		if tc.code.Known() != tc.known || tc.code.Advertised() != tc.advertised {
			t.Fatalf("%d known=%v advertised=%v", tc.code, tc.code.Known(), tc.code.Advertised())
		}
		if tc.code.AccessFamily() != tc.access || tc.code.AccountingFamily() != tc.accounting || tc.code.DynamicAuthFamily() != tc.dynauth {
			t.Fatalf("%d access=%v acct=%v dyn=%v", tc.code, tc.code.AccessFamily(), tc.code.AccountingFamily(), tc.code.DynamicAuthFamily())
		}
	}
	if CodeAccessChallenge.Advertised() {
		t.Fatal("Access-Challenge must not be advertised")
	}
	if CodeAccessChallenge.String() == "" {
		t.Fatal("challenge needs a discard-trace name")
	}
}
