package udp

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

func TestIndependentTestclientPAPAndAccountingOnUDP(t *testing.T) {
	t.Parallel()
	secret := []byte(labSecret)

	access, _ := startAccessPolicy(t)
	ac := dialUDP(t, access.Addr().String())
	var ra [16]byte
	ra[0] = 0xa1
	pap, err := testclient.EncodeAccessRequest(secret, testclient.AccessRequest{
		Identifier:    11,
		Authenticator: ra,
		UserName:      "lab-admin",
		Password:      []byte(accessTestPassword),
		IncludeMA:     true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Write(pap); err != nil {
		t.Fatal(err)
	}
	got := readUDP(t, ac, 2*time.Second)
	if got == nil {
		t.Fatal("missing access reply")
	}
	reply, err := testclient.DecodeAccessReply(secret, ra, got)
	if err != nil {
		t.Fatalf("independent client rejected Access reply: %v", err)
	}
	if reply.Code != tcodec.AccessAccept {
		t.Fatalf("code=%s", reply.Code)
	}
	if reply.Identifier != 11 {
		t.Fatalf("id=%d", reply.Identifier)
	}
	if len(reply.Attrs) == 0 || reply.Attrs[0].Type != tcodec.TypeMessageAuthenticator {
		t.Fatalf("MA first: %+v", reply.Attrs)
	}

	dir := t.TempDir()
	sec := writeSecret(t, dir)
	doc := mustParse(t, radiusYAML(sec, "127.0.0.0/8", "127.0.0.1:0"))
	acct, _, ring := startAccounting(t, doc)
	cc := dialUDP(t, acct.Addr().String())
	acctReq, err := testclient.EncodeAccountingRequest(secret, testclient.AccountingRequest{
		Identifier: 12,
		StatusType: testclient.AcctStart,
		SessionID:  "peer-1",
		IncludeMA:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := tcodec.Decode(acctReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write(acctReq); err != nil {
		t.Fatal(err)
	}
	acctGot := readUDP(t, cc, 2*time.Second)
	if acctGot == nil {
		t.Fatal("missing accounting reply")
	}
	acctReply, err := testclient.DecodeAccountingResponse(secret, pkt.Authenticator, acctGot)
	if err != nil {
		t.Fatalf("independent client rejected Accounting-Response: %v", err)
	}
	if acctReply.Identifier != 12 {
		t.Fatalf("acct id=%d", acctReply.Identifier)
	}
	if ring.Len() != 1 {
		t.Fatalf("recorded=%d", ring.Len())
	}
}
