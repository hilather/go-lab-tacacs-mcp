package tls

import (
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/codec"
	tcodec "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/testclient/codec"
)

func TestMissingUnencryptedFlagErrors(t *testing.T) {
	for _, typ := range []byte{tcodec.TypeAuthen, tcodec.TypeAuthor, tcodec.TypeAcct} {
		typ := typ
		t.Run(flagName(typ), func(t *testing.T) {
			ln, pki := startDefault(t)
			cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
			c := dialAuth(t, ln.Addr().String(), cfg)
			var body []byte
			var err error
			switch typ {
			case tcodec.TypeAuthen:
				body, err = tcodec.WriteStart(tcodec.Start{
					Action: tcodec.ActionLogin, AType: tcodec.TypeASCII, Service: tcodec.SvcLogin,
					User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
				})
			case tcodec.TypeAuthor:
				_, body = authorPacket()
			default:
				body, err = tcodec.WriteAcctReq(tcodec.AcctReq{
					Flags: tcodec.AcctStart, Method: tcodec.MethTACACS, Service: tcodec.SvcLogin,
					User: []byte("alice"), Port: []byte("tty0"), RemAddr: []byte("127.0.0.1"),
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			h := tcodec.Header{Version: tcodec.VersionByte(0), Type: typ, SeqNo: 1, Flags: 0, SessionID: 9}
			if err := c.WritePacket(h, body); err != nil {
				t.Fatal(err)
			}
			rh, rbody, err := c.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			if rh.Flags&tcodec.FlagUnencrypted == 0 {
				t.Fatalf("ERROR reply must set UNENCRYPTED, flags=%#x", rh.Flags)
			}
			switch typ {
			case tcodec.TypeAuthen:
				rep, err := tcodec.ReadReply(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.StatusError {
					t.Fatalf("status=%#x", rep.Status)
				}
			case tcodec.TypeAuthor:
				rep, err := tcodec.ReadAuthorRep(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.AuthorError {
					t.Fatalf("status=%#x", rep.Status)
				}
			default:
				rep, err := tcodec.ReadAcctRep(rbody)
				if err != nil {
					t.Fatal(err)
				}
				if rep.Status != tcodec.AcctErr {
					t.Fatalf("status=%#x", rep.Status)
				}
			}
		})
	}
}

func TestNoObfuscationOverTLS(t *testing.T) {
	ln, pki := startDefault(t)
	cfg := clientTLS(t, pki, pki.ClientOKCert, pki.ClientOKKey, "", nil)
	c := dialAuth(t, ln.Addr().String(), cfg)
	h, body := authorPacket()
	if err := c.WritePacket(h, body); err != nil {
		t.Fatal(err)
	}
	rh, rbody, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	// Body must decode as cleartext without a shared secret.
	if _, err := tcodec.ReadAuthorRep(rbody); err != nil {
		t.Fatal(err)
	}
	if rh.Flags&tcodec.FlagUnencrypted == 0 {
		t.Fatal("tls reply must not be obfuscated")
	}
	_ = codec.FlagUnencrypted
}

func flagName(typ byte) string {
	switch typ {
	case tcodec.TypeAuthen:
		return "authen"
	case tcodec.TypeAuthor:
		return "author"
	default:
		return "acct"
	}
}
