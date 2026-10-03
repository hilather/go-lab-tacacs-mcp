package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/attribute"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/codec"
	"github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient"
	tc "github.com/hilather/go-lab-tacacs-mcp/internal/radius/testclient/codec"
)

// Fixed RFC 5176 §§2.3/3.4 vectors generated with Python hashlib/hmac,
// independently of both Go codecs: zero RA/MA -> HMAC -> populated MA -> MD5.
func TestDynAuthRFC5176FixedVectors(t *testing.T) {
	for _, v := range []struct {
		code codec.Code
		wire string
	}{
		{codec.CodeDisconnectRequest, "280900299fec6b17d1858824761e5d028f64e2305012a5041bbb1195ae3ddbd27538e55cc46a010375"},
		{codec.CodeCoARequest, "2b09002920622bdf5fc6472155915daf063ac3475012a756daa992df1e011455b1610b0d0448010375"},
	} {
		t.Run(v.code.String(), func(t *testing.T) {
			secret := []byte("LabSecret-16chars!")
			want, _ := hex.DecodeString(v.wire)
			got, err := SignDynAuthRequest(secret, v.code, 9, [16]byte{99}, attribute.RawSet{{Type: 1, Value: []byte("u")}})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("RFC vector mismatch: %x", got)
			}
			independent, err := testclient.EncodeDynAuthRequest(secret, testclient.DynAuthRequest{Code: tc.Code(v.code), Identifier: 9, UserName: "u", Authenticator: [16]byte{99}}, nil)
			if err != nil || !bytes.Equal(independent, want) {
				t.Fatalf("independent vector mismatch: %x %v", independent, err)
			}
			for _, offset := range []int{-1, 4, 22, 40} {
				raw := append([]byte(nil), want...)
				if offset >= 0 {
					raw[offset] ^= 1
				}
				pkt, err := codec.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				reason := CheckIntegrity(Request{Role: domain.RoleDynamicAuthorization, Packet: pkt, Declared: raw, Secret: secret})
				if (reason == "") != (offset < 0) {
					t.Fatalf("offset %d integrity=%s", offset, reason)
				}
				_, err = testclient.DecodeDynAuthRequest(secret, raw)
				if (err == nil) != (offset < 0) {
					t.Fatalf("independent offset %d: %v", offset, err)
				}
			}
		})
	}
}

func TestOriginateIgnoresUnboundResponses(t *testing.T) {
	for _, reqCode := range []codec.Code{codec.CodeCoARequest, codec.CodeDisconnectRequest} {
		for _, invalid := range []string{"identifier", "family", "source", "integrity"} {
			t.Run(reqCode.String()+"/"+invalid, func(t *testing.T) {
				secret := []byte("LabSecret-16chars!")
				ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				done := make(chan error, 1)
				go func() {
					buf := make([]byte, 4096)
					n, peer, err := ln.ReadFromUDP(buf)
					if err != nil {
						done <- err
						return
					}
					pkt, err := tc.Decode(buf[:n])
					if err != nil {
						done <- err
						return
					}
					code := tc.CoAACK
					if reqCode == codec.CodeDisconnectRequest {
						code = tc.DisconnectACK
					}
					badCode, id := tc.CoANAK, pkt.Identifier
					if reqCode == codec.CodeDisconnectRequest {
						badCode = tc.DisconnectNAK
					}
					if invalid == "identifier" {
						id++
					}
					if invalid == "family" {
						if code == tc.CoAACK {
							badCode = tc.DisconnectACK
						} else {
							badCode = tc.CoAACK
						}
					}
					bad, err := testclient.EncodeDynAuthReply(secret, badCode, id, pkt.Authenticator, nil)
					if err != nil {
						done <- err
						return
					}
					if invalid == "integrity" {
						bad[4] ^= 1
					}
					sender := ln
					if invalid == "source" {
						sender, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
						if err != nil {
							done <- err
							return
						}
						defer sender.Close()
					}
					if _, err = sender.WriteToUDP(bad, peer); err != nil {
						done <- err
						return
					}
					good, err := testclient.EncodeDynAuthReply(secret, code, pkt.Identifier, pkt.Authenticator, nil)
					if err == nil {
						_, err = ln.WriteToUDP(good, peer)
					}
					done <- err
				}()
				res, err := (&Originator{}).Send(context.Background(), OriginateRequest{Secret: secret, Destination: ln.LocalAddr().String(), Code: reqCode, Timeout: time.Second})
				if err != nil || res.Outcome != DynAuthOutcomeACK || res.Code != codec.Code(tc.CoAACK) && reqCode == codec.CodeCoARequest || res.Code != codec.Code(tc.DisconnectACK) && reqCode == codec.CodeDisconnectRequest {
					t.Fatalf("result=%+v err=%v", res, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestOriginateCancellationInterruptsRead(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (&Originator{}).Send(ctx, OriginateRequest{Secret: []byte("LabSecret-16chars!"), Destination: ln.LocalAddr().String(), Code: codec.CodeCoARequest, Timeout: 10 * time.Second})
		done <- err
	}()
	buf := make([]byte, 4096)
	ln.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = ln.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt read")
	}
}

func BenchmarkSignDynAuthRequest(b *testing.B) {
	secret := []byte("LabSecret-16chars!")
	attrs := attribute.RawSet{{Type: 1, Value: []byte("u")}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := SignDynAuthRequest(secret, codec.CodeCoARequest, 9, [16]byte{}, attrs); err != nil {
			b.Fatal(err)
		}
	}
}
