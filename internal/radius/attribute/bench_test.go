package attribute

import "testing"

func BenchmarkDictionaryLookup_Name(b *testing.B) {
	d := Builtin()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := d.LookupName("Message-Authenticator"); !ok {
			b.Fatal("missing")
		}
	}
}

func BenchmarkDictionaryLookup_Code(b *testing.B) {
	d := Builtin()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := d.LookupIETF(TypeSessionTimeout); !ok {
			b.Fatal("missing")
		}
	}
}

func BenchmarkDictionaryCheckSet_8Attrs(b *testing.B) {
	d := Builtin()
	set := RawSet{
		maAttr(),
		{Type: TypeProxyState, Value: []byte("a")},
		{Type: TypeProxyState, Value: []byte("b")},
		{Type: TypeReplyMessage, Value: []byte("ok")},
		{Type: TypeSessionTimeout, Value: []byte{0, 0, 2, 88}},
		{Type: TypeIdleTimeout, Value: []byte{0, 0, 0, 60}},
		{Type: TypeClass, Value: []byte("c")},
		{Type: TypeFramedIPAddress, Value: []byte{192, 0, 2, 10}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := d.CheckSet(set, PacketAccessAccept); err != nil {
			b.Fatal(err)
		}
	}
}
