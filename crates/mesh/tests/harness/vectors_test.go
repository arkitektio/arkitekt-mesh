package harness

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/types/key"
)

// Fixed-key vectors the Rust unit tests check against:
//
//	MESH_VECTORS=1 go test -run TestVectors -v .
func TestVectors(t *testing.T) {
	if os.Getenv("MESH_VECTORS") == "" {
		t.Skip("prints vectors for the Rust tests")
	}
	var aPriv, bPriv [32]byte
	var nonce [24]byte
	for i := range aPriv {
		aPriv[i] = byte(i + 1)
		bPriv[i] = byte(100 + i)
	}
	for i := range nonce {
		nonce[i] = byte(200 + i)
	}
	bPub, err := curve25519.X25519(bPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sealed := box.Seal(nil, []byte("hello derp"), &nonce, (*[32]byte)(bPub), &aPriv)
	fmt.Printf("box(a->b, 'hello derp')=%s\n", hex.EncodeToString(sealed))

	// The peer relay messages and their Geneve header (crates/core/src/disco.rs,
	// geneve.rs), as tailscale's own marshalling writes them.
	discoKey := func(fill byte) key.DiscoPublic {
		var raw [32]byte
		for i := range raw {
			raw[i] = fill
		}
		return key.DiscoPublicFromRaw32(mem.B(raw[:]))
	}
	common := disco.BindUDPRelayEndpointCommon{VNI: 0x00abcdef, Generation: 7, RemoteKey: discoKey(0x22)}
	for i := range common.Challenge {
		common.Challenge[i] = byte(0x40 + i)
	}
	endpoint := disco.UDPRelayEndpoint{
		ServerDisco:         discoKey(0x11),
		ClientDisco:         [2]key.DiscoPublic{discoKey(0x22), discoKey(0x33)},
		LamportID:           0x0102030405060708,
		VNI:                 0x00abcdef,
		BindLifetime:        30 * time.Second,
		SteadyStateLifetime: 5 * time.Minute,
		AddrPorts: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.7:40000"),
			netip.MustParseAddrPort("[2001:db8::7]:40001"),
		},
	}
	for _, v := range []struct {
		name string
		msg  disco.Message
	}{
		{"bind", &disco.BindUDPRelayEndpoint{BindUDPRelayEndpointCommon: common}},
		{"challenge", &disco.BindUDPRelayEndpointChallenge{BindUDPRelayEndpointCommon: common}},
		{"answer", &disco.BindUDPRelayEndpointAnswer{BindUDPRelayEndpointCommon: common}},
		{"call-me-maybe-via", &disco.CallMeMaybeVia{UDPRelayEndpoint: endpoint}},
		{"allocate-request", &disco.AllocateUDPRelayEndpointRequest{
			ClientDisco: [2]key.DiscoPublic{discoKey(0x22), discoKey(0x33)}, Generation: 9}},
		{"allocate-response", &disco.AllocateUDPRelayEndpointResponse{Generation: 9, UDPRelayEndpoint: endpoint}},
	} {
		fmt.Printf("disco %s=%s\n", v.name, hex.EncodeToString(v.msg.AppendMarshal(nil)))
	}
	for _, control := range []bool{false, true} {
		header := packet.GeneveHeader{Protocol: packet.GeneveProtocolDisco, Control: control}
		header.VNI.Set(0x00abcdef)
		raw := make([]byte, packet.GeneveFixedHeaderLength)
		if err := header.Encode(raw); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("geneve disco control=%v=%s\n", control, hex.EncodeToString(raw))
	}
	header := packet.GeneveHeader{Protocol: packet.GeneveProtocolWireGuard}
	header.VNI.Set(1)
	raw := make([]byte, packet.GeneveFixedHeaderLength)
	if err := header.Encode(raw); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("geneve wireguard vni=1=%s\n", hex.EncodeToString(raw))
}
