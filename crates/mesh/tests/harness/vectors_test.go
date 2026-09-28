package harness

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
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
}
