package harness

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// Tailnet-lock vectors for the Rust tests (crates/mesh/tests/tka.rs),
// made by tailscale's own tka package:
//
//	MESH_TKA_VECTORS=../fixtures/tka_vectors.json go test -run TestTKAVectors .
func TestTKAVectors(t *testing.T) {
	out := os.Getenv("MESH_TKA_VECTORS")
	if out == "" {
		t.Skip("writes vectors for the Rust tests")
	}
	b64 := base64.StdEncoding.EncodeToString
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	admin, second, third := key.NewNLPrivate(), key.NewNLPrivate(), key.NewNLPrivate()
	disablement := make([]byte, 32)
	storage := tka.ChonkMem()
	authority, genesis, err := tka.Create(storage, tka.State{
		Keys: []tka.Key{
			{Kind: tka.Key25519, Public: admin.Public().Verifier(), Votes: 2},
			{Kind: tka.Key25519, Public: second.Public().Verifier(), Votes: 1},
		},
		DisablementValues: [][]byte{tka.DisablementKDF(disablement)},
	}, admin)
	must(err)

	// add third, update its votes, remove second: one AUM each, in order.
	var updates []tka.AUM
	for _, step := range []func(*tka.UpdateBuilder) error{
		func(b *tka.UpdateBuilder) error {
			return b.AddKey(tka.Key{Kind: tka.Key25519, Public: third.Public().Verifier(), Votes: 1})
		},
		func(b *tka.UpdateBuilder) error { return b.SetKeyVote(third.KeyID(), 3) },
		func(b *tka.UpdateBuilder) error { return b.RemoveKey(second.KeyID()) },
	} {
		b := authority.NewUpdater(admin)
		must(step(b))
		aums, err := b.Finalize(storage)
		must(err)
		must(authority.Inform(storage, aums))
		updates = append(updates, aums...)
	}

	node := key.NewNode().Public()
	nodeBytes, err := node.MarshalBinary()
	must(err)
	sign := func(sig tka.NodeKeySignature, by key.NLPrivate) tka.NodeKeySignature {
		sig.Signature, err = by.SignNKS(sig.SigHash())
		must(err)
		return sig
	}
	// Direct, by the admin key.
	direct := sign(tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: admin.KeyID(), Pubkey: nodeBytes}, admin)
	// Direct, by a key the chain removed.
	byRemoved := sign(tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: second.KeyID(), Pubkey: nodeBytes}, second)
	// Rotation: an old node key's direct signature (with a wrapping key)
	// re-signed for the new node key by the wrapping key.
	rotationKey := key.NewNLPrivate()
	oldNode := key.NewNode().Public()
	oldBytes, _ := oldNode.MarshalBinary()
	inner := sign(tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: admin.KeyID(), Pubkey: oldBytes,
		WrappingPubkey: rotationKey.Public().Verifier()}, admin)
	rotation := sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: nodeBytes, Nested: &inner}, rotationKey)
	// Credential (a signed pre-auth key), wrapped for this node key.
	cred := sign(tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: admin.KeyID(),
		WrappingPubkey: rotationKey.Public().Verifier()}, admin)
	credRotation := sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: nodeBytes, Nested: &cred}, rotationKey)
	// Forged: a valid signature's bytes, claiming another node key.
	forged := direct
	other := key.NewNode().Public()
	forged.Pubkey, _ = other.MarshalBinary()

	serialize := func(s tka.NodeKeySignature) string { return b64(s.Serialize()) }
	var aums []string
	for _, a := range updates {
		aums = append(aums, b64(a.Serialize()))
	}
	hashes := []string{genesis.Hash().String()}
	for _, a := range updates {
		hashes = append(hashes, a.Hash().String())
	}
	sigHash := genesis.SigHash()
	data, err := json.MarshalIndent(map[string]any{
		"genesis":         b64(genesis.Serialize()),
		"genesis_sighash": b64(sigHash[:]),
		"updates":         aums,
		"hashes":          hashes,
		"head":            authority.Head().String(),
		"trusted_keys": []string{
			b64(admin.Public().Verifier()), b64(third.Public().Verifier()),
		},
		"third_votes":  3,
		"node_key":     b64(nodeBytes),
		"old_node_key": b64(oldBytes),
		"signatures": map[string]string{
			"direct":          serialize(direct),
			"by_removed_key":  serialize(byRemoved),
			"rotation":        serialize(rotation),
			"credential":      serialize(credRotation),
			"bare_credential": serialize(cred),
			"forged":          serialize(forged),
		},
		"disablement_secret": b64(disablement),
		"direct_sighash":     b64(func() []byte { h := direct.SigHash(); return h[:] }()),
	}, "", "  ")
	must(err)
	must(os.WriteFile(out, append(data, '\n'), 0o644))
}
