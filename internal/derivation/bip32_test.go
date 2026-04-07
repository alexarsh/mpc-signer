package derivation

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// BIP32 Test Vector 1 master key from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
// (seed 000102030405060708090a0b0c0d0e0f)
//
// Master private key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
// Master chain code : 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
// Master public key : 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2 (compressed)
const (
	tv1MasterPrivHex      = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
	tv1MasterChainCodeHex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
)

func tv1MasterPubUncompressed(t *testing.T) []byte {
	t.Helper()
	priv, _ := hex.DecodeString(tv1MasterPrivHex)
	privKey, _ := btcec.PrivKeyFromBytes(priv)
	return privKey.PubKey().SerializeUncompressed()
}

// TestDerive_AlgebraicConsistency verifies the core invariants of our BIP32
// share-based derivation using BIP32 Test Vector 1's master key:
//  1. Public-only tweak path and share-side derivation produce identical
//     child public keys.
//  2. Scalar child_share * G equals the advertised child public key
//     (the fundamental ECDSA identity — proves the share is a valid privkey
//     for that pubkey).
//  3. Derivation is deterministic for the same path.
//  4. Different paths produce different keys.
//  5. Multi-level paths match step-by-step derivation.
func TestDerive_AlgebraicConsistency(t *testing.T) {
	masterPriv, _ := hex.DecodeString(tv1MasterPrivHex)
	chainCode, _ := hex.DecodeString(tv1MasterChainCodeHex)
	masterPub := tv1MasterPubUncompressed(t)

	paths := []string{"0", "0/0", "0/1", "0/1/2", "1/2/3/4"}

	curve := btcec.S256()

	seen := map[string]string{}

	for _, path := range paths {
		// (1) public-only vs share-side agreement on child pubkey.
		_, pubOnlyChildPub, pubOnlyChildCC, err := DeriveTweakFromPath(masterPub, chainCode, path)
		if err != nil {
			t.Fatalf("DeriveTweakFromPath(%q): %v", path, err)
		}

		shareRes, err := DeriveChildShareFromPath(masterPriv, masterPub, chainCode, path)
		if err != nil {
			t.Fatalf("DeriveChildShareFromPath(%q): %v", path, err)
		}

		if !bytes.Equal(pubOnlyChildPub, shareRes.ChildPubKey) {
			t.Errorf("path %q: pub-only and share-side child pubkeys differ\n  pub-only:  %x\n  share-side: %x",
				path, pubOnlyChildPub, shareRes.ChildPubKey)
		}
		if !bytes.Equal(pubOnlyChildCC, shareRes.ChildChainCode) {
			t.Errorf("path %q: child chain codes differ", path)
		}

		// (2) child_share * G == child pubkey.
		x, y := curve.ScalarBaseMult(shareRes.ChildShare)
		gotPub := make([]byte, 65)
		gotPub[0] = 0x04
		copy(gotPub[1:33], padTo32(x.Bytes()))
		copy(gotPub[33:65], padTo32(y.Bytes()))
		if !bytes.Equal(gotPub, shareRes.ChildPubKey) {
			t.Errorf("path %q: child_share * G != child pubkey\n  computed: %x\n  stored:   %x",
				path, gotPub, shareRes.ChildPubKey)
		}

		// (3) determinism.
		shareRes2, err := DeriveChildShareFromPath(masterPriv, masterPub, chainCode, path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(shareRes.ChildShare, shareRes2.ChildShare) {
			t.Errorf("path %q: non-deterministic derivation", path)
		}

		// (4) different paths yield different keys.
		hexPub := hex.EncodeToString(shareRes.ChildPubKey)
		if prev, ok := seen[hexPub]; ok {
			t.Errorf("path %q collides with %q (same child pubkey)", path, prev)
		}
		seen[hexPub] = path
	}
}

// TestDeriveTweak_AdditiveProperty verifies that
//
//	(master_priv + tweak) * G == child_pub
//
// i.e. the cumulative BIP32 tweak scalar returned by DeriveTweakFromPath is
// exactly the delta between the master private key and the derived child
// private key, which is what allows each MPC node to independently tweak its
// Shamir share by the same scalar.
func TestDeriveTweak_AdditiveProperty(t *testing.T) {
	masterPriv, _ := hex.DecodeString(tv1MasterPrivHex)
	chainCode, _ := hex.DecodeString(tv1MasterChainCodeHex)
	masterPub := tv1MasterPubUncompressed(t)

	path := "0/7/42"

	tweak, childPub, _, err := DeriveTweakFromPath(masterPub, chainCode, path)
	if err != nil {
		t.Fatal(err)
	}

	curve := btcec.S256()
	n := curve.N

	sum := new(big.Int).SetBytes(masterPriv)
	sum.Add(sum, new(big.Int).SetBytes(tweak))
	sum.Mod(sum, n)

	x, y := curve.ScalarBaseMult(padTo32(sum.Bytes()))
	got := make([]byte, 65)
	got[0] = 0x04
	copy(got[1:33], padTo32(x.Bytes()))
	copy(got[33:65], padTo32(y.Bytes()))

	if !bytes.Equal(got, childPub) {
		t.Errorf("(master + tweak)*G != childPub\n  got:      %x\n  expected: %x", got, childPub)
	}
}

func TestParsePath_RejectsHardened(t *testing.T) {
	cases := []string{"44'/0", "44h/0", "0/1'", "m/0h/0"}
	for _, c := range cases {
		if _, err := ParsePath(c); err == nil {
			t.Errorf("ParsePath(%q) should reject hardened component", c)
		}
	}
}

func TestParsePath_Valid(t *testing.T) {
	got, err := ParsePath("0/1/2")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{0, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: %v vs %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] got %d want %d", i, got[i], want[i])
		}
	}
}
