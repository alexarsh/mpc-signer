package derivation

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

// ChildShareResult holds the output of a child key derivation.
type ChildShareResult struct {
	ChildShare    []byte // derived child key share
	ChildPubKey   []byte // derived child public key (uncompressed, 65 bytes)
	ChildChainCode []byte // derived child chain code
}

// DeriveChildShare performs BIP32 non-hardened child key derivation on a key share.
//
// This is the core MPC trick: since non-hardened BIP32 derivation is:
//
//	child_key = parent_key + IL (mod n)
//
// And IL depends only on the PUBLIC key + chain code + index,
// each node can independently compute:
//
//	child_share_i = parent_share_i + IL (mod n)
//
// Without knowing the full parent key or communicating with the other node.
func DeriveChildShare(
	parentShare []byte,
	parentPubKey []byte, // uncompressed, 65 bytes (0x04 + X + Y)
	chainCode []byte,
	index uint32,
) (*ChildShareResult, error) {
	if index >= 0x80000000 {
		return nil, fmt.Errorf("hardened derivation (index >= 0x80000000) not supported on shares — only the DKG master level uses hardened paths")
	}

	// Compress the public key for HMAC input (BIP32 uses compressed keys)
	compressedPub, err := compressPublicKey(parentPubKey)
	if err != nil {
		return nil, fmt.Errorf("compress public key: %w", err)
	}

	// HMAC-SHA512(chain_code, compressed_pub || index)
	data := make([]byte, 33+4)
	copy(data[:33], compressedPub)
	binary.BigEndian.PutUint32(data[33:], index)

	mac := hmac.New(sha512.New, chainCode)
	mac.Write(data)
	I := mac.Sum(nil)

	IL := I[:32] // key tweak
	IR := I[32:] // child chain code

	// Parse IL as big.Int
	ilInt := new(big.Int).SetBytes(IL)
	curveOrder := btcec.S256().N

	// Check IL < curve order (extremely unlikely to fail, but BIP32 spec requires it)
	if ilInt.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("IL >= curve order — invalid derivation, try next index")
	}

	// child_share = parent_share + IL (mod curve order)
	parentShareInt := new(big.Int).SetBytes(parentShare)
	childShareInt := new(big.Int).Add(parentShareInt, ilInt)
	childShareInt.Mod(childShareInt, curveOrder)

	// Check child share is not zero
	if childShareInt.Sign() == 0 {
		return nil, fmt.Errorf("derived child share is zero — invalid, try next index")
	}

	// Derive child public key: parent_pub + IL*G
	ilX, ilY := btcec.S256().ScalarBaseMult(IL)
	parentX, parentY := unmarshalPubKey(parentPubKey)
	childX, childY := btcec.S256().Add(parentX, parentY, ilX, ilY)

	// Marshal child public key (uncompressed)
	childPubKey := marshalUncompressed(childX, childY)

	// Pad child share to 32 bytes
	childShareBytes := padTo32(childShareInt.Bytes())

	return &ChildShareResult{
		ChildShare:     childShareBytes,
		ChildPubKey:    childPubKey,
		ChildChainCode: IR,
	}, nil
}

// ParsePath parses a BIP32 path string like "0/42" into a list of indices.
// Returns an error if any component is hardened (contains ').
func ParsePath(path string) ([]uint32, error) {
	// Strip leading m/ if present
	path = strings.TrimPrefix(path, "m/")

	parts := strings.Split(path, "/")
	indices := make([]uint32, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H") {
			return nil, fmt.Errorf("hardened derivation not allowed after DKG: %q", part)
		}

		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path component %q: %w", part, err)
		}

		indices = append(indices, uint32(idx))
	}

	if len(indices) == 0 {
		return nil, fmt.Errorf("empty path")
	}

	return indices, nil
}

// DeriveChildShareFromPath derives through multiple levels (e.g., "0/42" = two derivations).
func DeriveChildShareFromPath(
	parentShare []byte,
	parentPubKey []byte,
	chainCode []byte,
	path string,
) (*ChildShareResult, error) {
	indices, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	currentShare := parentShare
	currentPubKey := parentPubKey
	currentChainCode := chainCode

	var result *ChildShareResult
	for _, idx := range indices {
		result, err = DeriveChildShare(currentShare, currentPubKey, currentChainCode, idx)
		if err != nil {
			return nil, fmt.Errorf("derive at index %d: %w", idx, err)
		}
		currentShare = result.ChildShare
		currentPubKey = result.ChildPubKey
		currentChainCode = result.ChildChainCode
	}

	return result, nil
}

// compressPublicKey converts a 65-byte uncompressed key to 33-byte compressed format.
func compressPublicKey(pubKey []byte) ([]byte, error) {
	if len(pubKey) == 33 {
		return pubKey, nil // already compressed
	}
	if len(pubKey) != 65 || pubKey[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key (len=%d)", len(pubKey))
	}

	x, y := unmarshalPubKey(pubKey)
	compressed := make([]byte, 33)
	if new(big.Int).SetBytes(y.Bytes()).Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	xBytes := padTo32(x.Bytes())
	copy(compressed[1:], xBytes)
	return compressed, nil
}

func unmarshalPubKey(pubKey []byte) (*big.Int, *big.Int) {
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		x := new(big.Int).SetBytes(pubKey[1:33])
		y := new(big.Int).SetBytes(pubKey[33:65])
		return x, y
	}
	return nil, nil
}

func marshalUncompressed(x, y *big.Int) []byte {
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	xBytes := padTo32(x.Bytes())
	yBytes := padTo32(y.Bytes())
	copy(pubKey[1:33], xBytes)
	copy(pubKey[33:65], yBytes)
	return pubKey
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
