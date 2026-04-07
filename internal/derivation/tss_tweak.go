package derivation

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TweakTSSDataForPath applies a BIP32 non-hardened derivation tweak to a
// tss-lib LocalPartySaveData in place of a fresh DKG for the child key.
//
// Math:
//
//	new Xi       = old Xi + delta          (mod n)
//	new BigXj[j] = old BigXj[j] + delta*G  (for all parties j)
//	new ECDSAPub = old ECDSAPub + delta*G
//
// where delta is the cumulative BIP32 tweak scalar for the path. Every party
// applies the same delta to its own saveData, so the reconstructed key becomes
// master + delta = the BIP32 child key, while every party still holds only a
// Shamir share.
//
// Returns the tweaked saveData, the child public key (uncompressed 65 bytes),
// and the child chain code.
func TweakTSSDataForPath(
	master *keygen.LocalPartySaveData,
	masterPubKey []byte,
	masterChainCode []byte,
	path string,
) (*keygen.LocalPartySaveData, []byte, []byte, error) {
	tweakBytes, childPub, childCC, err := DeriveTweakFromPath(masterPubKey, masterChainCode, path)
	if err != nil {
		return nil, nil, nil, err
	}

	delta := new(big.Int).SetBytes(tweakBytes)
	curve := tss.S256()
	curveN := curve.Params().N

	// Copy saveData so we don't mutate the caller's master data.
	tweaked := *master

	// new Xi
	if master.Xi == nil {
		return nil, nil, nil, fmt.Errorf("master saveData has nil Xi")
	}
	tweaked.Xi = new(big.Int).Add(master.Xi, delta)
	tweaked.Xi.Mod(tweaked.Xi, curveN)

	// delta*G — applied to every BigXj and to ECDSAPub
	deltaX, deltaY := curve.ScalarBaseMult(tweakBytes)

	// new BigXj
	newBigXj := make([]*crypto.ECPoint, len(master.BigXj))
	for i, p := range master.BigXj {
		if p == nil {
			return nil, nil, nil, fmt.Errorf("master saveData BigXj[%d] is nil", i)
		}
		nx, ny := curve.Add(p.X(), p.Y(), deltaX, deltaY)
		np, nerr := crypto.NewECPoint(curve, nx, ny)
		if nerr != nil {
			return nil, nil, nil, fmt.Errorf("tweak BigXj[%d]: %w", i, nerr)
		}
		newBigXj[i] = np
	}
	tweaked.BigXj = newBigXj

	// new ECDSAPub
	if master.ECDSAPub == nil {
		return nil, nil, nil, fmt.Errorf("master saveData has nil ECDSAPub")
	}
	newPubX, newPubY := curve.Add(master.ECDSAPub.X(), master.ECDSAPub.Y(), deltaX, deltaY)
	newPub, err := crypto.NewECPoint(curve, newPubX, newPubY)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tweak ECDSAPub: %w", err)
	}
	tweaked.ECDSAPub = newPub

	return &tweaked, childPub, childCC, nil
}
