package tron

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

const (
	// TronAddressPrefix is the mainnet/testnet prefix byte for TRON addresses.
	TronAddressPrefix = 0x41
	// AddressLength is the expected length of a TRON address string (Base58Check encoded).
	AddressLength = 34
)

// base58Alphabet is Bitcoin's Base58 alphabet (no 0, O, I, l).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// AddressFromPublicKey derives a TRON address from an uncompressed secp256k1 public key.
// The input should be 65 bytes (0x04 prefix + 64 bytes) or 64 bytes (no prefix).
func AddressFromPublicKey(pubKey []byte) (string, error) {
	// Strip 0x04 prefix if present
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		pubKey = pubKey[1:]
	}
	if len(pubKey) != 64 {
		return "", fmt.Errorf("invalid public key length: expected 64 bytes, got %d", len(pubKey))
	}

	// Step 1: Keccak-256 hash of the public key
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubKey)
	hash := hasher.Sum(nil)

	// Step 2: Take last 20 bytes
	addrBytes := hash[len(hash)-20:]

	// Step 3: Prepend 0x41 (TRON prefix)
	payload := make([]byte, 21)
	payload[0] = TronAddressPrefix
	copy(payload[1:], addrBytes)

	// Step 4: Base58Check encode
	return base58CheckEncode(payload), nil
}

// ValidateAddress checks if a TRON address is valid.
// Returns (formatValid, reason).
func ValidateAddress(address string) (bool, string) {
	if len(address) == 0 {
		return false, "address is empty"
	}

	if len(address) != AddressLength {
		return false, fmt.Sprintf("invalid length: expected %d, got %d", AddressLength, len(address))
	}

	if !strings.HasPrefix(address, "T") {
		return false, "address must start with 'T'"
	}

	// Check valid Base58 characters
	for _, c := range address {
		if !strings.ContainsRune(base58Alphabet, c) {
			return false, fmt.Sprintf("invalid Base58 character: %c", c)
		}
	}

	// Decode Base58Check and verify checksum
	decoded, err := base58CheckDecode(address)
	if err != nil {
		return false, fmt.Sprintf("Base58Check decode failed: %v", err)
	}

	// Check TRON prefix
	if decoded[0] != TronAddressPrefix {
		return false, fmt.Sprintf("invalid prefix byte: expected 0x%02x, got 0x%02x", TronAddressPrefix, decoded[0])
	}

	return true, ""
}

// base58CheckEncode encodes a byte slice with Base58Check (double SHA-256 checksum).
func base58CheckEncode(payload []byte) string {
	// Double SHA-256 for checksum
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	checksum := second[:4]

	// Append checksum
	full := append(payload, checksum...)

	// Convert to big.Int for Base58 encoding
	num := new(big.Int).SetBytes(full)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var encoded []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		encoded = append([]byte{base58Alphabet[mod.Int64()]}, encoded...)
	}

	// Add leading '1's for each leading zero byte
	for _, b := range full {
		if b != 0 {
			break
		}
		encoded = append([]byte{'1'}, encoded...)
	}

	return string(encoded)
}

// base58CheckDecode decodes a Base58Check string and verifies the checksum.
func base58CheckDecode(address string) ([]byte, error) {
	// Decode Base58
	num := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range address {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid Base58 character: %c", c)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}

	// Convert to bytes (25 bytes: 1 prefix + 20 address + 4 checksum)
	decoded := num.Bytes()

	// Pad with leading zeros if needed
	for i := 0; i < len(address) && address[i] == '1'; i++ {
		decoded = append([]byte{0}, decoded...)
	}

	// Ensure minimum length
	if len(decoded) < 25 {
		// Pad to 25 bytes
		padded := make([]byte, 25)
		copy(padded[25-len(decoded):], decoded)
		decoded = padded
	}

	// Split payload and checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	// Verify checksum
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])

	for i := 0; i < 4; i++ {
		if checksum[i] != second[i] {
			return nil, fmt.Errorf("checksum mismatch")
		}
	}

	return payload, nil
}
