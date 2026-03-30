package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

// ShareData holds a key share and associated metadata.
type ShareData struct {
	Share     []byte `json:"share"`      // The actual key share (secret)
	PublicKey []byte `json:"public_key"` // Combined public key
	ChainCode []byte `json:"chain_code"` // BIP32 chain code
}

// Metadata holds non-secret info about a key.
type Metadata struct {
	KeyID     string    `json:"key_id"`
	Path      string    `json:"path"`
	Threshold int       `json:"threshold"`
	Parties   int       `json:"parties"`
	CreatedAt time.Time `json:"created_at"`
}

// Store manages encrypted key share persistence.
type Store struct {
	baseDir    string
	passphrase string
}

// NewStore creates a new keystore at the given directory.
func NewStore(baseDir, passphrase string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create keystore dir: %w", err)
	}
	return &Store{baseDir: baseDir, passphrase: passphrase}, nil
}

// Save encrypts and stores a key share with its metadata.
func (s *Store) Save(keyID string, share *ShareData, meta *Metadata) error {
	keyDir := filepath.Join(s.baseDir, keyID)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	// Encrypt and save the share
	plaintext, err := json.Marshal(share)
	if err != nil {
		return fmt.Errorf("marshal share: %w", err)
	}

	encrypted, err := encrypt(plaintext, s.passphrase)
	if err != nil {
		return fmt.Errorf("encrypt share: %w", err)
	}

	if err := os.WriteFile(filepath.Join(keyDir, "share.enc"), encrypted, 0600); err != nil {
		return fmt.Errorf("write share: %w", err)
	}

	// Save public key (not secret)
	if err := os.WriteFile(filepath.Join(keyDir, "public_key"), share.PublicKey, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	// Save chain code (not secret)
	if err := os.WriteFile(filepath.Join(keyDir, "chain_code"), share.ChainCode, 0644); err != nil {
		return fmt.Errorf("write chain code: %w", err)
	}

	// Save metadata
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	if err := os.WriteFile(filepath.Join(keyDir, "metadata.json"), metaJSON, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

// Load decrypts and returns a key share.
func (s *Store) Load(keyID string) (*ShareData, *Metadata, error) {
	keyDir := filepath.Join(s.baseDir, keyID)

	// Read encrypted share
	encrypted, err := os.ReadFile(filepath.Join(keyDir, "share.enc"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("key %q not found", keyID)
		}
		return nil, nil, fmt.Errorf("read share: %w", err)
	}

	plaintext, err := decrypt(encrypted, s.passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt share: %w", err)
	}

	var share ShareData
	if err := json.Unmarshal(plaintext, &share); err != nil {
		return nil, nil, fmt.Errorf("unmarshal share: %w", err)
	}

	// Read metadata
	metaJSON, err := os.ReadFile(filepath.Join(keyDir, "metadata.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta Metadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &share, &meta, nil
}

// Exists checks if a key share exists.
func (s *Store) Exists(keyID string) bool {
	keyDir := filepath.Join(s.baseDir, keyID)
	_, err := os.Stat(filepath.Join(keyDir, "share.enc"))
	return err == nil
}

// Delete removes a key share and all associated files.
func (s *Store) Delete(keyID string) error {
	keyDir := filepath.Join(s.baseDir, keyID)
	return os.RemoveAll(keyDir)
}

// deriveKey uses Argon2id to derive an AES-256 key from a passphrase and salt.
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// encrypt uses AES-256-GCM to encrypt plaintext.
func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	// Generate random salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Output: salt (16) + nonce (12) + ciphertext + tag (16)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decrypt uses AES-256-GCM to decrypt ciphertext.
func decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 16+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt := data[:16]
	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < 16+nonceSize {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := data[16 : 16+nonceSize]
	ciphertext := data[16+nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
