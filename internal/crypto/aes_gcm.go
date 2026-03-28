package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 64 * 1024 // 64 MB
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2KeyLen      = 32
	nonceSizeGCM      = 12
	keySaltPrefix     = "platform-configctl"
)

// AESGCMEncryptor implements Encryptor using AES-256-GCM with Argon2id key
// derivation. The salt is deterministic so the same passphrase+project+env
// always produces the same derived key, enabling key_id rotation detection.
type AESGCMEncryptor struct {
	derivedKey []byte
	keyID      string
	aad        []byte // additional authenticated data binding ciphertext to location
}

// NewAESGCMEncryptor derives a 256-bit key from passphrase using Argon2id
// with a deterministic salt from project+env. Returns ErrKeyUnavailable if
// passphrase is empty.
func NewAESGCMEncryptor(passphrase, project, env string) (*AESGCMEncryptor, error) {
	if passphrase == "" {
		return nil, ErrKeyUnavailable
	}

	// Deterministic salt: SHA-256(keySaltPrefix + project + env)
	saltInput := fmt.Sprintf("%s|%s|%s", keySaltPrefix, project, env)
	saltRaw := sha256.Sum256([]byte(saltInput))
	salt := saltRaw[:]

	key := argon2.IDKey(
		[]byte(passphrase),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLen,
	)

	// keyID is the hex fingerprint of the derived key (first 16 bytes of SHA-256).
	h := sha256.Sum256(key)
	keyID := fmt.Sprintf("sha256:%x", h[:16])

	// AAD binds the ciphertext to its logical location.
	aad := []byte(fmt.Sprintf("project=%s|env=%s", project, env))

	return &AESGCMEncryptor{
		derivedKey: key,
		keyID:      keyID,
		aad:        aad,
	}, nil
}

func (e *AESGCMEncryptor) KeyID() string { return e.keyID }

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, string, error) {
	block, err := aes.NewCipher(e.derivedKey)
	if err != nil {
		return nil, "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, nonceSizeGCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+auth_tag to nonce.
	sealed := gcm.Seal(nonce, nonce, plaintext, e.aad)

	// Encode as base64 for safe DynamoDB storage.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(sealed)))
	base64.StdEncoding.Encode(encoded, sealed)

	return encoded, e.keyID, nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext []byte, storedKeyID string) ([]byte, error) {
	if storedKeyID != "" && storedKeyID != e.keyID {
		return nil, &ErrKeyMismatch{
			StoredKeyID:  storedKeyID,
			CurrentKeyID: e.keyID,
		}
	}

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(raw, ciphertext)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	raw = raw[:n]

	block, err := aes.NewCipher(e.derivedKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(raw) < nonceSizeGCM {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertextRaw := raw[:nonceSizeGCM], raw[nonceSizeGCM:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextRaw, e.aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
