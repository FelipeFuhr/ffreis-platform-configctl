package crypto

// Encryptor handles symmetric encryption and decryption of secret values.
// Implementations must be safe for concurrent use.
type Encryptor interface {
	// Encrypt encrypts plaintext and returns base64-encoded ciphertext and
	// the key fingerprint (key_id) to store alongside the ciphertext.
	Encrypt(plaintext []byte) (ciphertext []byte, keyID string, err error)

	// Decrypt decrypts ciphertext previously produced by Encrypt.
	// storedKeyID is the key_id retrieved from the store; if it does not
	// match the current key the implementation must return ErrKeyMismatch.
	Decrypt(ciphertext []byte, storedKeyID string) (plaintext []byte, err error)

	// KeyID returns the fingerprint of the currently active derived key.
	KeyID() string
}
