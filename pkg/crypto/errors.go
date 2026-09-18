package crypto

import "errors"

// ErrKeyUnavailable is returned when the encryption key is not configured.
var ErrKeyUnavailable = errors.New("encryption key unavailable: set CONFIGCTL_SECRET_KEY")

// ErrDecryptionFailed is returned when decryption fails (wrong key, corrupted data).
var ErrDecryptionFailed = errors.New("decryption failed: wrong key or corrupted ciphertext")

// ErrLegacyAAD is returned by Decrypt when a ciphertext was authenticated with
// the pre-v2 AAD (project+env only, no key name). The plaintext is still
// returned. Callers should re-encrypt the value on the next write to migrate it
// to the current AAD format that prevents cross-slot transplant attacks.
var ErrLegacyAAD = errors.New("ciphertext uses legacy AAD (no key binding): re-encrypt to upgrade")

// ErrKeyMismatch is returned when the stored key_id does not match the
// currently derived key. The secret was encrypted with a different key.
type ErrKeyMismatch struct {
	StoredKeyID  string
	CurrentKeyID string
}

func (e *ErrKeyMismatch) Error() string {
	return "key mismatch: stored key_id=" + e.StoredKeyID +
		" current key_id=" + e.CurrentKeyID +
		": set CONFIGCTL_SECRET_KEY to the correct passphrase or rotate the secret"
}
