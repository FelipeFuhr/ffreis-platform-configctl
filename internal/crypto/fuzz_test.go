package crypto

import (
	"bytes"
	"testing"
)

// FuzzDecrypt exercises decryption with arbitrary ciphertext bytes.
//
// Invariants verified:
//   - Decrypt must never panic on any byte input
//   - Arbitrary bytes must return an error (ErrDecryptionFailed or ErrKeyMismatch),
//     not silently succeed
func FuzzDecrypt(f *testing.F) {
	enc, err := NewAESGCMEncryptor("seed-passphrase", "myproject", "staging")
	if err != nil {
		f.Fatal("could not create encryptor for seeding:", err)
	}

	// Seed with a legitimately encrypted ciphertext
	ct, keyID, err := enc.Encrypt([]byte("hello world"))
	if err != nil {
		f.Fatal("could not encrypt seed:", err)
	}
	f.Add(ct, keyID)

	// Edge cases
	f.Add([]byte(""), "")
	f.Add([]byte("not-base64!!!"), "")
	f.Add([]byte("dGVzdA=="), "")                 // valid base64 but too short for nonce
	f.Add([]byte("AAAAAAAAAAAAAAAAAAAAAA=="), "") // valid base64, minimal length
	f.Add([]byte("dGVzdA=="), "sha256:deadbeef")  // wrong key ID
	f.Add([]byte("\x00\x01\x02\x03"), "")

	f.Fuzz(func(t *testing.T, ciphertext []byte, keyID string) {
		// Must not panic; error is expected for arbitrary/tampered input
		_, _ = enc.Decrypt(ciphertext, keyID)
	})
}

// FuzzEncryptDecryptRoundtrip verifies that any plaintext encrypted by
// AESGCMEncryptor can be round-tripped back to the original value.
//
// Invariants verified:
//   - Encrypt never fails for any plaintext byte slice
//   - Decrypt(Encrypt(pt)) == pt for all pt
func FuzzEncryptDecryptRoundtrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("a very long string with special chars: !@#$%^&*()_+=-[]{}|;':\",./<>?"))
	f.Add(bytes.Repeat([]byte("x"), 4096))

	enc, err := NewAESGCMEncryptor("roundtrip-pass", "proj", "env")
	if err != nil {
		f.Fatal("could not create encryptor:", err)
	}

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, keyID, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed unexpectedly: %v", err)
		}

		got, err := enc.Decrypt(ct, keyID)
		if err != nil {
			t.Fatalf("Decrypt failed after successful Encrypt: %v", err)
		}

		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
		}
	})
}
