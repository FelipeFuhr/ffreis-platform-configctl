package crypto_test

import (
	"bytes"
	"testing"

	"github.com/ffreis/platform-configctl/internal/crypto"
)

const (
	testProject = "payments"
	testEnv     = "prod"
)

func newEncryptor(t *testing.T, passphrase, project, env string) *crypto.AESGCMEncryptor {
	t.Helper()
	enc, err := crypto.NewAESGCMEncryptor(passphrase, project, env)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return enc
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	enc := newEncryptor(t, "correct-passphrase", testProject, testEnv)

	plaintext := []byte("super-secret-value")
	ciphertext, keyID, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext must not be empty")
	}
	if keyID == "" {
		t.Fatal("keyID must not be empty")
	}

	recovered, err := enc.Decrypt(ciphertext, keyID)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Errorf("recovered %q, want %q", recovered, plaintext)
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	enc := newEncryptor(t, "passphrase", "project", "env")
	plaintext := []byte("value")

	ct1, _, _ := enc.Encrypt(plaintext)
	ct2, _, _ := enc.Encrypt(plaintext)

	// Two encryptions of the same plaintext must produce different ciphertexts
	// (different random nonces).
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same plaintext produced identical ciphertexts")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	enc1 := newEncryptor(t, "key-one", "project", "env")
	enc2 := newEncryptor(t, "key-two", "project", "env")

	ct, keyID, err := enc1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// enc2 has a different derived key; should return ErrKeyMismatch.
	_, err = enc2.Decrypt(ct, keyID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(*crypto.ErrKeyMismatch); !ok {
		t.Errorf("expected ErrKeyMismatch, got %T: %v", err, err)
	}
}

func TestDecryptCorrupted(t *testing.T) {
	enc := newEncryptor(t, "passphrase", "project", "env")
	ct, keyID, _ := enc.Encrypt([]byte("secret"))

	// Corrupt the ciphertext.
	ct[len(ct)-1] ^= 0xFF

	_, err := enc.Decrypt(ct, keyID)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestKeyDerivationDeterministic(t *testing.T) {
	enc1 := newEncryptor(t, "same-pass", "p", "e")
	enc2 := newEncryptor(t, "same-pass", "p", "e")

	if enc1.KeyID() != enc2.KeyID() {
		t.Errorf("key derivation is not deterministic: %s != %s", enc1.KeyID(), enc2.KeyID())
	}
}

func TestEmptyPassphraseReturnsError(t *testing.T) {
	_, err := crypto.NewAESGCMEncryptor("", "project", "env")
	if err != crypto.ErrKeyUnavailable {
		t.Errorf("expected ErrKeyUnavailable, got %v", err)
	}
}

func TestAADBinding(t *testing.T) {
	// Ciphertext encrypted for project=A must not decrypt for project=B.
	encA := newEncryptor(t, "pass", "projectA", testEnv)
	encB := newEncryptor(t, "pass", "projectB", testEnv)

	ct, _, _ := encA.Encrypt([]byte("value"))
	keyID := encB.KeyID()

	_, err := encB.Decrypt(ct, keyID)
	if err == nil {
		t.Fatal("cross-project decryption must fail")
	}
}
