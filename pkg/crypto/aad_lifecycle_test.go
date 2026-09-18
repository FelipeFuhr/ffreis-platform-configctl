package crypto_test

import (
	"errors"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/crypto"
)

// TestKeyID_DifferentPassphraseProducesDifferentKeyID is the mirror of
// TestKeyDerivationDeterministic (same passphrase -> same KeyID): here the
// ONLY thing that varies is the passphrase, and the KeyID must differ. This
// is what lets `secret rotate` detect "old passphrase probe succeeded, so
// this really is the previous key" versus "still on the current key" — if
// two different passphrases ever collided on KeyID, rotation could silently
// skip re-encrypting a secret.
func TestKeyID_DifferentPassphraseProducesDifferentKeyID(t *testing.T) {
	t.Parallel()

	enc1 := newEncryptor(t, "passphrase-one", "p", "e", "k")
	enc2 := newEncryptor(t, "passphrase-two", "p", "e", "k")

	if enc1.KeyID() == enc2.KeyID() {
		t.Fatalf("two different passphrases produced the same KeyID %q", enc1.KeyID())
	}
}

// TestAADBinding_LegacyFallback_ReencryptProducesCurrentAAD extends
// TestAADBinding_LegacyFallback (which only proves the fallback decrypts a
// pre-migration blob) by completing the migration path the doc comment on
// ErrLegacyAAD promises: "callers should re-encrypt the value on the next
// write to migrate it to the current AAD format." This test performs that
// re-encrypt and proves the RESULT no longer needs the legacy fallback at
// all — i.e. a second Decrypt succeeds via the primary AAD path with no
// ErrLegacyAAD. Without this, a regression that silently kept re-encrypting
// with the legacy AAD (a no-op migration) would pass every existing test.
func TestAADBinding_LegacyFallback_ReencryptProducesCurrentAAD(t *testing.T) {
	t.Parallel()

	const project, env, keyName = "payments", "prod", "some_key"

	legacyEnc, err := crypto.NewLegacyAESGCMEncryptorForTest("pass", project, env)
	if err != nil {
		t.Fatalf("NewLegacyAESGCMEncryptorForTest: %v", err)
	}
	legacyCT, legacyKeyID, err := legacyEnc.Encrypt([]byte("old-value"))
	if err != nil {
		t.Fatalf("legacy Encrypt: %v", err)
	}

	current := newEncryptor(t, "pass", project, env, keyName)

	// Step 1: decrypting the legacy blob must report ErrLegacyAAD (already
	// covered by TestAADBinding_LegacyFallback; repeated here as the
	// precondition for step 2).
	plaintext, err := current.Decrypt(legacyCT, legacyKeyID)
	if !errors.Is(err, crypto.ErrLegacyAAD) {
		t.Fatalf("precondition failed: expected ErrLegacyAAD, got %v", err)
	}

	// Step 2: re-encrypt the recovered plaintext with the current encryptor,
	// exactly as the migration path does on the next `secret set`/rotate.
	migratedCT, migratedKeyID, err := current.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}

	// Step 3: decrypting the migrated blob must succeed via the PRIMARY AAD
	// — no ErrLegacyAAD this time. A nil error (not errors.Is ErrLegacyAAD)
	// is the proof the ciphertext now carries the new, key-name-bound AAD.
	got, err := current.Decrypt(migratedCT, migratedKeyID)
	if err != nil {
		t.Fatalf("decrypt after migration: %v (want plain success, no legacy fallback)", err)
	}
	if errors.Is(err, crypto.ErrLegacyAAD) {
		t.Fatal("decrypt after re-encrypt still reports ErrLegacyAAD — migration did not upgrade the AAD format")
	}
	if string(got) != "old-value" {
		t.Fatalf("recovered %q after migration, want %q", got, "old-value")
	}
}

// TestDecryptCorrupted_MiddleByte complements TestDecryptCorrupted (which
// flips the final byte, landing squarely in the GCM auth tag). Flipping a
// byte in the middle of the payload instead hits the ciphertext body rather
// than the tag — a distinct code path inside GCM's Open — and must fail the
// same way.
func TestDecryptCorrupted_MiddleByte(t *testing.T) {
	t.Parallel()

	enc := newEncryptor(t, "passphrase", "project", "env", "key")
	ct, keyID, err := enc.Encrypt([]byte("a secret value long enough to have a real middle"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	mid := len(ct) / 2
	ct[mid] ^= 0xFF

	_, err = enc.Decrypt(ct, keyID)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for a corrupted middle byte, got %v", err)
	}
}
