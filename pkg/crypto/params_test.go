package crypto

// Package-internal test: params_test.go lives in `package crypto` (not
// crypto_test) specifically so it can reach the unexported Argon2id tuning
// constants directly. Its only job is to fail loudly the moment someone
// edits argon2Memory/argon2Iterations/argon2Parallelism/argon2KeyLen —
// a one-line change to any of these quietly weakens (or, for KeyLen,
// breaks) every derived key in the fleet, and none of the black-box tests
// in aes_gcm_test.go would ever notice: they only observe that decryption
// round-trips, which is just as true at Argon2 memory=1 as at memory=64MB.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestArgon2Params_MatchDocumentedValues pins each tuning constant against a
// hardcoded literal (not against itself — comparing a constant to itself can
// never fail). If any of these constants is edited, this test goes red
// immediately, even if every round-trip test still passes.
func TestArgon2Params_MatchDocumentedValues(t *testing.T) {
	t.Parallel()

	const (
		wantMemoryKiB   = 64 * 1024 // 64 MB, per the doc comment on argon2Memory
		wantIterations  = 3
		wantParallelism = 4
		wantKeyLenBytes = 32 // AES-256 requires a 32-byte key
	)

	if argon2Memory != wantMemoryKiB {
		t.Errorf("argon2Memory = %d, want %d (64 MB) — a lower value weakens Argon2id against GPU/ASIC cracking", argon2Memory, wantMemoryKiB)
	}
	if argon2Iterations != wantIterations {
		t.Errorf("argon2Iterations = %d, want %d", argon2Iterations, wantIterations)
	}
	if argon2Parallelism != wantParallelism {
		t.Errorf("argon2Parallelism = %d, want %d", argon2Parallelism, wantParallelism)
	}
	if argon2KeyLen != wantKeyLenBytes {
		t.Errorf("argon2KeyLen = %d, want %d — AES-256 needs a 32-byte key; any other length breaks Encrypt/Decrypt outright", argon2KeyLen, wantKeyLenBytes)
	}
}

// TestKeyDerivation_MatchesIndependentArgon2Computation re-derives the key
// for a fixed passphrase/project/env using the argon2 library directly, with
// the parameters and salt formula hardcoded independently of the production
// constants, and asserts it matches what NewAESGCMEncryptor actually
// produced. Unlike TestArgon2Params_MatchDocumentedValues (which checks the
// constants in isolation), this test would also catch a change to the salt
// formula (keySaltPrefix, or the "prefix|project|env" layout) itself, since
// that formula is reproduced here from scratch rather than by calling any
// package function.
func TestKeyDerivation_MatchesIndependentArgon2Computation(t *testing.T) {
	t.Parallel()

	const passphrase, project, env = "correct-passphrase", "payments", "prod"

	enc, err := NewAESGCMEncryptor(passphrase, project, env, "api_key")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	// Independently reproduce the salt + Argon2id call, using literal
	// parameter values (not the package's own constants) as the spec.
	saltInput := "platform-configctl" + "|" + project + "|" + env
	saltSum := sha256.Sum256([]byte(saltInput))
	independentKey := argon2.IDKey([]byte(passphrase), saltSum[:], 3, 64*1024, 4, 32)
	independentKeyIDSum := sha256.Sum256(independentKey)
	wantKeyID := "sha256:" + hex.EncodeToString(independentKeyIDSum[:16])

	if enc.KeyID() != wantKeyID {
		t.Errorf("KeyID() = %s, want %s (independently computed with memory=64MB iterations=3 parallelism=4 keyLen=32)", enc.KeyID(), wantKeyID)
	}
}
