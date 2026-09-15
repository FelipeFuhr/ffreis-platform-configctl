package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/internal/appconfig"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/crypto"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// secretGetKillSwitchDeps builds a deps wired to a fake store returning a
// single real, encrypted "top-secret-value" item under api_key.
func secretGetKillSwitchDeps(t *testing.T) *deps {
	t.Helper()

	enc, err := crypto.NewAESGCMEncryptor(secretWiringKey, "platform", "dev", "api_key")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte("top-secret-value"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "api_key", Value: string(ciphertext), KeyID: keyID, Version: 1}, nil
			},
		},
	}
}

// TestSecretGetCmd_RevealPrintsPlaintext_WhenKillSwitchUnset proves the
// baseline: with CONFIGCTL_NO_REVEAL unset, --reveal prints the plaintext as
// it always has. This is the control for
// TestSecretGetCmd_RevealRefused_WhenKillSwitchSet below — together they
// prove the kill switch actually changes behaviour rather than --reveal
// being broken outright.
func TestSecretGetCmd_RevealPrintsPlaintext_WhenKillSwitchUnset(t *testing.T) {
	t.Setenv("CONFIGCTL_NO_REVEAL", "")

	d := secretGetKillSwitchDeps(t)
	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")
	_ = cmd.Flags().Set("reveal", "true")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("top-secret-value")) {
		t.Fatalf("expected plaintext in output when kill switch is unset, got: %s", out.String())
	}
}

// TestSecretGetCmd_RevealRefused_WhenKillSwitchSet is the acceptance test
// for the CONFIGCTL_NO_REVEAL kill switch: with it set to a truthy value,
// --reveal must be refused with a clear error, and the plaintext must not
// appear anywhere in configctl's own stdout. This test is only meaningful
// paired with the control above — see that test's doc comment — and was
// verified to fail (red) when the guard in runSecretGet was reverted, then
// pass again once reapplied (see the command's commit description / PR for
// the before/after run).
func TestSecretGetCmd_RevealRefused_WhenKillSwitchSet(t *testing.T) {
	t.Setenv("CONFIGCTL_NO_REVEAL", "1")

	d := secretGetKillSwitchDeps(t)
	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")
	_ = cmd.Flags().Set("reveal", "true")

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want refusal error when CONFIGCTL_NO_REVEAL is set")
	}
	if bytes.Contains(out.Bytes(), []byte("top-secret-value")) {
		t.Fatalf("plaintext leaked to stdout despite CONFIGCTL_NO_REVEAL, got: %s", out.String())
	}
}

// TestSecretGetCmd_KillSwitchDoesNotBlockMetadataOnlyGet proves the kill
// switch is scoped to --reveal: a plain 'secret get' (no --reveal) still
// succeeds and still reports the fingerprint even while the switch is set,
// since that path never prints the plaintext in the first place.
func TestSecretGetCmd_KillSwitchDoesNotBlockMetadataOnlyGet(t *testing.T) {
	t.Setenv("CONFIGCTL_NO_REVEAL", "true")

	d := secretGetKillSwitchDeps(t)
	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil for metadata-only get", err)
	}
	if bytes.Contains(out.Bytes(), []byte("top-secret-value")) {
		t.Fatalf("plaintext must never appear without --reveal, got: %s", out.String())
	}
	wantFingerprint := secretFingerprint([]byte("top-secret-value"))
	if !bytes.Contains(out.Bytes(), []byte(wantFingerprint)) {
		t.Fatalf("fingerprint missing even though the kill switch should not affect it, got: %s", out.String())
	}
}

func TestIsEnvTruthy_RecognisesCommonSpellings(t *testing.T) {
	truthy := []string{"1", "t", "T", "true", "True", "TRUE", "yes", "YES", "y", "on", "ON"}
	for _, v := range truthy {
		t.Run("truthy_"+v, func(t *testing.T) {
			t.Setenv("CONFIGCTL_TEST_TRUTHY", v)
			if !isEnvTruthy("CONFIGCTL_TEST_TRUTHY") {
				t.Errorf("isEnvTruthy(%q) = false, want true", v)
			}
		})
	}

	falsy := []string{"", "0", "f", "false", "False", "no", "N", "off", "garbage"}
	for _, v := range falsy {
		t.Run("falsy_"+v, func(t *testing.T) {
			t.Setenv("CONFIGCTL_TEST_TRUTHY", v)
			if isEnvTruthy("CONFIGCTL_TEST_TRUTHY") {
				t.Errorf("isEnvTruthy(%q) = true, want false", v)
			}
		})
	}
}

func TestSecretFingerprint_DifferentPlaintextsDiffer(t *testing.T) {
	t.Parallel()

	a := secretFingerprint([]byte("value-one"))
	b := secretFingerprint([]byte("value-two"))
	if a == b {
		t.Fatalf("secretFingerprint produced the same digest %q for two different plaintexts", a)
	}
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("secretFingerprint length = %d/%d, want 16 hex chars (8 bytes)", len(a), len(b))
	}
}

func TestSecretFingerprint_StableAcrossCalls(t *testing.T) {
	t.Parallel()

	first := secretFingerprint([]byte("repeatable-value"))
	second := secretFingerprint([]byte("repeatable-value"))
	if first != second {
		t.Fatalf("secretFingerprint is not stable: %q != %q", first, second)
	}
}
