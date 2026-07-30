package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

// TestNewSecretRotateCmdFlagWiring pins the command surface.
//
// This is deliberately paranoid about --dry-run: if that flag ever stopped
// reaching secretRotateOpts, `rotate --dry-run` would silently WRITE. A
// unit-tested runSecretRotate proves nothing about that, because the bug would
// live entirely in the wiring this test covers.
func TestNewSecretRotateCmdFlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newSecretRotateCmd(&deps{}, &globalFlags{})

	if cmd.Use != "rotate" {
		t.Errorf("Use = %q, want rotate", cmd.Use)
	}

	for _, name := range []string{"dry-run", "continue-on-error", "project", "env"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}

	// Both safety flags must default OFF: rotate writes for real, and only
	// aborts-all on failure, unless the operator opts otherwise.
	for _, name := range []string{"dry-run", "continue-on-error"} {
		if got := cmd.Flags().Lookup(name).DefValue; got != "false" {
			t.Errorf("--%s default = %q, want false", name, got)
		}
	}

	// The long help must document the two-phase guarantee and resumability —
	// this is the operator's only warning about what a partial run leaves behind.
	for _, phrase := range []string{"CONFIGCTL_OLD_SECRET_KEY", "--dry-run", "resumable"} {
		if !strings.Contains(cmd.Long, phrase) {
			t.Errorf("long help does not mention %q", phrase)
		}
	}

	if cmd.Args == nil {
		t.Error("Args is nil; rotate takes no positional arguments and should reject them")
	}
}

// TestSecretRotateCmdRejectsPositionalArgs verifies a stray argument is an error
// rather than being silently ignored — a mistyped `rotate prod` must not run a
// full rotation against whatever --env happens to default to.
func TestSecretRotateCmdRejectsPositionalArgs(t *testing.T) {
	t.Parallel()

	cmd := newSecretRotateCmd(&deps{}, &globalFlags{})
	if err := cmd.Args(cmd, []string{"unexpected"}); err == nil {
		t.Error("positional argument accepted; want an error")
	}
}

// TestVerifyAlreadyRotatedReportsCorruptedItem covers the case where an item's
// stored key_id already matches the NEW key but its ciphertext will not decrypt.
//
// That item is skipped by the rotation path (it looks done), so this defensive
// re-verification is the only thing standing between a corrupted secret and a
// report that says everything is fine. It must surface as failed.
func TestVerifyAlreadyRotatedReportsCorruptedItem(t *testing.T) {
	t.Parallel()

	// Encrypt under the NEW key so key_id matches, then corrupt the ciphertext.
	item := encryptFor(t, testNewKey, "stripe_key", "sk_live_abc123", 1)
	item.Value = item.Value[:len(item.Value)-4] + "XXXX"

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
		setFn: func(context.Context, *store.Item) error {
			t.Error("store.Set called for a corrupted already-rotated item; nothing should be written")
			return nil
		},
	}

	var buf bytes.Buffer
	err := runSecretRotate(context.Background(),
		rotateDeps(testNewKey, testOldKey, st),
		secretRotateOpts{project: testRotateProject, env: testRotateEnv, output: formatJSON},
		&buf, stubUpdatedBy)

	if err == nil {
		t.Fatal("want an error for a corrupted secret, got nil")
	}
	out := buf.String()
	if !strings.Contains(out, `"failed":1`) {
		t.Errorf("want failed=1 in the report, got: %s", out)
	}
	if !strings.Contains(out, "already on target key but failed to decrypt") {
		t.Errorf("the report should explain the item is on the target key yet undecryptable, got: %s", out)
	}
	if strings.Contains(out, `"already_rotated":1`) {
		t.Errorf("a corrupted item must NOT be counted as already_rotated, got: %s", out)
	}
}

// TestVerifyAlreadyRotatedAcceptsHealthyItem is the counterpart: an item genuinely
// on the new key verifies and is left untouched, with no write attempted.
func TestVerifyAlreadyRotatedAcceptsHealthyItem(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testNewKey, "stripe_key", "sk_live_abc123", 1)

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
		setFn: func(context.Context, *store.Item) error {
			t.Error("store.Set called for an already-rotated item; it must be left untouched")
			return nil
		},
	}

	var buf bytes.Buffer
	if err := runSecretRotate(context.Background(),
		rotateDeps(testNewKey, testOldKey, st),
		secretRotateOpts{project: testRotateProject, env: testRotateEnv, output: formatJSON},
		&buf, stubUpdatedBy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"already_rotated":1`) {
		t.Errorf("want already_rotated=1, got: %s", out)
	}
	if !strings.Contains(out, `"rotated":0`) {
		t.Errorf("want rotated=0, got: %s", out)
	}
}

// TestRotateWithoutOldKeyStillVerifiesAlreadyRotatedItems verifies a rotation
// run AFTER a completed rotation succeeds even with CONFIGCTL_OLD_SECRET_KEY
// unset — the old key is only needed for items still on the old key. Operators
// unset it once rotation completes, and that must not turn a clean re-run into
// a failure.
func TestRotateWithoutOldKeyStillVerifiesAlreadyRotatedItems(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testNewKey, "stripe_key", "sk_live_abc123", 1)

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
	}

	var buf bytes.Buffer
	if err := runSecretRotate(context.Background(),
		rotateDeps(testNewKey, "", st), // no old key at all
		secretRotateOpts{project: testRotateProject, env: testRotateEnv, output: formatJSON},
		&buf, stubUpdatedBy); err != nil {
		t.Fatalf("re-run with no old key should succeed, got: %v (output: %s)", err, buf.String())
	}
	if !strings.Contains(buf.String(), `"already_rotated":1`) {
		t.Errorf("want already_rotated=1, got: %s", buf.String())
	}
}
