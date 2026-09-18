package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// TestRunSecretRotate_TextOutput_IncludesFailedItemError closes a gap in
// TestRunSecretRotate_TextOutput, which only ever renders a successful
// ("[rotated] key_a", no error suffix) item. writeRotateReport's text
// branch has a distinct code path for a failed item
// (`if item.Error != "" { ... "%s: %s" ... }`) that no test previously
// exercised in TEXT output (only in JSON, via
// TestRunSecretRotate_WriteFailurePreservesOtherItems, which never inspects
// the text rendering at all).
func TestRunSecretRotate_TextOutput_IncludesFailedItemError(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testOldKey, "key_a", "value-a", 1)
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
		setFn: func(_ context.Context, item *store.Item) error {
			return &store.ErrVersionConflict{Key: item.Key, ExpectedVersion: item.Version}
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want error (key_a write failed)")
	}

	out := stdout.String()
	if !strings.Contains(out, "failed=1") {
		t.Fatalf("text output = %q, want it to contain failed=1", out)
	}
	if !strings.Contains(out, "[failed] key_a:") {
		t.Fatalf("text output = %q, want a per-item failed line with an error suffix (\"[failed] key_a: ...\")", out)
	}
}

// TestRunSecretRotate_WriteFailureErrorMessage strengthens
// TestRunSecretRotate_WriteFailurePreservesOtherItems (secret_rotate_test.go),
// which only ever asserted `err != nil` for the partial-failure case — never
// the message content. runSecretRotate's `case report.Failed > 0:` branch
// builds a specific "%d of %d secret(s) failed to rotate" message; this
// pins it, so a regression that returned some OTHER non-nil error (e.g. a
// generic wrap, or the verifyAborted message meant for a different case)
// would be caught.
func TestRunSecretRotate_WriteFailureErrorMessage(t *testing.T) {
	t.Parallel()

	item1 := encryptFor(t, testOldKey, "key_a", "value-a", 1)
	item2 := encryptFor(t, testOldKey, "key_b", "value-b", 1)

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item1, item2}, nil
		},
		setFn: func(_ context.Context, item *store.Item) error {
			if item.Key == "key_a" {
				return &store.ErrVersionConflict{Key: item.Key, ExpectedVersion: item.Version}
			}
			return nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want error (key_a write failed)")
	}
	const want = "1 of 2 secret(s) failed to rotate"
	if err.Error() != want {
		t.Fatalf("error = %q, want exactly %q", err.Error(), want)
	}
}
