package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

const (
	testRotateProject = "payments"
	testRotateEnv     = "prod"
	testOldKey        = "old-passphrase-0123456789"
	testNewKey        = "new-passphrase-9876543210"
)

func stubUpdatedBy(_ context.Context, _ *deps) string { return "tester" }

// encryptFor encrypts plaintext for item key `key` under `passphrase`,
// returning a ready-to-store *store.Item.
func encryptFor(t *testing.T, passphrase, key, plaintext string, version int64) *store.Item {
	t.Helper()
	enc, err := crypto.NewAESGCMEncryptor(passphrase, testRotateProject, testRotateEnv, key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	h := sha256.Sum256(ciphertext)
	return &store.Item{
		Project:   testRotateProject,
		Env:       testRotateEnv,
		Key:       key,
		Value:     string(ciphertext),
		Type:      store.ItemTypeSecret,
		Encrypted: true,
		KeyID:     keyID,
		Version:   version,
		Checksum:  fmt.Sprintf(checksumFormatSHA256, h),
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedBy: "someone",
	}
}

// decryptWith asserts item.Value decrypts to want under passphrase, using
// item.KeyID as the stored fingerprint (mirrors what 'secret get --reveal' does).
func decryptWith(t *testing.T, passphrase string, item *store.Item, want string) {
	t.Helper()
	enc, err := crypto.NewAESGCMEncryptor(passphrase, testRotateProject, testRotateEnv, item.Key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	got, err := enc.Decrypt([]byte(item.Value), item.KeyID)
	if err != nil {
		t.Fatalf("Decrypt(%s): %v", item.Key, err)
	}
	if string(got) != want {
		t.Fatalf("decrypted %s = %q, want %q", item.Key, got, want)
	}
}

func rotateDeps(secretKey, oldSecretKey string, st store.Store) *deps {
	return &deps{
		cfg:   &appconfig.Config{SecretKey: secretKey, OldSecretKey: oldSecretKey},
		log:   noopLogger{},
		store: st,
	}
}

func TestRunSecretRotate_RequiresProjectEnv(t *testing.T) {
	t.Parallel()

	d := rotateDeps(testNewKey, testOldKey, fakeStore{})
	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{project: "", env: testRotateEnv}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want error")
	}
}

func TestRunSecretRotate_RequiresSecretKey(t *testing.T) {
	t.Parallel()

	// fakeStore{} panics on any Get/Set/List call — proves the command never
	// reaches the store when the new key is missing.
	d := rotateDeps("", testOldKey, fakeStore{})
	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{project: testRotateProject, env: testRotateEnv}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want error")
	}
}

func TestRunSecretRotate_EmptyTable(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{}, nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{project: testRotateProject, env: testRotateEnv}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if !strings.Contains(stdout.String(), "total=0") {
		t.Fatalf("stdout = %q, want total=0", stdout.String())
	}
}

func TestRunSecretRotate_ListError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return nil, errors.New("dynamodb unavailable")
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{project: testRotateProject, env: testRotateEnv}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want error")
	}
}

func TestRunSecretRotate_HappyPath(t *testing.T) {
	t.Parallel()

	item1 := encryptFor(t, testOldKey, "stripe_key", "sk_live_abc", 3)
	item2 := encryptFor(t, testOldKey, "db_password", "hunter2", 1)

	var setCalls []*store.Item
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item1, item2}, nil
		},
		setFn: func(_ context.Context, item *store.Item) error {
			setCalls = append(setCalls, item)
			return nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	if len(setCalls) != 2 {
		t.Fatalf("store.Set called %d times, want 2", len(setCalls))
	}
	for _, item := range setCalls {
		if item.KeyID == item1.KeyID { // still equal to old key's fingerprint would be a bug
			t.Fatalf("rotated item %s kept the old key_id", item.Key)
		}
	}

	byKey := map[string]*store.Item{}
	for _, item := range setCalls {
		byKey[item.Key] = item
	}
	decryptWith(t, testNewKey, byKey["stripe_key"], "sk_live_abc")
	decryptWith(t, testNewKey, byKey["db_password"], "hunter2")

	// Version is preserved from the read so the store's optimistic-lock check
	// still protects against concurrent modification.
	if byKey["stripe_key"].Version != 3 {
		t.Fatalf("stripe_key Version = %d, want 3 (preserved)", byKey["stripe_key"].Version)
	}

	report := decodeRotateReport(t, stdout.Bytes())
	if report.Total != 2 || report.Rotated != 2 || report.Failed != 0 {
		t.Fatalf("report = %+v, want total=2 rotated=2 failed=0", report)
	}

	// Never leak plaintext or key material into the report.
	raw := stdout.String()
	for _, leaked := range []string{"sk_live_abc", "hunter2", testOldKey, testNewKey} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("report leaked secret material: contains %q\n%s", leaked, raw)
		}
	}
}

func TestRunSecretRotate_WrongOldKey(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testOldKey, "stripe_key", "sk_live_abc", 1)

	// fakeStore has no setFn — any Set call panics the test.
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
	}
	d := rotateDeps(testNewKey, "totally-wrong-passphrase", st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want abort error")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("error = %q, want it to mention 'aborted'", err.Error())
	}
	if strings.Contains(err.Error(), "sk_live_abc") {
		t.Fatalf("error leaked plaintext: %q", err.Error())
	}
}

func TestRunSecretRotate_MissingOldKey(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testOldKey, "stripe_key", "sk_live_abc", 1)

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
	}
	d := rotateDeps(testNewKey, "", st) // no old key set

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want abort error")
	}

	report := decodeRotateReport(t, stdout.Bytes())
	if report.Failed != 1 {
		t.Fatalf("report.Failed = %d, want 1", report.Failed)
	}
	if !strings.Contains(report.Items[0].Error, "CONFIGCTL_OLD_SECRET_KEY") {
		t.Fatalf("item error = %q, want it to name CONFIGCTL_OLD_SECRET_KEY", report.Items[0].Error)
	}
}

// midRunFixtures builds three secrets, one with a deliberately corrupted
// ciphertext, so tests can prove the "process dies after item 40 of 100"
// story: a single bad item among healthy ones.
func midRunFixtures(t *testing.T) []*store.Item {
	t.Helper()
	good1 := encryptFor(t, testOldKey, "key_a", "value-a", 1)
	bad := encryptFor(t, testOldKey, "key_b", "value-b", 1)
	bad.Value = string([]byte(bad.Value)[:len(bad.Value)-4]) // truncate: corrupts the ciphertext
	good2 := encryptFor(t, testOldKey, "key_c", "value-c", 1)
	return []*store.Item{good1, bad, good2}
}

// TestRunSecretRotate_MidRunFailure proves that a single corrupted item among
// healthy ones is survivable. By default nothing is written (all-or-nothing
// verify gate); with --continue-on-error the healthy items are rotated and
// the bad one is reported, not silently dropped or silently written.
func TestRunSecretRotate_MidRunFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		continueOnError bool
		wantSetCalls    int
		wantFailed      int
		wantWouldRotate int
		wantRotated     int
	}{
		{name: "default_aborts_all", wantSetCalls: 0, wantFailed: 1, wantWouldRotate: 2, wantRotated: 0},
		{name: "continue_on_error_rotates_the_rest", continueOnError: true, wantSetCalls: 2, wantFailed: 1, wantRotated: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var setCalls []*store.Item
			st := fakeStore{
				listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
					return midRunFixtures(t), nil
				},
				setFn: func(_ context.Context, item *store.Item) error {
					setCalls = append(setCalls, item)
					return nil
				},
			}
			d := rotateDeps(testNewKey, testOldKey, st)

			var stdout bytes.Buffer
			err := runSecretRotate(context.Background(), d, secretRotateOpts{
				project: testRotateProject, env: testRotateEnv, continueOnError: tc.continueOnError, output: formatJSON,
			}, &stdout, stubUpdatedBy)
			if err == nil {
				t.Fatal("error = nil, want error")
			}
			assertNeverWrote(t, setCalls, "key_b")
			if len(setCalls) != tc.wantSetCalls {
				t.Fatalf("store.Set called %d times, want %d", len(setCalls), tc.wantSetCalls)
			}

			report := decodeRotateReport(t, stdout.Bytes())
			if report.Failed != tc.wantFailed || report.WouldRotate != tc.wantWouldRotate || report.Rotated != tc.wantRotated {
				t.Fatalf("report = %+v, want failed=%d would_rotate=%d rotated=%d",
					report, tc.wantFailed, tc.wantWouldRotate, tc.wantRotated)
			}
		})
	}
}

func decodeRotateReport(t *testing.T, raw []byte) rotateReport {
	t.Helper()
	var report rotateReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return report
}

func assertNeverWrote(t *testing.T, setCalls []*store.Item, key string) {
	t.Helper()
	for _, item := range setCalls {
		if item.Key == key {
			t.Fatalf("the corrupted item %q must never be written", key)
		}
	}
}

// TestRunSecretRotate_Idempotent proves that re-running rotate once every
// secret is already on the new key performs zero writes — the store's
// stored key_id is the resumability signal, not a separate state file.
func TestRunSecretRotate_Idempotent(t *testing.T) {
	t.Parallel()

	already1 := encryptFor(t, testNewKey, "key_a", "value-a", 5)
	already2 := encryptFor(t, testNewKey, "key_b", "value-b", 2)

	// No setFn: this test fails loudly if rotate calls store.Set at all.
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{already1, already2}, nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	report := decodeRotateReport(t, stdout.Bytes())
	if report.AlreadyRotated != 2 || report.Rotated != 0 || report.Failed != 0 {
		t.Fatalf("report = %+v, want already_rotated=2 rotated=0 failed=0", report)
	}
}

// TestRunSecretRotate_Resumable simulates a process death partway through:
// one item already carries the new key_id (as if a prior run wrote it and
// then the process died before finishing), the rest are still on the old
// key. Re-running must rotate only the remaining items.
func TestRunSecretRotate_Resumable(t *testing.T) {
	t.Parallel()

	alreadyDone := encryptFor(t, testNewKey, "key_a", "value-a", 4) // as if item 1 of 2 already succeeded
	stillPending := encryptFor(t, testOldKey, "key_b", "value-b", 1)

	var setCalls []*store.Item
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{alreadyDone, stillPending}, nil
		},
		setFn: func(_ context.Context, item *store.Item) error {
			setCalls = append(setCalls, item)
			return nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	if len(setCalls) != 1 {
		t.Fatalf("store.Set called %d times, want 1 (only the still-pending item)", len(setCalls))
	}
	if setCalls[0].Key != "key_b" {
		t.Fatalf("rotated key = %s, want key_b", setCalls[0].Key)
	}
	decryptWith(t, testNewKey, setCalls[0], "value-b")

	report := decodeRotateReport(t, stdout.Bytes())
	if report.AlreadyRotated != 1 || report.Rotated != 1 {
		t.Fatalf("report = %+v, want already_rotated=1 rotated=1", report)
	}
}

func TestRunSecretRotate_DryRunWritesNothing(t *testing.T) {
	t.Parallel()

	item1 := encryptFor(t, testOldKey, "key_a", "value-a", 1)
	item2 := encryptFor(t, testOldKey, "key_b", "value-b", 1)

	// No setFn: dry-run must never call store.Set.
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item1, item2}, nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, dryRun: true, output: formatJSON,
	}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}

	report := decodeRotateReport(t, stdout.Bytes())
	if !report.DryRun {
		t.Fatal("report.DryRun = false, want true")
	}
	if report.WouldRotate != 2 || report.Rotated != 0 {
		t.Fatalf("report = %+v, want would_rotate=2 rotated=0", report)
	}

	// The items in the store must be provably untouched: decrypting them
	// still requires the OLD key, not the new one.
	decryptWith(t, testOldKey, item1, "value-a")
	decryptWith(t, testOldKey, item2, "value-b")
}

func TestRunSecretRotate_DryRunAbortsOnFailureToo(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testOldKey, "key_a", "value-a", 1)

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
	}
	d := rotateDeps(testNewKey, "wrong-old-key", st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, dryRun: true,
	}, &stdout, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want abort error even in dry-run")
	}
}

func TestRunSecretRotate_WriteFailurePreservesOtherItems(t *testing.T) {
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

	report := decodeRotateReport(t, stdout.Bytes())
	if report.Rotated != 1 || report.Failed != 1 {
		t.Fatalf("report = %+v, want rotated=1 failed=1 (key_b succeeds despite key_a's write failure)", report)
	}
}

func TestRunSecretRotate_TextOutput(t *testing.T) {
	t.Parallel()

	item := encryptFor(t, testOldKey, "key_a", "value-a", 1)
	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{item}, nil
		},
		setFn: func(context.Context, *store.Item) error { return nil },
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	var stdout bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &stdout, stubUpdatedBy)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "rotated=1") {
		t.Fatalf("text output = %q, want it to contain rotated=1", out)
	}
	if !strings.Contains(out, "[rotated] key_a") {
		t.Fatalf("text output = %q, want a per-item [rotated] key_a line", out)
	}
}

// fakeEncryptor lets decryptTolerant be unit-tested against exact sentinel
// errors without needing internal/crypto's package-private legacy-AAD test
// helper, which is not visible outside that package's own test binary.
type fakeEncryptor struct {
	decryptFn func(ciphertext []byte, keyID string) ([]byte, error)
}

func (fakeEncryptor) Encrypt([]byte) ([]byte, string, error) { return nil, "", nil }
func (f fakeEncryptor) Decrypt(ciphertext []byte, keyID string) ([]byte, error) {
	return f.decryptFn(ciphertext, keyID)
}
func (fakeEncryptor) KeyID() string { return "kid" }

func TestDecryptTolerant_LegacyAADTreatedAsSuccess(t *testing.T) {
	t.Parallel()

	enc := fakeEncryptor{decryptFn: func([]byte, string) ([]byte, error) {
		return []byte("legacy-value"), crypto.ErrLegacyAAD
	}}
	got, err := decryptTolerant(enc, &store.Item{Value: "ct", KeyID: "kid"})
	if err != nil {
		t.Fatalf("decryptTolerant error = %v, want nil (legacy AAD is not a failure)", err)
	}
	if string(got) != "legacy-value" {
		t.Fatalf("decryptTolerant = %q, want %q", got, "legacy-value")
	}
}

func TestDecryptTolerant_OtherErrorsPropagate(t *testing.T) {
	t.Parallel()

	enc := fakeEncryptor{decryptFn: func([]byte, string) ([]byte, error) {
		return nil, crypto.ErrDecryptionFailed
	}}
	_, err := decryptTolerant(enc, &store.Item{Value: "ct", KeyID: "kid"})
	if !errors.Is(err, crypto.ErrDecryptionFailed) {
		t.Fatalf("decryptTolerant error = %v, want ErrDecryptionFailed", err)
	}
}

// TestRunSecretRotate_ReportWriteError targets the --output json path
// specifically: json.Encode surfaces write errors (unlike the text renderer,
// which — matching 'diff's writeDiffText convention elsewhere in this
// package — treats stdout writes as best-effort UI output).
func TestRunSecretRotate_ReportWriteError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{}, nil
		},
	}
	d := rotateDeps(testNewKey, testOldKey, st)

	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, errWriter{}, stubUpdatedBy)
	if err == nil {
		t.Fatal("error = nil, want write error")
	}
}

func TestProbeKeyID_EmptyPassphrase(t *testing.T) {
	t.Parallel()

	if _, err := probeKeyID("", testRotateProject, testRotateEnv); err == nil {
		t.Fatal("error = nil, want ErrKeyUnavailable")
	}
}

func TestProbeKeyID_IndependentOfKeyName(t *testing.T) {
	t.Parallel()

	id1, err := probeKeyID("pass", testRotateProject, testRotateEnv)
	if err != nil {
		t.Fatalf("probeKeyID: %v", err)
	}
	enc, err := crypto.NewAESGCMEncryptor("pass", testRotateProject, testRotateEnv, "any_key_name")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	if id1 != enc.KeyID() {
		t.Fatalf("probeKeyID() = %s, want it to match a fully-bound encryptor's KeyID %s", id1, enc.KeyID())
	}
}
