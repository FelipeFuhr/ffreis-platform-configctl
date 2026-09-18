package backup_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/backup"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/crypto"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// memStoreForRoundTrip is a minimal store.Store good enough to drive a real
// Exporter -> Importer cycle. It is intentionally separate from the
// exporterFakeStore/errStore/memStore fakes in the other _test.go files
// (which live in `package backup` and panic on the methods they don't use)
// since this one needs a working List, Get AND Set, from `package
// backup_test`.
type memStoreForRoundTrip struct {
	items map[string]*store.Item
}

func newMemStoreForRoundTrip() *memStoreForRoundTrip {
	return &memStoreForRoundTrip{items: map[string]*store.Item{}}
}

func (m *memStoreForRoundTrip) key(project, env string, t store.ItemType, k string) string {
	return project + "|" + env + "|" + string(t) + "|" + k
}

func (m *memStoreForRoundTrip) Get(_ context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error) {
	if it, ok := m.items[m.key(project, env, itemType, key)]; ok {
		copyItem := *it
		return &copyItem, nil
	}
	return nil, store.ErrNotFound
}

func (m *memStoreForRoundTrip) Set(_ context.Context, item *store.Item) error {
	itemCopy := *item
	m.items[m.key(item.Project, item.Env, item.Type, item.Key)] = &itemCopy
	return nil
}

func (m *memStoreForRoundTrip) List(_ context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
	var out []*store.Item
	for _, it := range m.items {
		if it.Project == project && it.Env == env && it.Type == itemType {
			itemCopy := *it
			out = append(out, &itemCopy)
		}
	}
	return out, nil
}

func (m *memStoreForRoundTrip) Delete(_ context.Context, project, env string, itemType store.ItemType, key string) error {
	delete(m.items, m.key(project, env, itemType, key))
	return nil
}

func (m *memStoreForRoundTrip) ListProjects(context.Context) ([]string, error) {
	return nil, nil
}

// TestExportThenImport_CiphertextIsByteIdenticalAcrossStores is the actual
// "round-trip: export then import reproduces the original data exactly,
// byte-for-byte on ciphertext" test. TestBackupRoundtrip (roundtrip_test.go)
// only round-trips a BackupFile through Seal/JSON/Verify directly — it never
// calls Exporter or Importer, and never touches a real ciphertext blob (its
// secret item's Value is the literal string "<ciphertext>"). This test
// drives the full path: encrypt a real secret with pkg/crypto, put it in a
// source store, Export it, Import the resulting BackupFile into a SEPARATE
// destination store, and assert the destination's stored Value is
// byte-for-byte identical to the original AES-GCM ciphertext — not merely
// "no error was returned".
func TestExportThenImport_CiphertextIsByteIdenticalAcrossStores(t *testing.T) {
	t.Parallel()

	const project, env, key = "payments", "prod", "api_key"

	enc, err := crypto.NewAESGCMEncryptor("passphrase", project, env, key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte("s3cr3t-api-token"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	source := newMemStoreForRoundTrip()
	if err := source.Set(context.Background(), &store.Item{
		Project: project, Env: env, Key: key,
		Value: string(ciphertext), Type: store.ItemTypeSecret,
		Encrypted: true, KeyID: keyID, Version: 0,
	}); err != nil {
		t.Fatalf("seed source store: %v", err)
	}

	exporter := backup.NewExporter(source)
	bf, err := exporter.Export(context.Background(), project, env, backup.ExportOptions{IncludeSecrets: true})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// The exported ciphertext must already be byte-identical to what was
	// stored, before import even happens.
	if len(bf.Items) != 1 {
		t.Fatalf("Export produced %d items, want 1", len(bf.Items))
	}
	if bf.Items[0].Value != string(ciphertext) {
		t.Fatalf("exported ciphertext differs from the source store's stored value")
	}

	destination := newMemStoreForRoundTrip()
	importer := backup.NewImporter(destination)
	result, err := importer.Import(context.Background(), bf, backup.ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if result.Written != 1 || result.Failed != 0 {
		t.Fatalf("Import result = %+v, want Written=1 Failed=0", result)
	}

	got, err := destination.Get(context.Background(), project, env, store.ItemTypeSecret, key)
	if err != nil {
		t.Fatalf("Get from destination: %v", err)
	}
	if got.Value != string(ciphertext) {
		t.Fatalf("round-tripped ciphertext differs from the original:\n got  = %q\n want = %q", got.Value, string(ciphertext))
	}

	// And the round-tripped ciphertext must still decrypt to the original
	// plaintext — proof this isn't just two equal-looking strings, but a
	// still-valid AES-GCM blob for the exact same AAD.
	plaintext, err := enc.Decrypt([]byte(got.Value), got.KeyID)
	if err != nil {
		t.Fatalf("decrypting round-tripped ciphertext: %v", err)
	}
	if string(plaintext) != "s3cr3t-api-token" {
		t.Fatalf("decrypted round-tripped plaintext = %q, want %q", plaintext, "s3cr3t-api-token")
	}
}

// TestImportFromFile_CorruptedFileRejectedByChecksum is the "actually
// corrupting a byte" checksum test the mandate asks for.
// TestVerifyChecksumMismatch (roundtrip_test.go) only mutates an in-memory
// BackupFile field and calls Verify() directly — it never writes a file to
// disk or goes through ImportFromFile's read-and-parse path at all. This
// test writes a real, validly-sealed backup to a temp file, flips one
// character inside an item's value in the RAW FILE BYTES (staying valid
// JSON — an arbitrary byte flip almost always breaks JSON syntax outright,
// which would fail at json.Unmarshal for an unrelated reason and never
// reach the checksum check this test targets), and asserts
// ImportFromFile rejects it with ErrChecksumMismatch, propagated through
// the real file-reading code path.
func TestImportFromFile_CorruptedFileRejectedByChecksum(t *testing.T) {
	t.Parallel()

	bf := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "original-value", ItemType: "config", Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Corrupt exactly one byte of the actual value text on disk, in place,
	// while keeping the file syntactically valid JSON: replace one
	// character of "original-value" with a different one.
	corrupted := []byte(string(raw))
	idx := indexOf(corrupted, "original-value")
	if idx < 0 {
		t.Fatal("test setup: could not locate the value text to corrupt")
	}
	corrupted[idx] = 'X' // "original-value" -> "Xriginal-value"

	// Confirm the corruption really did keep the file parseable JSON (so the
	// test below fails on the checksum, not on json.Unmarshal for an
	// unrelated syntax reason).
	var sanity backup.BackupFile
	if err := json.Unmarshal(corrupted, &sanity); err != nil {
		t.Fatalf("test setup produced invalid JSON: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "corrupted.json")
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	imp := backup.NewImporter(newMemStoreForRoundTrip())
	_, err = imp.ImportFromFile(context.Background(), path, backup.ImportOptions{})
	if err == nil {
		t.Fatal("ImportFromFile on a byte-corrupted file: error = nil, want ErrChecksumMismatch")
	}
	if !errorIsChecksumMismatch(err) {
		t.Fatalf("ImportFromFile on a byte-corrupted file: err = %v, want ErrChecksumMismatch", err)
	}
}

func indexOf(haystack []byte, needle string) int {
	s := string(haystack)
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func errorIsChecksumMismatch(err error) bool {
	for err != nil {
		if err == backup.ErrChecksumMismatch {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// dryRunProbeStore wraps memStoreForRoundTrip and counts Set calls, so a
// dry-run test can assert on ACTUAL STORE BEHAVIOUR rather than trusting the
// ImportResult counters the dry-run code path itself produces.
type dryRunProbeStore struct {
	*memStoreForRoundTrip
	setCalls int
}

func (d *dryRunProbeStore) Set(ctx context.Context, item *store.Item) error {
	d.setCalls++
	return d.memStoreForRoundTrip.Set(ctx, item)
}

// TestImporterImport_DryRun_StoreStateUnchanged is the "checking the store
// state before/after, not trusting the flag's own logic" dry-run test.
// TestImporterImport_DryRunCountsWrites (importer_test.go) only asserts
// res.Written == 1 — but Written is incremented by the SAME early-return
// branch that is supposed to skip the real write (see Importer.importOne:
// `if opts.DryRun { result.Written++; return }`), so that assertion cannot
// distinguish "dry-run correctly skipped the write" from "dry-run
// accidentally also wrote, and also reported Written=1". This test drives
// dry-run against a store that (a) starts with an existing item and asserts
// its value is untouched afterward, and (b) independently counts Set calls
// and asserts it is exactly zero.
func TestImporterImport_DryRun_StoreStateUnchanged(t *testing.T) {
	t.Parallel()

	base := newMemStoreForRoundTrip()
	if err := base.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "k", Value: "untouched-original", Type: store.ItemTypeConfig, Version: 1,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	probe := &dryRunProbeStore{memStoreForRoundTrip: base}

	imp := backup.NewImporter(probe)
	bf := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "value-from-the-backup-file", ItemType: "config", Version: 99},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	result, err := imp.Import(context.Background(), bf, backup.ImportOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if result.Written != 1 {
		t.Fatalf("result.Written = %d, want 1 (dry-run still reports what WOULD be written)", result.Written)
	}

	if probe.setCalls != 0 {
		t.Fatalf("store.Set was called %d times during a --dry-run import, want 0", probe.setCalls)
	}

	got, err := probe.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get after dry-run: %v", err)
	}
	if got.Value != "untouched-original" {
		t.Fatalf("stored value after dry-run = %q, want %q (unchanged)", got.Value, "untouched-original")
	}
	if got.Version != 1 {
		t.Fatalf("stored version after dry-run = %d, want 1 (unchanged)", got.Version)
	}
}

// TestImporterImport_UpdatedByOverridesBackupValue and
// TestImporterImport_EmptyUpdatedByKeepsBackupValue together cover
// ImportOptions.UpdatedBy, which no existing test exercised at all: every
// pre-existing Import test left ImportOptions.UpdatedBy at its zero value,
// so the "opts.UpdatedBy overrides bi.UpdatedBy when non-empty" branch in
// storeItemFromBackupItem was written to but never observed either way.
func TestImporterImport_UpdatedByOverridesBackupValue(t *testing.T) {
	t.Parallel()

	st := newMemStoreForRoundTrip()
	imp := backup.NewImporter(st)
	bf := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "v", ItemType: "config", Version: 0, UpdatedBy: "original-cli-user"},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := imp.Import(context.Background(), bf, backup.ImportOptions{UpdatedBy: "importing-operator"}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	got, err := st.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UpdatedBy != "importing-operator" {
		t.Fatalf("UpdatedBy = %q, want %q (opts.UpdatedBy must override the backup's own value)", got.UpdatedBy, "importing-operator")
	}
}

func TestImporterImport_EmptyUpdatedByKeepsBackupValue(t *testing.T) {
	t.Parallel()

	st := newMemStoreForRoundTrip()
	imp := backup.NewImporter(st)
	bf := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "v", ItemType: "config", Version: 0, UpdatedBy: "original-cli-user"},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := imp.Import(context.Background(), bf, backup.ImportOptions{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	got, err := st.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UpdatedBy != "original-cli-user" {
		t.Fatalf("UpdatedBy = %q, want %q (an empty opts.UpdatedBy must leave the backup's value alone)", got.UpdatedBy, "original-cli-user")
	}
}

// TestSeal_ChecksumIsOrderIndependentWithinSameItemType exercises
// computeChecksum's tie-breaker sort (by Key, once ItemType is equal) via
// the public Seal API. Every pre-existing checksum test used items of
// DIFFERENT ItemType (config vs secret), so the sort comparator's ItemType
// branch always decided the order and the Key tie-breaker line was never
// reached by any test. Two items of the SAME ItemType with different Keys,
// inserted in reverse order in one of the two files, are needed to actually
// exercise it — and to prove Seal()'s checksum is order-independent, which
// is the entire point of sorting before hashing.
func TestSeal_ChecksumIsOrderIndependentWithinSameItemType(t *testing.T) {
	t.Parallel()

	forward := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	forward.Items = []backup.BackupItem{
		{Key: "a", Value: "va", ItemType: "config", Version: 1},
		{Key: "b", Value: "vb", ItemType: "config", Version: 1},
	}
	if err := forward.Seal(); err != nil {
		t.Fatalf("Seal (forward): %v", err)
	}

	reversed := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	reversed.Items = []backup.BackupItem{
		{Key: "b", Value: "vb", ItemType: "config", Version: 1},
		{Key: "a", Value: "va", ItemType: "config", Version: 1},
	}
	if err := reversed.Seal(); err != nil {
		t.Fatalf("Seal (reversed): %v", err)
	}

	if forward.Checksum != reversed.Checksum {
		t.Fatalf("Seal() checksum depends on input order for same-ItemType items: forward=%q reversed=%q", forward.Checksum, reversed.Checksum)
	}

	// And a genuinely different item set (different Key content, same
	// count) must still produce a DIFFERENT checksum — otherwise the sort
	// fix above could be paired with an accidentally-constant checksum and
	// this test would still pass.
	different := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	different.Items = []backup.BackupItem{
		{Key: "a", Value: "va", ItemType: "config", Version: 1},
		{Key: "c", Value: "vc", ItemType: "config", Version: 1},
	}
	if err := different.Seal(); err != nil {
		t.Fatalf("Seal (different): %v", err)
	}
	if different.Checksum == forward.Checksum {
		t.Fatal("a different item set produced the same checksum as forward's")
	}
}

// TestSeal_ChecksumMatchesKnownValueForFixedInput hardcodes the checksum for
// a fixed, known set of items, computed independently (see the commit that
// introduced this test for the standalone script used to derive it) rather
// than by calling Seal/Verify and checking they agree with each other.
//
// This closes a real blind spot the round-trip-style tests above cannot:
// computeChecksum's sort-by-(ItemType,Key) comparator runs identically
// whether Seal (writing bf.Checksum) or Verify (recomputing to compare) —
// so a mutation that reverses or otherwise breaks that comparator is
// applied CONSISTENTLY on both sides of every Seal-then-Verify round trip
// and produces a checksum that still matches itself. The same is true of
// TestSeal_ChecksumIsOrderIndependentWithinSameItemType above: sorting is a
// deterministic total order regardless of which comparator direction is
// used, so a negated comparator still makes insertion order irrelevant.
// Only a test that pins the checksum to a value computed OUTSIDE this
// package's own logic can tell "sorted correctly" apart from "sorted
// consistently but wrong". Gremlins mutation testing confirmed this: the
// comparator's CONDITIONALS_NEGATION/CONDITIONALS_BOUNDARY mutants at
// format.go:118 and format.go:120 survived every round-trip-style test in
// this file and were only killed by this one.
func TestSeal_ChecksumMatchesKnownValueForFixedInput(t *testing.T) {
	t.Parallel()

	bf := backup.NewBackupFile("p", "e", "1.0.0", "tester")
	// Deliberately unsorted and mixed-type, so both comparator branches
	// (ItemType-differs, and the Key tie-breaker within the same type) are
	// exercised by this one fixed dataset.
	bf.Items = []backup.BackupItem{
		{Key: "z_config", Value: "zval", ItemType: "config", Version: 1},
		{Key: "a_secret", Value: "aciphertext", ItemType: "secret", Version: 2, KeyID: "kid1", Encrypted: true},
		{Key: "a_config", Value: "aval", ItemType: "config", Version: 3},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	const wantChecksum = "sha256:26351a7b6223030f697466ce6f2333c0cc0b36e1a23d6f94956013016692d241"
	if bf.Checksum != wantChecksum {
		t.Fatalf("Seal() checksum for this fixed input = %q, want %q (if the BackupItem shape or the sort comparator legitimately changed, recompute this value and update it deliberately, not just to make the test pass)", bf.Checksum, wantChecksum)
	}
}
