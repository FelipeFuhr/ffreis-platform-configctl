//go:build integration

// Integration coverage for `secret rotate` against a REAL DynamoDB.
//
// The unit tests in secret_rotate_test.go already use real crypto, but they
// drive a fakeStore that cannot reproduce DynamoDB's conditional writes. That
// matters: rotate's safety story depends on the optimistic lock in
// DynamoStore.Set ("#v = :expected") rejecting a stale write, and a hand-rolled
// fake proves nothing about whether the real conditional expression behaves as
// assumed. These tests exercise the genuine article.
//
// Run with: make test-integration  (starts DynamoDB Local via podman)
// Or point DYNAMODB_ENDPOINT at an already-running instance.
// Skipped entirely when no endpoint is reachable, so `go test ./...` stays green
// on a machine without a container runtime.
package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

const defaultDDBEndpoint = "http://localhost:8000"

func ddbEndpoint() string {
	if v := os.Getenv("DYNAMODB_ENDPOINT"); v != "" {
		return v
	}
	return defaultDDBEndpoint
}

// newIntegrationClient returns a DynamoDB client pointed at DynamoDB Local, or
// skips the test when nothing is listening there.
func newIntegrationClient(t *testing.T) *dynamodb.Client {
	t.Helper()

	endpoint := ddbEndpoint()
	host := endpoint
	for _, prefix := range []string{"http://", "https://"} {
		if len(host) > len(prefix) && host[:len(prefix)] == prefix {
			host = host[len(prefix):]
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		t.Skipf("DynamoDB Local not reachable at %s (%v) — run `make test-integration`", endpoint, err)
	}
	_ = conn.Close()

	return dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: awssdk.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
}

// newIntegrationTable creates a throwaway table with the real PK/SK schema and
// removes it when the test ends, so tests never collide or leak state.
func newIntegrationTable(t *testing.T, client *dynamodb.Client) string {
	t.Helper()

	name := fmt.Sprintf("configctl-rotate-it-%s-%d", t.Name(), time.Now().UnixNano())
	// Table names allow [a-zA-Z0-9_.-] only; t.Name() may contain '/'.
	safe := make([]rune, 0, len(name))
	for _, r := range name {
		if r == '/' || r == ' ' {
			r = '-'
		}
		safe = append(safe, r)
	}
	name = string(safe)

	ctx := context.Background()
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: awssdk.String(name),
		AttributeDefinitions: []ddbtypes.AttributeDefinition{
			{AttributeName: awssdk.String("PK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: awssdk.String("SK"), AttributeType: ddbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []ddbtypes.KeySchemaElement{
			{AttributeName: awssdk.String("PK"), KeyType: ddbtypes.KeyTypeHash},
			{AttributeName: awssdk.String("SK"), KeyType: ddbtypes.KeyTypeRange},
		},
		BillingMode: ddbtypes.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatalf("CreateTable(%s): %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
			TableName: awssdk.String(name),
		})
	})
	return name
}

// seedSecret writes a secret encrypted under passphrase through the REAL store,
// exactly as `secret set` would.
func seedSecret(t *testing.T, st store.Store, passphrase, key, plaintext string) {
	t.Helper()

	enc, err := crypto.NewAESGCMEncryptor(passphrase, testRotateProject, testRotateEnv, key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	item := &store.Item{
		Project:   testRotateProject,
		Env:       testRotateEnv,
		Key:       key,
		Value:     string(ciphertext),
		Type:      store.ItemTypeSecret,
		Encrypted: true,
		KeyID:     keyID,
		Version:   0, // 0 => create (attribute_not_exists(PK))
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedBy: "seed",
	}
	if err := st.Set(context.Background(), item); err != nil {
		t.Fatalf("seeding %s: %v", key, err)
	}
}

func mustGet(t *testing.T, st store.Store, key string) *store.Item {
	t.Helper()
	item, err := st.Get(context.Background(), testRotateProject, testRotateEnv, store.ItemTypeSecret, key)
	if err != nil {
		t.Fatalf("Get(%s): %v", key, err)
	}
	return item
}

// assertDecrypts asserts the stored ciphertext decrypts to want under passphrase.
func assertDecrypts(t *testing.T, passphrase string, item *store.Item, want string) {
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
		t.Errorf("%s decrypted to %q, want %q", item.Key, got, want)
	}
}

// assertDoesNotDecrypt asserts the OLD passphrase can no longer read the item —
// the property that makes a rotation meaningful rather than cosmetic.
func assertDoesNotDecrypt(t *testing.T, passphrase string, item *store.Item) {
	t.Helper()
	enc, err := crypto.NewAESGCMEncryptor(passphrase, testRotateProject, testRotateEnv, item.Key)
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	if _, err := enc.Decrypt([]byte(item.Value), item.KeyID); err == nil {
		t.Errorf("%s still decrypts under the OLD passphrase after rotation", item.Key)
	}
}

func integrationDeps(t *testing.T, secretKey, oldKey string) (*deps, store.Store) {
	t.Helper()
	client := newIntegrationClient(t)
	table := newIntegrationTable(t, client)
	st := store.NewDynamoStore(client, table)
	return &deps{
		cfg:   &appconfig.Config{SecretKey: secretKey, OldSecretKey: oldKey, TableName: table},
		log:   noopLogger{},
		store: st,
	}, st
}

// TestIntegrationRotateReEncryptsAgainstRealDynamo is the end-to-end proof: seed
// under the old key, rotate, and confirm every secret now reads under the NEW
// key and no longer reads under the old one — with the real store, real
// conditional writes, and real crypto.
func TestIntegrationRotateReEncryptsAgainstRealDynamo(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "stripe_key", "sk_live_abc123")
	seedSecret(t, st, testOldKey, "db_password", "hunter2")

	want := map[string]string{
		"stripe_key":  "sk_live_abc123",
		"db_password": "hunter2",
	}
	before := map[string]int64{}
	for key := range want {
		before[key] = mustGet(t, st, key).Version
	}

	var buf bytes.Buffer
	if err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &buf, stubUpdatedBy); err != nil {
		t.Fatalf("runSecretRotate: %v\noutput: %s", err, buf.String())
	}

	for key, plaintext := range want {
		item := mustGet(t, st, key)

		// The plaintext survives the round trip, reads under the NEW key, and no
		// longer reads under the old one — the property that makes a rotation
		// meaningful rather than cosmetic.
		assertDecrypts(t, testNewKey, item, plaintext)
		assertDoesNotDecrypt(t, testOldKey, item)

		// DynamoStore.Set persists item.Version+1, so exactly one write happened.
		if got, wantVer := item.Version, before[key]+1; got != wantVer {
			t.Errorf("%s version = %d, want %d (exactly one write)", key, got, wantVer)
		}
	}
}

// TestIntegrationRotateIsResumable verifies a second run is a no-op: every item
// reports already_rotated and nothing is rewritten. This is what makes an
// interrupted rotation safe to simply re-run.
func TestIntegrationRotateIsResumable(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "stripe_key", "sk_live_abc123")

	var first bytes.Buffer
	if err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &first, stubUpdatedBy); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	afterFirst := mustGet(t, st, "stripe_key")

	var second bytes.Buffer
	if err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &second, stubUpdatedBy); err != nil {
		t.Fatalf("second rotate: %v\noutput: %s", err, second.String())
	}

	if !bytes.Contains(second.Bytes(), []byte(`"already_rotated":1`)) {
		t.Errorf("second run should report already_rotated=1, got: %s", second.String())
	}
	if !bytes.Contains(second.Bytes(), []byte(`"rotated":0`)) {
		t.Errorf("second run should rewrite nothing, got: %s", second.String())
	}

	afterSecond := mustGet(t, st, "stripe_key")
	if afterSecond.Version != afterFirst.Version {
		t.Errorf("version changed on a no-op run: %d -> %d", afterFirst.Version, afterSecond.Version)
	}
	if afterSecond.Value != afterFirst.Value {
		t.Error("ciphertext was rewritten on a no-op run")
	}
	assertDecrypts(t, testNewKey, afterSecond, "sk_live_abc123")
}

// TestIntegrationRotateRejectsStaleWrite is the one a fake store cannot prove.
// Rotate reads and verifies in Phase 1, then writes in Phase 2 using the version
// it observed. If someone changes the secret in between, the real conditional
// expression must reject the stale write — otherwise rotate would silently
// clobber the newer value with the plaintext it captured earlier.
func TestIntegrationRotateRejectsStaleWrite(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "stripe_key", "sk_live_original")

	// Simulate a concurrent `secret set` landing after rotate read the item:
	// bump the stored version so the version rotate captured is now stale.
	current := mustGet(t, st, "stripe_key")
	concurrent := *current
	concurrent.UpdatedBy = "someone-else"
	if err := st.Set(context.Background(), &concurrent); err != nil {
		t.Fatalf("simulating concurrent write: %v", err)
	}

	// Hand rotate the STALE version by writing through commitRotationPlan with
	// the pre-bump item, which is exactly the state Phase 1 would have captured.
	stale := &rotatePlanItem{
		item:          current, // version captured before the concurrent bump
		status:        rotateStatusWouldRotate,
		newCiphertext: []byte("irrelevant-would-be-ciphertext"),
		newKeyID:      "sha256:deadbeef",
	}
	commitRotationPlan(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, []*rotatePlanItem{stale}, stubUpdatedBy)

	if stale.status != rotateStatusFailed {
		t.Errorf("stale write status = %q, want %q — the optimistic lock did not reject it",
			stale.status, rotateStatusFailed)
	}
	if stale.err == nil {
		t.Error("stale write recorded no error")
	}

	// And the store must still hold the concurrent writer's value, unclobbered.
	after := mustGet(t, st, "stripe_key")
	if after.UpdatedBy != "someone-else" {
		t.Errorf("UpdatedBy = %q, want someone-else — the stale write clobbered a newer value", after.UpdatedBy)
	}
	assertDecrypts(t, testOldKey, after, "sk_live_original")
}

// TestIntegrationRotateAbortsWithoutWritingWhenOneSecretFails verifies the
// two-phase guarantee against the real store: if any secret fails verification,
// NOTHING is written — not even the secrets that verified fine.
func TestIntegrationRotateAbortsWithoutWritingWhenOneSecretFails(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "good_secret", "readable")
	// A secret encrypted under a THIRD passphrase: neither old nor new key opens it.
	seedSecret(t, st, "a-completely-different-passphrase", "bad_secret", "unreadable")

	before := mustGet(t, st, "good_secret")

	var buf bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &buf, stubUpdatedBy)
	if err == nil {
		t.Fatal("want an error when a secret fails verification, got nil")
	}

	after := mustGet(t, st, "good_secret")
	if after.Version != before.Version || after.Value != before.Value {
		t.Error("a verifiable secret was written even though another failed verification — " +
			"the two-phase abort guarantee is broken")
	}
	assertDecrypts(t, testOldKey, after, "readable")
}

// TestIntegrationRotateContinueOnErrorRotatesTheRest verifies --continue-on-error
// against the real store: the readable secret is rotated, the unreadable one is
// left exactly as it was, and the command still reports failure.
func TestIntegrationRotateContinueOnErrorRotatesTheRest(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "good_secret", "readable")
	seedSecret(t, st, "a-completely-different-passphrase", "bad_secret", "unreadable")

	badBefore := mustGet(t, st, "bad_secret")

	var buf bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, continueOnError: true,
	}, &buf, stubUpdatedBy)
	if err == nil {
		t.Fatal("want a non-nil error reporting the failed secret, got nil")
	}

	good := mustGet(t, st, "good_secret")
	assertDecrypts(t, testNewKey, good, "readable")
	assertDoesNotDecrypt(t, testOldKey, good)

	badAfter := mustGet(t, st, "bad_secret")
	if badAfter.Value != badBefore.Value || badAfter.Version != badBefore.Version {
		t.Error("the unreadable secret was modified; a secret that cannot be decrypted must be left untouched")
	}
}

// TestIntegrationDryRunWritesNothing verifies --dry-run against the real store.
func TestIntegrationDryRunWritesNothing(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, testOldKey)

	seedSecret(t, st, testOldKey, "stripe_key", "sk_live_abc123")
	before := mustGet(t, st, "stripe_key")

	var buf bytes.Buffer
	if err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, dryRun: true, output: formatJSON,
	}, &buf, stubUpdatedBy); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"would_rotate":1`)) {
		t.Errorf("dry run should report would_rotate=1, got: %s", buf.String())
	}

	after := mustGet(t, st, "stripe_key")
	if after.Version != before.Version || after.Value != before.Value {
		t.Error("--dry-run wrote to the store")
	}
	assertDecrypts(t, testOldKey, after, "sk_live_abc123")
}

// TestIntegrationRotateMissingOldKeyLeavesEverythingAlone verifies that running
// without CONFIGCTL_OLD_SECRET_KEY cannot damage anything: every item fails
// verification and the store is untouched.
func TestIntegrationRotateMissingOldKeyLeavesEverythingAlone(t *testing.T) {
	d, st := integrationDeps(t, testNewKey, "")

	seedSecret(t, st, testOldKey, "stripe_key", "sk_live_abc123")
	before := mustGet(t, st, "stripe_key")

	var buf bytes.Buffer
	err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv,
	}, &buf, stubUpdatedBy)
	if err == nil {
		t.Fatal("want an error when the old key is absent, got nil")
	}
	if !bytes.Contains(buf.Bytes(), []byte("CONFIGCTL_OLD_SECRET_KEY")) {
		t.Errorf("the failure should name the missing variable, got: %s", buf.String())
	}

	after := mustGet(t, st, "stripe_key")
	if after.Version != before.Version || after.Value != before.Value {
		t.Error("store was modified despite no usable old key")
	}
	assertDecrypts(t, testOldKey, after, "sk_live_abc123")
}

// TestIntegrationRotateEmptyProjectEnvIsANoOp verifies a project+env with no
// secrets succeeds without touching anything.
func TestIntegrationRotateEmptyProjectEnvIsANoOp(t *testing.T) {
	d, _ := integrationDeps(t, testNewKey, testOldKey)

	var buf bytes.Buffer
	if err := runSecretRotate(context.Background(), d, secretRotateOpts{
		project: testRotateProject, env: testRotateEnv, output: formatJSON,
	}, &buf, stubUpdatedBy); err != nil {
		t.Fatalf("rotate on an empty project+env: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"total":0`)) {
		t.Errorf("want total=0, got: %s", buf.String())
	}
}

// TestIntegrationStoreOptimisticLockRejectsStaleVersion pins the store-level
// behaviour rotate depends on, independent of rotate itself. If this ever stops
// holding, rotate's safety argument collapses — so assert it directly.
func TestIntegrationStoreOptimisticLockRejectsStaleVersion(t *testing.T) {
	client := newIntegrationClient(t)
	table := newIntegrationTable(t, client)
	st := store.NewDynamoStore(client, table)

	seedSecret(t, st, testOldKey, "k", "v1")
	v1 := mustGet(t, st, "k")

	// First update from v1 succeeds and bumps the stored version.
	update := *v1
	update.UpdatedBy = "writer-a"
	if err := st.Set(context.Background(), &update); err != nil {
		t.Fatalf("first update: %v", err)
	}

	// A second write carrying the SAME (now stale) version must be rejected.
	stale := *v1
	stale.UpdatedBy = "writer-b"
	err := st.Set(context.Background(), &stale)
	if err == nil {
		t.Fatal("stale-version write succeeded; the optimistic lock is not enforced")
	}

	var ccf *ddbtypes.ConditionalCheckFailedException
	if !errors.As(err, &ccf) {
		t.Logf("note: error was %v (not ConditionalCheckFailedException) — still rejected, which is what matters", err)
	}

	after := mustGet(t, st, "k")
	if after.UpdatedBy != "writer-a" {
		t.Errorf("UpdatedBy = %q, want writer-a — the stale write was applied", after.UpdatedBy)
	}
}
