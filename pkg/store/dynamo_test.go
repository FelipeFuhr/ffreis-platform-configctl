package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

const testTable = "platform-config-test"

// fakeDynamoClient is an in-memory DynamoClient implementing only what
// DynamoStore needs. Tests can preload items via items, capture the last
// inputs for assertion, and force errors via putErr / getErr / etc.
//
// PutItem ACTUALLY enforces the ConditionExpression it is given
// (attribute_not_exists(PK) for new items, "#v = :expected" for updates),
// rejecting a write whose condition doesn't hold with a
// ConditionalCheckFailedException-shaped error — exactly like real
// DynamoDB. This is what makes a genuine concurrent-write test meaningful:
// a fake that unconditionally accepted every PutItem would let two racing
// writers both "succeed" regardless of whether DynamoStore.Set's
// optimistic-concurrency logic works at all, silently certifying a broken
// implementation. All access is guarded by mu so PutItem is safe to call
// from multiple goroutines at once.
type fakeDynamoClient struct {
	mu    sync.Mutex
	items map[string]map[string]types.AttributeValue // PK#SK -> item

	lastPut    *dynamodb.PutItemInput
	lastGet    *dynamodb.GetItemInput
	lastDelete *dynamodb.DeleteItemInput
	lastQuery  *dynamodb.QueryInput
	lastScan   *dynamodb.ScanInput

	putErr    error
	getErr    error
	deleteErr error
	queryErr  error
	scanErr   error
}

func newFake() *fakeDynamoClient {
	return &fakeDynamoClient{items: map[string]map[string]types.AttributeValue{}}
}

func itemKey(pk, sk string) string { return pk + "\x00" + sk }

func avString(item map[string]types.AttributeValue, key string) string {
	if v, ok := item[key]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			return s.Value
		}
	}
	return ""
}

func avNumber(item map[string]types.AttributeValue, key string) (string, bool) {
	if v, ok := item[key]; ok {
		if n, ok := v.(*types.AttributeValueMemberN); ok {
			return n.Value, true
		}
	}
	return "", false
}

func (f *fakeDynamoClient) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastGet = in
	if f.getErr != nil {
		return nil, f.getErr
	}
	pk := avString(in.Key, "PK")
	sk := avString(in.Key, "SK")
	item, ok := f.items[itemKey(pk, sk)]
	if !ok {
		return &dynamodb.GetItemOutput{}, nil
	}
	return &dynamodb.GetItemOutput{Item: item}, nil
}

// errConditionalCheckFailed mimics the error shape DynamoStore's
// isConditionFailed looks for (a string-contains check on
// "ConditionalCheckFailedException" — see dynamo.go).
var errConditionalCheckFailed = errors.New("ConditionalCheckFailedException: the conditional request failed")

// evaluateCondition enforces the two ConditionExpression shapes DynamoStore
// ever sends (see dynamo.go's Set): "attribute_not_exists(PK)" for a new
// item, or "#v = :expected" for an update. Any other/missing expression is
// treated as unconditional, matching real DynamoDB's PutItem behaviour.
func (f *fakeDynamoClient) evaluateCondition(in *dynamodb.PutItemInput, pk, sk string) error {
	if in.ConditionExpression == nil {
		return nil
	}
	existing, exists := f.items[itemKey(pk, sk)]
	switch *in.ConditionExpression {
	case "attribute_not_exists(PK)":
		if exists {
			return errConditionalCheckFailed
		}
	case "#v = :expected":
		expectedAV, ok := in.ExpressionAttributeValues[":expected"]
		if !ok {
			return fmt.Errorf("test fake: missing :expected in ExpressionAttributeValues")
		}
		expectedN, ok := expectedAV.(*types.AttributeValueMemberN)
		if !ok {
			return fmt.Errorf("test fake: :expected is not a number attribute")
		}
		if !exists {
			return errConditionalCheckFailed
		}
		currentVersion, ok := avNumber(existing, "version")
		if !ok || currentVersion != expectedN.Value {
			return errConditionalCheckFailed
		}
	}
	return nil
}

func (f *fakeDynamoClient) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastPut = in
	if f.putErr != nil {
		return nil, f.putErr
	}
	pk := avString(in.Item, "PK")
	sk := avString(in.Item, "SK")
	if err := f.evaluateCondition(in, pk, sk); err != nil {
		return nil, err
	}
	f.items[itemKey(pk, sk)] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamoClient) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastDelete = in
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	pk := avString(in.Key, "PK")
	sk := avString(in.Key, "SK")
	delete(f.items, itemKey(pk, sk))
	return &dynamodb.DeleteItemOutput{}, nil
}

func (f *fakeDynamoClient) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastQuery = in
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	wantPK := ""
	wantPrefix := ""
	if v, ok := in.ExpressionAttributeValues[":pk"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			wantPK = s.Value
		}
	}
	if v, ok := in.ExpressionAttributeValues[":prefix"]; ok {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			wantPrefix = s.Value
		}
	}
	var matched []map[string]types.AttributeValue
	for _, item := range f.items {
		if avString(item, "PK") == wantPK && strings.HasPrefix(avString(item, "SK"), wantPrefix) {
			matched = append(matched, item)
		}
	}
	return &dynamodb.QueryOutput{Items: matched, Count: int32(len(matched))}, nil
}

func (f *fakeDynamoClient) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastScan = in
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	out := make([]map[string]types.AttributeValue, 0, len(f.items))
	for _, item := range f.items {
		out = append(out, item)
	}
	return &dynamodb.ScanOutput{Items: out, Count: int32(len(out))}, nil
}

// preload writes an item into the fake by marshalling the same dynamoRecord
// shape DynamoStore would write. Mirrors recordFromItem in dynamo.go.
func (f *fakeDynamoClient) preload(t *testing.T, item *store.Item) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	h := sha256.Sum256([]byte(item.Value))
	rec := map[string]any{
		"PK":         item.PK(),
		"SK":         item.SK(),
		"value":      item.Value,
		"item_type":  string(item.Type),
		"encrypted":  item.Encrypted,
		"key_id":     item.KeyID,
		"version":    item.Version,
		"checksum":   fmt.Sprintf("sha256:%x", h),
		"created_at": now,
		"updated_at": now,
		"updated_by": item.UpdatedBy,
		"project":    item.Project,
		"env":        item.Env,
		"key":        item.Key,
	}
	av, err := attributevalue.MarshalMap(rec)
	if err != nil {
		t.Fatalf("preload marshal: %v", err)
	}
	f.items[itemKey(item.PK(), item.SK())] = av
}

// --- contract tests --------------------------------------------------------

// TestPKSKFormat_AADContract pins the on-disk key format. Per AGENTS.md the
// encryption AAD is `PROJECT#{project}#ENV#{env}#KEY#{key}`. Changing the PK
// or SK format here invalidates every previously-stored secret. This test is
// deliberately strict: literal string equality, no helpers.
func TestPKSKFormat_AADContract(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	cases := []struct {
		item   *store.Item
		wantPK string
		wantSK string
	}{
		{
			item:   &store.Item{Project: "payments", Env: "prod", Key: "database_url", Type: store.ItemTypeConfig, Version: 0},
			wantPK: "PROJECT#payments#ENV#prod",
			wantSK: "CONFIG#database_url",
		},
		{
			item:   &store.Item{Project: "payments", Env: "prod", Key: "api_key", Type: store.ItemTypeSecret, Version: 0, Encrypted: true},
			wantPK: "PROJECT#payments#ENV#prod",
			wantSK: "SECRET#api_key",
		},
	}

	for _, tc := range cases {
		if err := s.Set(context.Background(), tc.item); err != nil {
			t.Fatalf("Set %v: %v", tc.item.Key, err)
		}
		gotPK := avString(fake.lastPut.Item, "PK")
		gotSK := avString(fake.lastPut.Item, "SK")
		if gotPK != tc.wantPK {
			t.Errorf("PK = %q, want %q", gotPK, tc.wantPK)
		}
		if gotSK != tc.wantSK {
			t.Errorf("SK = %q, want %q", gotSK, tc.wantSK)
		}
	}
}

func TestSetGet_RoundTrip(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	original := &store.Item{
		Project:   "payments",
		Env:       "prod",
		Key:       "database_url",
		Value:     "postgres://example",
		Type:      store.ItemTypeConfig,
		Encrypted: false,
		KeyID:     "",
		Version:   0,
		UpdatedBy: "alice",
	}

	if err := s.Set(context.Background(), original); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(context.Background(), "payments", "prod", store.ItemTypeConfig, "database_url")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Project != original.Project || got.Env != original.Env || got.Key != original.Key {
		t.Errorf("identity mismatch: got %+v want %+v", got, original)
	}
	if got.Value != original.Value {
		t.Errorf("Value = %q, want %q", got.Value, original.Value)
	}
	if got.Type != original.Type {
		t.Errorf("Type = %q, want %q", got.Type, original.Type)
	}
	if got.UpdatedBy != "alice" {
		t.Errorf("UpdatedBy = %q, want alice", got.UpdatedBy)
	}
	// Set bumps Version from 0 to 1 on write (see recordFromItem).
	if got.Version != 1 {
		t.Errorf("Version after Set+Get = %d, want 1", got.Version)
	}
	// Checksum is sha256:hex of the value.
	wantSum := sha256.Sum256([]byte(original.Value))
	wantChecksum := fmt.Sprintf("sha256:%x", wantSum)
	if got.Checksum != wantChecksum {
		t.Errorf("Checksum = %q, want %q", got.Checksum, wantChecksum)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero, want RFC3339 timestamp")
	}
}

// TestSet_NewItemUsesAttributeNotExists locks in the optimistic-concurrency
// contract for new items: Version=0 must write with attribute_not_exists(PK)
// so two concurrent creates can't both succeed.
func TestSet_NewItemUsesAttributeNotExists(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	err := s.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "k",
		Value: "v", Type: store.ItemTypeConfig, Version: 0,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if fake.lastPut.ConditionExpression == nil {
		t.Fatal("ConditionExpression not set on new-item Put")
	}
	if got := *fake.lastPut.ConditionExpression; got != "attribute_not_exists(PK)" {
		t.Errorf("ConditionExpression = %q, want attribute_not_exists(PK)", got)
	}
	if fake.lastPut.ExpressionAttributeValues != nil {
		t.Errorf("ExpressionAttributeValues should be nil for new items, got %v", fake.lastPut.ExpressionAttributeValues)
	}
}

// TestSet_ExistingItemUsesVersionMatch locks in the optimistic-concurrency
// contract for updates: Version>0 must write with `#v = :expected` and pass
// the current expected version.
func TestSet_ExistingItemUsesVersionMatch(t *testing.T) {
	fake := newFake()
	// The fake's PutItem enforces "#v = :expected" for real (see
	// evaluateCondition above), just like DynamoDB does — so, unlike before
	// that enforcement existed, an update against a key with no existing
	// item at the expected version would now correctly be rejected. Preload
	// the item at version 3 first so this test's actual write is the
	// legitimate update it claims to be.
	fake.preload(t, &store.Item{Project: "p", Env: "e", Key: "k", Value: "v0", Type: store.ItemTypeConfig, Version: 3})
	s := store.NewDynamoStore(fake, testTable)

	err := s.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "k",
		Value: "v", Type: store.ItemTypeConfig, Version: 3,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if fake.lastPut.ConditionExpression == nil {
		t.Fatal("ConditionExpression not set on update Put")
	}
	if got := *fake.lastPut.ConditionExpression; got != "#v = :expected" {
		t.Errorf("ConditionExpression = %q, want #v = :expected", got)
	}
	if got := fake.lastPut.ExpressionAttributeNames["#v"]; got != "version" {
		t.Errorf("ExpressionAttributeNames[#v] = %q, want version", got)
	}
	expVal := fake.lastPut.ExpressionAttributeValues[":expected"]
	num, ok := expVal.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf(":expected attribute = %T, want *types.AttributeValueMemberN", expVal)
	}
	if num.Value != "3" {
		t.Errorf(":expected = %q, want 3", num.Value)
	}
}

// TestSet_VersionConflictReturnsTypedError verifies a conditional-check
// failure from DynamoDB is mapped to *ErrVersionConflict, not surfaced as a
// raw wrapped error. Without this mapping the CLI couldn't show its
// "run diff to inspect" hint.
func TestSet_VersionConflictReturnsTypedError(t *testing.T) {
	fake := newFake()
	// The current implementation does a string-contains check on the error
	// message; any error whose Error() includes the SDK type name triggers it.
	fake.putErr = errors.New("ConditionalCheckFailedException: the conditional request failed")
	s := store.NewDynamoStore(fake, testTable)

	err := s.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "api_key",
		Value: "v", Type: store.ItemTypeSecret, Version: 2,
	})
	var conflict *store.ErrVersionConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("Set: err = %v, want *ErrVersionConflict", err)
	}
	if conflict.Key != "api_key" {
		t.Errorf("ErrVersionConflict.Key = %q, want api_key", conflict.Key)
	}
	if conflict.ExpectedVersion != 2 {
		t.Errorf("ErrVersionConflict.ExpectedVersion = %d, want 2", conflict.ExpectedVersion)
	}
}

func TestSet_NonConflictErrorIsWrapped(t *testing.T) {
	fake := newFake()
	fake.putErr = errors.New("ResourceNotFoundException: table missing")
	s := store.NewDynamoStore(fake, testTable)

	err := s.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "k",
		Value: "v", Type: store.ItemTypeConfig, Version: 0,
	})
	if err == nil {
		t.Fatal("Set: expected error")
	}
	var conflict *store.ErrVersionConflict
	if errors.As(err, &conflict) {
		t.Errorf("non-conditional error misclassified as ErrVersionConflict: %v", err)
	}
	if !strings.Contains(err.Error(), "ResourceNotFoundException") {
		t.Errorf("wrapped err = %v, expected to contain ResourceNotFoundException", err)
	}
}

func TestGet_NotFoundReturnsErrNotFound(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	_, err := s.Get(context.Background(), "p", "e", store.ItemTypeConfig, "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get missing: err = %v, want ErrNotFound", err)
	}
}

func TestGet_PassesPKAndSK(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	// Result is irrelevant; we just want to capture the input.
	_, _ = s.Get(context.Background(), "payments", "prod", store.ItemTypeSecret, "api_key")
	if got := avString(fake.lastGet.Key, "PK"); got != "PROJECT#payments#ENV#prod" {
		t.Errorf("Get PK = %q, want PROJECT#payments#ENV#prod", got)
	}
	if got := avString(fake.lastGet.Key, "SK"); got != "SECRET#api_key" {
		t.Errorf("Get SK = %q, want SECRET#api_key", got)
	}
	if fake.lastGet.TableName == nil || *fake.lastGet.TableName != testTable {
		t.Errorf("Get TableName = %v, want %q", fake.lastGet.TableName, testTable)
	}
}

// TestDelete_IsIdempotent confirms Delete reports success even when the item
// is absent. This matches the Store interface contract (see store.go:20).
func TestDelete_IsIdempotent(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	if err := s.Delete(context.Background(), "p", "e", store.ItemTypeConfig, "absent"); err != nil {
		t.Errorf("Delete on absent key returned %v, want nil", err)
	}
}

func TestDelete_RemovesExistingItem(t *testing.T) {
	fake := newFake()
	item := &store.Item{Project: "p", Env: "e", Key: "k", Value: "v", Type: store.ItemTypeConfig, Version: 1}
	fake.preload(t, item)
	s := store.NewDynamoStore(fake, testTable)

	if err := s.Delete(context.Background(), "p", "e", store.ItemTypeConfig, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrNotFound", err)
	}
}

func TestList_FiltersByPKAndSKPrefix(t *testing.T) {
	fake := newFake()
	// Same project+env, mix of configs and secrets, plus a different env.
	fake.preload(t, &store.Item{Project: "p", Env: "prod", Key: "host", Value: "x", Type: store.ItemTypeConfig, Version: 1})
	fake.preload(t, &store.Item{Project: "p", Env: "prod", Key: "port", Value: "5432", Type: store.ItemTypeConfig, Version: 1})
	fake.preload(t, &store.Item{Project: "p", Env: "prod", Key: "api_key", Value: "secret", Type: store.ItemTypeSecret, Version: 1})
	fake.preload(t, &store.Item{Project: "p", Env: "dev", Key: "host", Value: "x", Type: store.ItemTypeConfig, Version: 1})
	s := store.NewDynamoStore(fake, testTable)

	items, err := s.List(context.Background(), "p", "prod", store.ItemTypeConfig)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("List config in p/prod returned %d items, want 2", len(items))
	}
	for _, it := range items {
		if it.Type != store.ItemTypeConfig {
			t.Errorf("item %q has type %q, want config", it.Key, it.Type)
		}
		if it.Env != "prod" {
			t.Errorf("item %q has env %q, want prod (PK filter failed)", it.Key, it.Env)
		}
	}

	// Sanity-check the actual query expression sent to DDB.
	if got := *fake.lastQuery.KeyConditionExpression; got != "PK = :pk AND begins_with(SK, :prefix)" {
		t.Errorf("KeyConditionExpression = %q, want PK = :pk AND begins_with(SK, :prefix)", got)
	}
}

func TestListProjects_Deduplicates(t *testing.T) {
	fake := newFake()
	// Multiple entries for the same project must produce a single result.
	fake.preload(t, &store.Item{Project: "alpha", Env: "prod", Key: "k1", Value: "v", Type: store.ItemTypeConfig, Version: 1})
	fake.preload(t, &store.Item{Project: "alpha", Env: "dev", Key: "k1", Value: "v", Type: store.ItemTypeConfig, Version: 1})
	fake.preload(t, &store.Item{Project: "alpha", Env: "prod", Key: "k2", Value: "v", Type: store.ItemTypeSecret, Version: 1})
	fake.preload(t, &store.Item{Project: "bravo", Env: "prod", Key: "k1", Value: "v", Type: store.ItemTypeConfig, Version: 1})
	s := store.NewDynamoStore(fake, testTable)

	projects, err := s.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 2 {
		t.Errorf("ListProjects returned %d, want 2 (alpha, bravo). got=%v", len(projects), projects)
	}
	seen := map[string]bool{}
	for _, p := range projects {
		if seen[p] {
			t.Errorf("ListProjects returned duplicate: %q", p)
		}
		seen[p] = true
	}
	if !seen["alpha"] || !seen["bravo"] {
		t.Errorf("ListProjects = %v, want alpha and bravo", projects)
	}
	if fake.lastScan.ProjectionExpression == nil || *fake.lastScan.ProjectionExpression != "project" {
		t.Errorf("Scan ProjectionExpression = %v, want \"project\"", fake.lastScan.ProjectionExpression)
	}
}

// TestListProjects_EmptyTable exercises ListProjects against a table with no
// items at all. Unlike Get, List/ListProjects have no ErrNotFound in their
// contract (store.go documents ErrNotFound only for Get) — an empty
// collection is a normal, successful result: an empty, non-nil-error slice.
// This specific case (zero items, zero projects) was previously untested;
// every existing ListProjects test preloaded at least one project.
func TestListProjects_EmptyTable(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	projects, err := s.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects on empty table: err = %v, want nil", err)
	}
	if len(projects) != 0 {
		t.Fatalf("ListProjects on empty table = %v, want empty slice", projects)
	}
}

// TestList_EmptyResult is List's equivalent of TestListProjects_EmptyTable:
// an empty result set is success, not an error.
func TestList_EmptyResult(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, testTable)

	items, err := s.List(context.Background(), "p", "e", store.ItemTypeConfig)
	if err != nil {
		t.Fatalf("List on empty table: err = %v, want nil", err)
	}
	if len(items) != 0 {
		t.Fatalf("List on empty table = %v, want empty slice", items)
	}
}

// TestSet_BumpsVersionOnWrite documents that the stored version is always one
// higher than the in-memory item.Version, regardless of starting value. This
// is what makes the version-match optimistic-concurrency scheme work.
func TestSet_BumpsVersionOnWrite(t *testing.T) {
	for _, startVersion := range []int64{0, 1, 5, 99} {
		fake := newFake()
		// version=0 means "new item" (attribute_not_exists(PK), nothing to
		// preload). Any non-zero version is an update, and the fake's
		// PutItem now really enforces "#v = :expected" against existing
		// state — preload an item already sitting at exactly that version
		// so the update is legitimate, matching what DynamoStore.Set
		// actually promises its caller (pass the version you currently
		// hold, get it bumped by one).
		if startVersion != 0 {
			fake.preload(t, &store.Item{Project: "p", Env: "e", Key: "k", Value: "v0", Type: store.ItemTypeConfig, Version: startVersion})
		}
		s := store.NewDynamoStore(fake, testTable)
		err := s.Set(context.Background(), &store.Item{
			Project: "p", Env: "e", Key: "k",
			Value: "v", Type: store.ItemTypeConfig, Version: startVersion,
		})
		if err != nil {
			t.Fatalf("Set(version=%d): %v", startVersion, err)
		}
		stored := fake.lastPut.Item["version"]
		num, ok := stored.(*types.AttributeValueMemberN)
		if !ok {
			t.Fatalf("stored version attr is %T", stored)
		}
		want := fmt.Sprintf("%d", startVersion+1)
		if num.Value != want {
			t.Errorf("stored version after Set(in=%d) = %q, want %q", startVersion, num.Value, want)
		}
	}
}

// TestGet_PropagatesAWSError ensures non-NotFound errors from DynamoDB are
// wrapped (not swallowed). Without this any transient AWS error would be
// indistinguishable from a missing item.
func TestGet_PropagatesAWSError(t *testing.T) {
	fake := newFake()
	fake.getErr = errors.New("ThrottlingException: rate exceeded")
	s := store.NewDynamoStore(fake, testTable)

	_, err := s.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Error("transient AWS error misclassified as ErrNotFound")
	}
	if !strings.Contains(err.Error(), "ThrottlingException") {
		t.Errorf("err = %v, expected to contain ThrottlingException", err)
	}
}

// TestSet_TableNameIsForwarded protects against a regression where the
// configured table name silently isn't used (e.g. someone hardcodes a name
// during refactor).
func TestSet_TableNameIsForwarded(t *testing.T) {
	fake := newFake()
	s := store.NewDynamoStore(fake, "custom-table-xyz")
	_ = s.Set(context.Background(), &store.Item{
		Project: "p", Env: "e", Key: "k",
		Value: "v", Type: store.ItemTypeConfig, Version: 0,
	})
	if fake.lastPut.TableName == nil || *fake.lastPut.TableName != "custom-table-xyz" {
		t.Errorf("TableName = %v, want custom-table-xyz", aws.ToString(fake.lastPut.TableName))
	}
}

// TestErrVersionConflict_Error pins the exact message ErrVersionConflict
// produces — the CLI's "run `diff` to inspect" hint lives in this string,
// so a wording regression would previously have gone undetected (nothing
// called .Error() on this type; every other test only inspected the
// struct fields).
func TestErrVersionConflict_Error(t *testing.T) {
	err := &store.ErrVersionConflict{Key: "api_key", ExpectedVersion: 5}
	want := "version conflict on key api_key: run `diff` to inspect current state before retrying"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// TestSet_ConcurrentWrites_OnlyOneSucceeds is the genuine concurrent-write
// test the version-conflict happy-path tests above cannot substitute for.
// TestSet_VersionConflictReturnsTypedError only proves the CODE correctly
// interprets an error message string handed to it by a mock — it never
// actually races two writers against shared state, so it would pass
// identically even if DynamoStore.Set built no ConditionExpression at all
// (as long as *something* eventually produced that error text). This test
// instead seeds one real item at version=1, then launches N goroutines that
// all read that same starting point and race to Set with Version=1
// (expecting to bump to 2). Because the fake DynamoClient above now
// actually enforces "#v = :expected" against its current state under a
// mutex — mirroring DynamoDB's real atomic conditional-write guarantee —
// exactly one writer must observe success and every other writer must
// observe *ErrVersionConflict, regardless of goroutine scheduling.
func TestSet_ConcurrentWrites_OnlyOneSucceeds(t *testing.T) {
	fake := newFake()
	fake.preload(t, &store.Item{Project: "p", Env: "e", Key: "k", Value: "v0", Type: store.ItemTypeConfig, Version: 1})
	s := store.NewDynamoStore(fake, testTable)

	const writers = 8
	var wg sync.WaitGroup
	var succeeded, conflicted int32
	var mu sync.Mutex
	var otherErrs []error

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := s.Set(context.Background(), &store.Item{
				Project: "p", Env: "e", Key: "k",
				Value: "v-from-writer-" + strconv.Itoa(n), Type: store.ItemTypeConfig, Version: 1,
			})
			mu.Lock()
			defer mu.Unlock()
			var conflict *store.ErrVersionConflict
			switch {
			case err == nil:
				succeeded++
			case errors.As(err, &conflict):
				conflicted++
			default:
				otherErrs = append(otherErrs, err)
			}
		}(i)
	}
	wg.Wait()

	if len(otherErrs) != 0 {
		t.Fatalf("unexpected non-conflict errors from concurrent Set: %v", otherErrs)
	}
	if succeeded != 1 {
		t.Fatalf("succeeded = %d, want exactly 1 (all %d writers raced from the same starting version)", succeeded, writers)
	}
	if conflicted != writers-1 {
		t.Fatalf("conflicted = %d, want %d", conflicted, writers-1)
	}

	// The stored version must have advanced by exactly one bump (1 -> 2),
	// never more — proof that only one of the racing writes actually landed.
	got, err := s.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get after race: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("final stored Version = %d, want 2 (exactly one successful bump from 1)", got.Version)
	}
}
