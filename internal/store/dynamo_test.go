package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ffreis/platform-configctl/internal/store"
)

const testTable = "platform-config-test"

// fakeDynamoClient is an in-memory DynamoClient implementing only what
// DynamoStore needs. Tests can preload items via items, capture the last
// inputs for assertion, and force errors via putErr / getErr / etc.
type fakeDynamoClient struct {
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

func (f *fakeDynamoClient) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
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

func (f *fakeDynamoClient) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.lastPut = in
	if f.putErr != nil {
		return nil, f.putErr
	}
	pk := avString(in.Item, "PK")
	sk := avString(in.Item, "SK")
	f.items[itemKey(pk, sk)] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamoClient) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
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

// TestSet_BumpsVersionOnWrite documents that the stored version is always one
// higher than the in-memory item.Version, regardless of starting value. This
// is what makes the version-match optimistic-concurrency scheme work.
func TestSet_BumpsVersionOnWrite(t *testing.T) {
	for _, startVersion := range []int64{0, 1, 5, 99} {
		fake := newFake()
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
