package diff_test

import (
	"testing"
	"time"

	"github.com/ffreis/platform-configctl/internal/diff"
	"github.com/ffreis/platform-configctl/internal/store"
)

const (
	testProject = "test"
	testEnvDev  = "dev"
)

func makeItem(key, value string, t store.ItemType) *store.Item {
	return &store.Item{
		Project:   testProject,
		Env:       testEnvDev,
		Key:       key,
		Value:     value,
		Type:      t,
		Encrypted: false,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestDiffAdded(t *testing.T) {
	live := []*store.Item{}
	snapshot := []*store.Item{
		makeItem("new_key", "value", store.ItemTypeConfig),
	}

	d := diff.New()
	result := d.Diff(live, snapshot)

	if len(result.Added) != 1 {
		t.Errorf("expected 1 added change, got %d", len(result.Added))
	}
	if result.Added[0].Key != "new_key" {
		t.Errorf("expected key=new_key, got %s", result.Added[0].Key)
	}
	if result.Added[0].Kind != diff.Added {
		t.Errorf("expected kind=added")
	}
}

func TestDiffModified(t *testing.T) {
	live := []*store.Item{makeItem("key", "old", store.ItemTypeConfig)}
	snapshot := []*store.Item{makeItem("key", "new", store.ItemTypeConfig)}

	d := diff.New()
	result := d.Diff(live, snapshot)

	if len(result.Modified) != 1 {
		t.Errorf("expected 1 modified, got %d", len(result.Modified))
	}
	if result.Modified[0].OldValue != "old" {
		t.Errorf("old value: got %q, want %q", result.Modified[0].OldValue, "old")
	}
	if result.Modified[0].NewValue != "new" {
		t.Errorf("new value: got %q, want %q", result.Modified[0].NewValue, "new")
	}
}

func TestDiffDeleted(t *testing.T) {
	live := []*store.Item{makeItem("gone_key", "v", store.ItemTypeConfig)}
	snapshot := []*store.Item{}

	d := diff.New()
	result := d.Diff(live, snapshot)

	if len(result.Deleted) != 1 {
		t.Errorf("expected 1 deleted, got %d", len(result.Deleted))
	}
	if result.Deleted[0].Key != "gone_key" {
		t.Errorf("expected key=gone_key")
	}
}

func TestDiffUnchanged(t *testing.T) {
	item := makeItem("same", "value", store.ItemTypeConfig)
	live := []*store.Item{item}
	snapshot := []*store.Item{makeItem("same", "value", store.ItemTypeConfig)}

	d := diff.New()
	result := d.Diff(live, snapshot)

	if len(result.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged, got %d", len(result.Unchanged))
	}
	if result.HasChanges() {
		t.Error("expected no changes")
	}
}

func TestDiffSecretValuesAreMasked(t *testing.T) {
	live := []*store.Item{
		{
			Project: testProject, Env: testEnvDev, Key: "api_key",
			Value: "plaintext-should-not-appear",
			Type:  store.ItemTypeSecret, Encrypted: true,
		},
	}
	snapshot := []*store.Item{
		{
			Project: testProject, Env: testEnvDev, Key: "api_key",
			Value: "different-ciphertext",
			Type:  store.ItemTypeSecret, Encrypted: true,
		},
	}

	d := diff.New()
	result := d.Diff(live, snapshot)

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(result.Modified))
	}
	if result.Modified[0].OldValue == "plaintext-should-not-appear" {
		t.Error("secret plaintext leaked in diff output")
	}
	if result.Modified[0].NewValue == "different-ciphertext" {
		t.Error("secret ciphertext leaked in diff output")
	}
}

func TestDiffNoChanges(t *testing.T) {
	d := diff.New()
	result := d.Diff([]*store.Item{}, []*store.Item{})
	if result.HasChanges() {
		t.Error("empty diff should not have changes")
	}
}
