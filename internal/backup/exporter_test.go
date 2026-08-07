package backup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ffreis/platform-configctl/internal/store"
)

type exporterFakeStore struct {
	listFn func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error)
}

func (f exporterFakeStore) Get(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
	panic("unexpected store.Get call")
}
func (f exporterFakeStore) Set(context.Context, *store.Item) error {
	panic("unexpected store.Set call")
}
func (f exporterFakeStore) List(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
	return f.listFn(ctx, project, env, itemType)
}
func (f exporterFakeStore) Delete(context.Context, string, string, store.ItemType, string) error {
	panic("unexpected store.Delete call")
}
func (f exporterFakeStore) ListProjects(context.Context) ([]string, error) {
	panic("unexpected store.ListProjects call")
}

func TestNewExporter(t *testing.T) {
	t.Parallel()

	e := NewExporter(exporterFakeStore{})
	if e == nil {
		t.Fatal("NewExporter() = nil")
	}
}

func TestExporter_Export_ConfigsOnly(t *testing.T) {
	t.Parallel()

	st := exporterFakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			if itemType != store.ItemTypeConfig {
				t.Fatalf("unexpected list for secrets when IncludeSecrets=false")
			}
			return []*store.Item{
				{Key: "a", Value: "v1", Type: store.ItemTypeConfig, Version: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()},
			}, nil
		},
	}

	e := NewExporter(st)
	bf, err := e.Export(context.Background(), "proj", "dev", ExportOptions{ToolVersion: "1.0.0", ExportedBy: "tester"})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if bf.Metadata.IncludesSecret {
		t.Fatal("IncludesSecret = true, want false")
	}
	if len(bf.Items) != 1 || bf.Items[0].Key != "a" {
		t.Fatalf("Items = %#v, want one item with key a", bf.Items)
	}
	if bf.Checksum == "" {
		t.Fatal("Export() did not seal the backup file (empty checksum)")
	}
	if err := bf.Verify(); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestExporter_Export_IncludesSecrets(t *testing.T) {
	t.Parallel()

	st := exporterFakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			switch itemType {
			case store.ItemTypeConfig:
				return []*store.Item{{Key: "a", Value: "v1", Type: store.ItemTypeConfig, Version: 1}}, nil
			case store.ItemTypeSecret:
				return []*store.Item{{Key: "s", Value: "ciphertext", Type: store.ItemTypeSecret, Encrypted: true, KeyID: "kid", Version: 2}}, nil
			default:
				return nil, nil
			}
		},
	}

	e := NewExporter(st)
	bf, err := e.Export(context.Background(), "proj", "dev", ExportOptions{IncludeSecrets: true})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if !bf.Metadata.IncludesSecret {
		t.Fatal("IncludesSecret = false, want true")
	}
	if len(bf.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(bf.Items))
	}
}

func TestExporter_Export_ConfigListError(t *testing.T) {
	t.Parallel()

	st := exporterFakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return nil, errors.New("boom")
		},
	}

	e := NewExporter(st)
	if _, err := e.Export(context.Background(), "proj", "dev", ExportOptions{}); err == nil {
		t.Fatal("Export() error = nil, want error")
	}
}

func TestExporter_Export_SecretListError(t *testing.T) {
	t.Parallel()

	st := exporterFakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			if itemType == store.ItemTypeConfig {
				return []*store.Item{}, nil
			}
			return nil, errors.New("boom")
		},
	}

	e := NewExporter(st)
	if _, err := e.Export(context.Background(), "proj", "dev", ExportOptions{IncludeSecrets: true}); err == nil {
		t.Fatal("Export() error = nil, want error")
	}
}

func TestBackupItemFromStoreItem_ZeroTimestamps(t *testing.T) {
	t.Parallel()

	item := &store.Item{Key: "a", Value: "v", Type: store.ItemTypeConfig}
	bi := backupItemFromStoreItem(item)
	if bi.CreatedAt != "" || bi.UpdatedAt != "" {
		t.Fatalf("zero timestamps should serialise to empty strings, got created=%q updated=%q", bi.CreatedAt, bi.UpdatedAt)
	}
}

func TestBackupItemFromStoreItem_NonZeroTimestamps(t *testing.T) {
	t.Parallel()

	now := time.Now()
	item := &store.Item{Key: "a", Value: "v", Type: store.ItemTypeConfig, CreatedAt: now, UpdatedAt: now}
	bi := backupItemFromStoreItem(item)
	if bi.CreatedAt == "" || bi.UpdatedAt == "" {
		t.Fatal("non-zero timestamps should not serialise to empty strings")
	}
}
