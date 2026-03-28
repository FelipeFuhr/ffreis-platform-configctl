package backup

import (
	"context"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

type memStore struct {
	items map[string]*store.Item
}

func newMemStore() *memStore { return &memStore{items: map[string]*store.Item{}} }

func (m *memStore) key(project, env string, t store.ItemType, k string) string {
	return project + "|" + env + "|" + string(t) + "|" + k
}

func (m *memStore) Get(ctx context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error) {
	if it, ok := m.items[m.key(project, env, itemType, key)]; ok {
		copy := *it
		return &copy, nil
	}
	return nil, store.ErrNotFound
}

func (m *memStore) Set(ctx context.Context, item *store.Item) error {
	m.items[m.key(item.Project, item.Env, item.Type, item.Key)] = item
	return nil
}

func (m *memStore) List(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
	panic("not used")
}
func (m *memStore) Delete(context.Context, string, string, store.ItemType, string) error {
	panic("not used")
}
func (m *memStore) ListProjects(context.Context) ([]string, error) { panic("not used") }

func TestVerifyBackupFile_RejectsSchemaMismatch(t *testing.T) {
	bf := &BackupFile{Format: FormatIdentifier, SchemaVersion: "99"}
	if err := verifyBackupFile(bf); err == nil {
		t.Fatal("expected error")
	}
}

func TestImporterImport_DryRunCountsWrites(t *testing.T) {
	st := newMemStore()
	imp := NewImporter(st)

	bf := &BackupFile{
		Format:        FormatIdentifier,
		SchemaVersion: SchemaVersion,
		Metadata:      Metadata{Project: "p", Environment: "e"},
		Items:         []BackupItem{{Key: "k", Value: "v", ItemType: "config", Version: 1}},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	res, err := imp.Import(context.Background(), bf, ImportOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Written != 1 {
		t.Fatalf("expected Written=1, got %d", res.Written)
	}
}
