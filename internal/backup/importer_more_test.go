package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

// errStore always returns a generic (non-NotFound) error from Get, to exercise
// resolveImportVersion's failure path distinctly from the "not found" path.
type errStore struct {
	getErr error
	setFn  func(ctx context.Context, item *store.Item) error
}

func (e errStore) Get(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
	return nil, e.getErr
}
func (e errStore) Set(ctx context.Context, item *store.Item) error {
	if e.setFn != nil {
		return e.setFn(ctx, item)
	}
	return nil
}
func (e errStore) List(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
	panic("not used")
}
func (e errStore) Delete(context.Context, string, string, store.ItemType, string) error {
	panic("not used")
}
func (e errStore) ListProjects(context.Context) ([]string, error) { panic("not used") }

func sealedBackupFile(t *testing.T, items ...BackupItem) *BackupFile {
	t.Helper()
	bf := &BackupFile{
		Format:        FormatIdentifier,
		SchemaVersion: SchemaVersion,
		Metadata:      Metadata{Project: "p", Environment: "e"},
		Items:         items,
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return bf
}

func TestNewImporter(t *testing.T) {
	t.Parallel()

	if imp := NewImporter(newMemStore()); imp == nil {
		t.Fatal("NewImporter() = nil")
	}
}

func TestImporterImportFromFile_Success(t *testing.T) {
	t.Parallel()

	bf := sealedBackupFile(t, BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1})
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	imp := NewImporter(newMemStore())
	result, err := imp.ImportFromFile(context.Background(), path, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportFromFile() error = %v", err)
	}
	if result.Written != 1 {
		t.Fatalf("Written = %d, want 1", result.Written)
	}
}

func TestImporterImportFromFile_MissingFile(t *testing.T) {
	t.Parallel()

	imp := NewImporter(newMemStore())
	if _, err := imp.ImportFromFile(context.Background(), "does-not-exist.json", ImportOptions{}); err == nil {
		t.Fatal("ImportFromFile() error = nil, want error")
	}
}

func TestImporterImportFromFile_InvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	imp := NewImporter(newMemStore())
	if _, err := imp.ImportFromFile(context.Background(), path, ImportOptions{}); err == nil {
		t.Fatal("ImportFromFile() error = nil, want error")
	}
}

func TestImporterImport_NewItemGetsVersionZero(t *testing.T) {
	t.Parallel()

	st := newMemStore()
	imp := NewImporter(st)
	bf := sealedBackupFile(t, BackupItem{Key: "new-key", Value: "v", ItemType: "config", Version: 5})

	result, err := imp.Import(context.Background(), bf, ImportOptions{})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if result.Written != 1 || result.Failed != 0 {
		t.Fatalf("result = %#v, want Written=1 Failed=0", result)
	}
	got, err := st.Get(context.Background(), "p", "e", store.ItemTypeConfig, "new-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Version != 0 {
		t.Fatalf("stored Version = %d, want 0 for a brand-new item", got.Version)
	}
}

func TestImporterImport_OverwriteUsesCurrentVersion(t *testing.T) {
	t.Parallel()

	st := newMemStore()
	// Seed an existing item at version 3.
	if err := st.Set(context.Background(), &store.Item{Project: "p", Env: "e", Key: "k", Type: store.ItemTypeConfig, Version: 3}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}

	imp := NewImporter(st)
	bf := sealedBackupFile(t, BackupItem{Key: "k", Value: "new-value", ItemType: "config", Version: 1})

	result, err := imp.Import(context.Background(), bf, ImportOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if result.Written != 1 {
		t.Fatalf("Written = %d, want 1", result.Written)
	}
	got, err := st.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Version != 3 {
		t.Fatalf("stored Version = %d, want 3 (current, not backup's 1)", got.Version)
	}
}

func TestImporterImport_NoOverwriteUsesBackupVersion(t *testing.T) {
	t.Parallel()

	st := newMemStore()
	if err := st.Set(context.Background(), &store.Item{Project: "p", Env: "e", Key: "k", Type: store.ItemTypeConfig, Version: 3}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}

	imp := NewImporter(st)
	bf := sealedBackupFile(t, BackupItem{Key: "k", Value: "new-value", ItemType: "config", Version: 7})

	if _, err := imp.Import(context.Background(), bf, ImportOptions{Overwrite: false}); err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	got, err := st.Get(context.Background(), "p", "e", store.ItemTypeConfig, "k")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Version != 7 {
		t.Fatalf("stored Version = %d, want 7 (backup's version)", got.Version)
	}
}

func TestImporterImport_GetErrorCountsFailed(t *testing.T) {
	t.Parallel()

	st := errStore{getErr: errors.New("ddb unavailable")}
	imp := NewImporter(st)
	bf := sealedBackupFile(t, BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1})

	result, err := imp.Import(context.Background(), bf, ImportOptions{})
	if err != nil {
		t.Fatalf("Import() error = %v, want nil (per-item failures don't abort)", err)
	}
	if result.Failed != 1 || result.Written != 0 {
		t.Fatalf("result = %#v, want Failed=1 Written=0", result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1", len(result.Errors))
	}
}

func TestImporterImport_SetErrorCountsFailed(t *testing.T) {
	t.Parallel()

	st := errStore{
		getErr: store.ErrNotFound,
		setFn: func(context.Context, *store.Item) error {
			return errors.New("write denied")
		},
	}
	imp := NewImporter(st)
	bf := sealedBackupFile(t, BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1})

	result, err := imp.Import(context.Background(), bf, ImportOptions{})
	if err != nil {
		t.Fatalf("Import() error = %v, want nil", err)
	}
	if result.Failed != 1 || result.Written != 0 {
		t.Fatalf("result = %#v, want Failed=1 Written=0", result)
	}
}

func TestErrUnknownSchemaVersion_Error(t *testing.T) {
	t.Parallel()

	err := &ErrUnknownSchemaVersion{Version: "99"}
	want := "unknown backup schema version: 99"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
