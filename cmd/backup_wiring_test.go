package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/backup"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestNewBackupCmd_HasSubcommands(t *testing.T) {
	t.Parallel()

	cmd := newBackupCmd(&deps{}, &globalFlags{})
	if cmd.Use != "backup" {
		t.Fatalf("Use = %q, want backup", cmd.Use)
	}
	want := map[string]bool{"export": false, "import": false}
	for _, c := range cmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func sealedBackupFileForCmd(t *testing.T, items ...backup.BackupItem) *backup.BackupFile {
	t.Helper()
	bf := backup.NewBackupFile("proj", "dev", "1.0.0", "tester")
	bf.Items = items
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return bf
}

func writeBackupFile(t *testing.T, bf *backup.BackupFile) string {
	t.Helper()
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestBackupImportCmd_MissingInput(t *testing.T) {
	t.Parallel()

	d := &deps{log: noopLogger{}, store: fakeStore{}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing --input")
	}
}

func TestBackupImportCmd_FileNotFound(t *testing.T) {
	t.Parallel()

	d := &deps{log: noopLogger{}, store: fakeStore{}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", "does-not-exist.json")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing file")
	}
}

func TestBackupImportCmd_DryRun(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, sealedBackupFileForCmd(t, backup.BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1}))

	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, store.ErrNotFound
		},
		setFn: func(context.Context, *store.Item) error {
			t.Fatal("store.Set called during --dry-run; nothing should be written")
			return nil
		},
	}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", path)
	_ = cmd.Flags().Set("dry-run", "true")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestBackupImportCmd_SuccessWrite(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, sealedBackupFileForCmd(t, backup.BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1}))

	var setCalled bool
	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, store.ErrNotFound
		},
		setFn: func(context.Context, *store.Item) error {
			setCalled = true
			return nil
		},
	}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", path)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !setCalled {
		t.Fatal("store.Set was not called")
	}
}

func TestBackupImportCmd_OverwriteFlagWired(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, sealedBackupFileForCmd(t, backup.BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 9}))

	var gotVersion int64
	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return &store.Item{Version: 42}, nil
		},
		setFn: func(ctx context.Context, item *store.Item) error {
			gotVersion = item.Version
			return nil
		},
	}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", path)
	_ = cmd.Flags().Set("overwrite", "true")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if gotVersion != 42 {
		t.Fatalf("--overwrite did not reach the importer: version = %d, want 42", gotVersion)
	}
}

func TestBackupImportCmd_FailedItemsReturnError(t *testing.T) {
	t.Parallel()

	path := writeBackupFile(t, sealedBackupFileForCmd(t, backup.BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1}))

	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, errors.New("ddb unavailable")
		},
	}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", path)

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error when items fail to import")
	}
}

func TestBackupImportCmd_ImportError(t *testing.T) {
	t.Parallel()

	// A backup file with the wrong checksum fails verification inside Import.
	bf := sealedBackupFileForCmd(t, backup.BackupItem{Key: "k", Value: "v", ItemType: "config", Version: 1})
	bf.Checksum = "sha256:deadbeef"
	path := writeBackupFile(t, bf)

	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{}}
	cmd := newBackupImportCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("input", path)

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for checksum mismatch")
	}
}

// TestNewBackupExportCmdFlagWiring pins the command surface without invoking
// Execute(): the RunE closure writes to the real os.Stdout (not
// cmd.OutOrStdout()), and runBackupExport itself is already exercised
// end-to-end by backup_export_test.go, so there is no need to run the
// closure here — see secret_rotate_wiring_test.go for the identical rationale.
func TestNewBackupExportCmdFlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newBackupExportCmd(&deps{}, &globalFlags{})
	if cmd.Use != "export" {
		t.Fatalf("Use = %q, want export", cmd.Use)
	}
	for _, name := range []string{"project", "env", "output", "include-secrets"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if got := cmd.Flags().Lookup("output").DefValue; got != "-" {
		t.Errorf("--output default = %q, want -", got)
	}
	if got := cmd.Flags().Lookup("include-secrets").DefValue; got != "false" {
		t.Errorf("--include-secrets default = %q, want false", got)
	}
}
