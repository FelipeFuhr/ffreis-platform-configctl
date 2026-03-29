package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffreis/platform-configctl/internal/backup"
	"github.com/ffreis/platform-configctl/internal/diff"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestLoadBackupFile_ChecksumMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")

	bf := backup.NewBackupFile("proj", "dev", "t", "u")
	bf.Items = []backup.BackupItem{
		{Key: "a", Value: "v1", ItemType: string(store.ItemTypeConfig), Encrypted: false, Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	bf.Checksum = "sha256:deadbeef"

	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err = loadBackupFile(path)
	if err != backup.ErrChecksumMismatch {
		t.Fatalf("loadBackupFile error = %v, want %v", err, backup.ErrChecksumMismatch)
	}
}

func TestRunDiff_NoChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")

	bf := backup.NewBackupFile("proj", "dev", "t", "u")
	bf.Items = []backup.BackupItem{
		{Key: "a", Value: "v1", ItemType: string(store.ItemTypeConfig), Encrypted: false, Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			switch itemType {
			case store.ItemTypeConfig:
				return []*store.Item{{Project: project, Env: env, Key: "a", Value: "v1", Type: store.ItemTypeConfig, Encrypted: false, Version: 1}}, nil
			case store.ItemTypeSecret:
				return []*store.Item{}, nil
			default:
				return []*store.Item{}, nil
			}
		},
	}
	d := &deps{log: noopLogger{}, store: st}
	gf := &globalFlags{output: "text"}

	var out bytes.Buffer
	if err := runDiff(context.Background(), d, gf, "proj", "dev", path, &out); err != nil {
		t.Fatalf("runDiff error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (no changes)", out.String())
	}
}

func TestRunDiff_WithChanges_JSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "backup.json")

	bf := backup.NewBackupFile("proj", "dev", "t", "u")
	bf.Items = []backup.BackupItem{
		{Key: "a", Value: "v1", ItemType: string(store.ItemTypeConfig), Encrypted: false, Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			switch itemType {
			case store.ItemTypeConfig:
				return []*store.Item{{Project: project, Env: env, Key: "a", Value: "v2", Type: store.ItemTypeConfig, Encrypted: false, Version: 1}}, nil
			case store.ItemTypeSecret:
				return []*store.Item{}, nil
			default:
				return []*store.Item{}, nil
			}
		},
	}
	d := &deps{log: noopLogger{}, store: st}
	gf := &globalFlags{output: formatJSON}

	var out bytes.Buffer
	if err := runDiff(context.Background(), d, gf, "proj", "dev", path, &out); err != nil {
		t.Fatalf("runDiff error = %v", err)
	}

	var got []diff.Change
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected changes, got none")
	}
}

