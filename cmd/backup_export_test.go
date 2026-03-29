package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/backup"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestIsStdoutOutput(t *testing.T) {
	t.Parallel()

	if !isStdoutOutput("") {
		t.Fatalf("isStdoutOutput(\"\") = false, want true")
	}
	if !isStdoutOutput("-") {
		t.Fatalf("isStdoutOutput(\"-\") = false, want true")
	}
	if isStdoutOutput("out.json") {
		t.Fatalf("isStdoutOutput(\"out.json\") = true, want false")
	}
}

func TestRequireSecretKeyIfNeeded(t *testing.T) {
	t.Parallel()

	cfg := &appconfig.Config{}
	if err := requireSecretKeyIfNeeded(cfg, false); err != nil {
		t.Fatalf("includeSecrets=false: error = %v", err)
	}
	if err := requireSecretKeyIfNeeded(cfg, true); err == nil {
		t.Fatalf("includeSecrets=true: error = nil, want error")
	}

	cfg.SecretKey = "x"
	if err := requireSecretKeyIfNeeded(cfg, true); err != nil {
		t.Fatalf("includeSecrets=true with key: error = %v", err)
	}
}

func TestRunBackupExport_WritesToStdout(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			switch itemType {
			case store.ItemTypeConfig:
				return []*store.Item{
					{Project: project, Env: env, Key: "a", Value: "v1", Type: store.ItemTypeConfig, Encrypted: false, Version: 1},
				}, nil
			case store.ItemTypeSecret:
				return []*store.Item{
					{Project: project, Env: env, Key: "s1", Value: "ciphertext", Type: store.ItemTypeSecret, Encrypted: true, KeyID: "kid", Version: 2},
				}, nil
			default:
				return nil, nil
			}
		},
	}

	d := &deps{
		cfg:   &appconfig.Config{SecretKey: "secret"},
		log:   noopLogger{},
		store: st,
	}

	var stdout bytes.Buffer
	writeFileCalled := false
	writeFile := func(string, []byte, os.FileMode) error {
		writeFileCalled = true
		return nil
	}

	if err := runBackupExport(
		context.Background(),
		d,
		backupExportOpts{project: "proj", env: "dev", outputPath: "-", includeSecrets: true},
		&stdout,
		writeFile,
		func(context.Context, *deps) string { return "tester" },
	); err != nil {
		t.Fatalf("runBackupExport error = %v", err)
	}
	if writeFileCalled {
		t.Fatalf("writeFile called unexpectedly")
	}

	var bf backup.BackupFile
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &bf); err != nil {
		t.Fatalf("unmarshal stdout: %v", err)
	}
	if bf.Metadata.Project != "proj" || bf.Metadata.Environment != "dev" {
		t.Fatalf("metadata project/env = %q/%q, want proj/dev", bf.Metadata.Project, bf.Metadata.Environment)
	}
	if !bf.Metadata.IncludesSecret {
		t.Fatalf("IncludesSecret = false, want true")
	}
	if bf.Metadata.ExportedBy != "tester" {
		t.Fatalf("ExportedBy = %q, want tester", bf.Metadata.ExportedBy)
	}
	if bf.Metadata.ItemCount != 2 {
		t.Fatalf("ItemCount = %d, want 2", bf.Metadata.ItemCount)
	}
	if err := bf.Verify(); err != nil {
		t.Fatalf("backup Verify() error = %v", err)
	}
}

func TestRunBackupExport_WritesToFile(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			if itemType != store.ItemTypeConfig {
				return nil, nil
			}
			return []*store.Item{
				{Project: project, Env: env, Key: "a", Value: "v1", Type: store.ItemTypeConfig, Encrypted: false, Version: 1},
			}, nil
		},
	}

	d := &deps{
		cfg:   &appconfig.Config{},
		log:   noopLogger{},
		store: st,
	}

	var stdout bytes.Buffer
	var gotPath string
	var gotData []byte
	var gotPerm os.FileMode

	writeFile := func(path string, data []byte, perm os.FileMode) error {
		gotPath = path
		gotData = append([]byte(nil), data...)
		gotPerm = perm
		return nil
	}

	if err := runBackupExport(
		context.Background(),
		d,
		backupExportOpts{project: "proj", env: "dev", outputPath: "out.json", includeSecrets: false},
		&stdout,
		writeFile,
		func(context.Context, *deps) string { return "tester" },
	); err != nil {
		t.Fatalf("runBackupExport error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}

	if gotPath != "out.json" {
		t.Fatalf("writeFile path = %q, want out.json", gotPath)
	}
	if gotPerm != 0600 {
		t.Fatalf("writeFile perm = %v, want 0600", gotPerm)
	}
	if len(gotData) == 0 || gotData[len(gotData)-1] != '\n' {
		t.Fatalf("writeFile data missing trailing newline")
	}

	var bf backup.BackupFile
	if err := json.Unmarshal(bytes.TrimSpace(gotData), &bf); err != nil {
		t.Fatalf("unmarshal file data: %v", err)
	}
	if bf.Metadata.ItemCount != 1 {
		t.Fatalf("ItemCount = %d, want 1", bf.Metadata.ItemCount)
	}
}

