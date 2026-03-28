package backup_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ffreis/platform-configctl/internal/backup"
)

const (
	testProject   = "payments"
	testEnv       = "prod"
	testVersion   = "0.1.0"
	testSource    = "test"
	testTimestamp = "2024-01-01T00:00:00Z"
)

func TestBackupRoundtrip(t *testing.T) {
	bf := backup.NewBackupFile(testProject, testEnv, testVersion, testSource)

	bf.Items = []backup.BackupItem{
		{
			Key:       "db_host",
			Value:     "localhost",
			ItemType:  "config",
			Encrypted: false,
			Version:   1,
			UpdatedAt: testTimestamp,
		},
		{
			Key:       "api_key",
			Value:     "<ciphertext>",
			ItemType:  "secret",
			Encrypted: true,
			KeyID:     "sha256:abc123",
			Version:   2,
			UpdatedAt: testTimestamp,
		},
	}

	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bf.Checksum == "" {
		t.Fatal("checksum must be set after Seal")
	}

	// Verify passes on the original.
	if err := bf.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Serialise and deserialise.
	raw, err := json.Marshal(bf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored backup.BackupFile
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if err := restored.Verify(); err != nil {
		t.Fatalf("Verify after roundtrip: %v", err)
	}

	if restored.Metadata.Project != testProject {
		t.Errorf("project: got %q, want %q", restored.Metadata.Project, testProject)
	}
	if restored.Metadata.ItemCount != 2 {
		t.Errorf("item_count: got %d, want 2", restored.Metadata.ItemCount)
	}
}

func TestVerifyChecksumMismatch(t *testing.T) {
	bf := backup.NewBackupFile("p", "e", testVersion, testSource)
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "v", ItemType: "config", Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Tamper with an item value after sealing.
	bf.Items[0].Value = "tampered"

	err := bf.Verify()
	if err != backup.ErrChecksumMismatch {
		t.Errorf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestSealIsIdempotent(t *testing.T) {
	bf := backup.NewBackupFile("p", "e", testVersion, testSource)
	bf.Items = []backup.BackupItem{
		{Key: "k", Value: "v", ItemType: "config", Version: 1},
	}
	if err := bf.Seal(); err != nil {
		t.Fatal(err)
	}
	cs1 := bf.Checksum

	if err := bf.Seal(); err != nil {
		t.Fatal(err)
	}
	cs2 := bf.Checksum

	if cs1 != cs2 {
		t.Error("Seal must be deterministic: checksums differ")
	}
}

func TestUnknownSchemaVersion(t *testing.T) {
	raw := []byte(`{
		"format": "platform-configctl-backup",
		"schema_version": "99",
		"checksum": "sha256:abc",
		"items": []
	}`)

	importer := backup.NewImporter(nil)
	var bf backup.BackupFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := importer.Import(context.Background(), &bf, backup.ImportOptions{})
	if err == nil {
		t.Fatal("expected error for unknown schema version")
	}
}
