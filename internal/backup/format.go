package backup

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	FormatIdentifier = "platform-configctl-backup"
	SchemaVersion    = "1"
)

// ErrChecksumMismatch is returned when the file's checksum does not match
// the computed checksum of the items array.
var ErrChecksumMismatch = errors.New("backup checksum mismatch: file may be corrupted")

// ErrUnknownSchemaVersion is returned when the schema_version is not handled.
type ErrUnknownSchemaVersion struct{ Version string }

func (e *ErrUnknownSchemaVersion) Error() string {
	return "unknown backup schema version: " + e.Version
}

// BackupFile is the canonical JSON structure written and read by export/import.
type BackupFile struct {
	Format        string       `json:"format"`
	SchemaVersion string       `json:"schema_version"`
	Metadata      Metadata     `json:"metadata"`
	Checksum      string       `json:"checksum"`
	Items         []BackupItem `json:"items"`
}

// Metadata holds provenance information about the backup.
type Metadata struct {
	ToolVersion    string `json:"tool_version"`
	ExportedAt     string `json:"exported_at"`
	ExportedBy     string `json:"exported_by"`
	Project        string `json:"project"`
	Environment    string `json:"environment"`
	ItemCount      int    `json:"item_count"`
	IncludesSecret bool   `json:"includes_secrets"`
}

// BackupItem is a single entry in the backup file.
type BackupItem struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	ItemType  string `json:"item_type"`
	Encrypted bool   `json:"encrypted"`
	KeyID     string `json:"key_id,omitempty"`
	Version   int64  `json:"version"`
	Checksum  string `json:"checksum"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

// NewBackupFile initialises a BackupFile with required fields.
func NewBackupFile(project, env, toolVersion, exportedBy string) *BackupFile {
	return &BackupFile{
		Format:        FormatIdentifier,
		SchemaVersion: SchemaVersion,
		Metadata: Metadata{
			ToolVersion: toolVersion,
			ExportedAt:  time.Now().UTC().Format(time.RFC3339),
			ExportedBy:  exportedBy,
			Project:     project,
			Environment: env,
		},
	}
}

// Seal computes and sets the checksum over the Items array.
// Must be called after all items are added and before serialisation.
func (f *BackupFile) Seal() error {
	f.Metadata.ItemCount = len(f.Items)
	cs, err := computeChecksum(f.Items)
	if err != nil {
		return err
	}
	f.Checksum = cs
	return nil
}

// Verify recomputes the checksum and compares it to the stored value.
func (f *BackupFile) Verify() error {
	cs, err := computeChecksum(f.Items)
	if err != nil {
		return err
	}
	if cs != f.Checksum {
		return ErrChecksumMismatch
	}
	return nil
}

// computeChecksum produces SHA-256 over canonical (sorted-key) JSON of items.
func computeChecksum(items []BackupItem) (string, error) {
	// Sort items for deterministic output.
	sorted := make([]BackupItem, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ItemType != sorted[j].ItemType {
			return sorted[i].ItemType < sorted[j].ItemType
		}
		return sorted[i].Key < sorted[j].Key
	})

	raw, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("marshal items for checksum: %w", err)
	}

	h := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", h), nil
}
