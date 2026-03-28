package backup

import (
	"context"
	"fmt"
	"time"

	"github.com/ffreis/platform-configctl/internal/store"
)

// ExportOptions controls what is included in an export.
type ExportOptions struct {
	IncludeSecrets bool
	ToolVersion    string
	ExportedBy     string // IAM identity string; leave empty to omit
}

// Exporter reads items from the Store and produces a BackupFile.
type Exporter struct {
	st store.Store
}

// NewExporter constructs an Exporter.
func NewExporter(st store.Store) *Exporter {
	return &Exporter{st: st}
}

// Export retrieves all items for project+env and serialises them into a
// BackupFile. Secrets are included as stored ciphertext when
// opts.IncludeSecrets is true; otherwise secret items are omitted.
func (e *Exporter) Export(ctx context.Context, project, env string, opts ExportOptions) (*BackupFile, error) {
	bf := NewBackupFile(project, env, opts.ToolVersion, opts.ExportedBy)
	bf.Metadata.IncludesSecret = opts.IncludeSecrets

	configs, err := e.st.List(ctx, project, env, store.ItemTypeConfig)
	if err != nil {
		return nil, fmt.Errorf("list configs: %w", err)
	}
	for _, item := range configs {
		bf.Items = append(bf.Items, backupItemFromStoreItem(item))
	}

	if opts.IncludeSecrets {
		secrets, err := e.st.List(ctx, project, env, store.ItemTypeSecret)
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		for _, item := range secrets {
			bf.Items = append(bf.Items, backupItemFromStoreItem(item))
		}
	}

	if err := bf.Seal(); err != nil {
		return nil, fmt.Errorf("seal backup: %w", err)
	}
	return bf, nil
}

func backupItemFromStoreItem(item *store.Item) BackupItem {
	createdAt := item.CreatedAt.Format(time.RFC3339)
	updatedAt := item.UpdatedAt.Format(time.RFC3339)
	if item.CreatedAt.IsZero() {
		createdAt = ""
	}
	if item.UpdatedAt.IsZero() {
		updatedAt = ""
	}
	return BackupItem{
		Key:       item.Key,
		Value:     item.Value,
		ItemType:  string(item.Type),
		Encrypted: item.Encrypted,
		KeyID:     item.KeyID,
		Version:   item.Version,
		Checksum:  item.Checksum,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		UpdatedBy: item.UpdatedBy,
	}
}
