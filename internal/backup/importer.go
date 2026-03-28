package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ffreis/platform-configctl/internal/store"
)

// ImportOptions controls import behaviour.
type ImportOptions struct {
	// DryRun performs all validation but writes nothing.
	DryRun bool
	// Overwrite allows overwriting items with a higher version than the backup.
	// When false, version conflicts abort the import.
	Overwrite bool
	// UpdatedBy sets the IAM identity recorded on written items.
	UpdatedBy string
}

// ImportResult describes what happened during an import.
type ImportResult struct {
	Written int
	Skipped int
	Failed  int
	DryRun  bool
	Errors  []error
}

// Importer reads a BackupFile and writes items to the Store.
type Importer struct {
	st store.Store
}

// NewImporter constructs an Importer.
func NewImporter(st store.Store) *Importer {
	return &Importer{st: st}
}

// ImportFromFile reads a BackupFile from path and imports it.
func (i *Importer) ImportFromFile(ctx context.Context, path string, opts ImportOptions) (*ImportResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	var bf BackupFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, fmt.Errorf("parse backup file: %w", err)
	}

	return i.Import(ctx, &bf, opts)
}

// Import validates and applies a BackupFile to the Store.
func (i *Importer) Import(ctx context.Context, bf *BackupFile, opts ImportOptions) (*ImportResult, error) {
	if err := verifyBackupFile(bf); err != nil {
		return nil, err
	}

	result := &ImportResult{DryRun: opts.DryRun}

	for _, bi := range bf.Items {
		i.importOne(ctx, bf, bi, opts, result)
	}

	return result, nil
}

func verifyBackupFile(bf *BackupFile) error {
	if bf.Format != FormatIdentifier {
		return fmt.Errorf("unrecognised backup format: %q", bf.Format)
	}
	if bf.SchemaVersion != SchemaVersion {
		return &ErrUnknownSchemaVersion{Version: bf.SchemaVersion}
	}
	return bf.Verify()
}

func (i *Importer) importOne(ctx context.Context, bf *BackupFile, bi BackupItem, opts ImportOptions, result *ImportResult) {
	item := storeItemFromBackupItem(bi, bf.Metadata.Project, bf.Metadata.Environment, opts.UpdatedBy)

	if opts.DryRun {
		result.Written++
		return
	}

	if err := i.resolveImportVersion(ctx, item, bi, opts.Overwrite, result); err != nil {
		return
	}

	if err := i.st.Set(ctx, item); err != nil {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Errorf("set %s: %w", item.Key, err))
		return
	}
	result.Written++
}

func (i *Importer) resolveImportVersion(
	ctx context.Context,
	item *store.Item,
	bi BackupItem,
	overwrite bool,
	result *ImportResult,
) error {
	current, err := i.st.Get(ctx, item.Project, item.Env, item.Type, item.Key)
	if err != nil && err != store.ErrNotFound {
		result.Failed++
		result.Errors = append(result.Errors, fmt.Errorf("get %s: %w", item.Key, err))
		return err
	}

	if err == store.ErrNotFound {
		item.Version = 0
		return nil
	}

	if overwrite {
		item.Version = current.Version
		return nil
	}

	item.Version = bi.Version
	return nil
}

func storeItemFromBackupItem(bi BackupItem, project, env, updatedBy string) *store.Item {
	createdAt, _ := time.Parse(time.RFC3339, bi.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, bi.UpdatedAt)

	by := bi.UpdatedBy
	if updatedBy != "" {
		by = updatedBy
	}

	return &store.Item{
		Project:   project,
		Env:       env,
		Key:       bi.Key,
		Value:     bi.Value,
		Type:      store.ItemType(bi.ItemType),
		Encrypted: bi.Encrypted,
		KeyID:     bi.KeyID,
		Version:   bi.Version,
		Checksum:  bi.Checksum,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		UpdatedBy: by,
	}
}
