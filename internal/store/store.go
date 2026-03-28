package store

import "context"

// Store abstracts all DynamoDB operations. Implementations must be safe
// for concurrent use.
type Store interface {
	// Get retrieves a single item. Returns ErrNotFound if absent.
	Get(ctx context.Context, project, env string, itemType ItemType, key string) (*Item, error)

	// Set writes an item. If item.Version == 0 the item must not exist
	// (new item). Otherwise the stored version must equal item.Version
	// or ErrVersionConflict is returned.
	Set(ctx context.Context, item *Item) error

	// List returns all items of the given type for the project+env pair.
	List(ctx context.Context, project, env string, itemType ItemType) ([]*Item, error)

	// Delete removes an item. Returns nil if the item does not exist.
	Delete(ctx context.Context, project, env string, itemType ItemType, key string) error

	// ListProjects returns all distinct project names across all partitions.
	// This uses a DynamoDB scan and should be used sparingly.
	ListProjects(ctx context.Context) ([]string, error)
}
