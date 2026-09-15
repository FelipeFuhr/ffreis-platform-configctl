package store

import "time"

// ItemType distinguishes configs from secrets at the storage layer.
type ItemType string

const (
	ItemTypeConfig ItemType = "config"
	ItemTypeSecret ItemType = "secret"
)

// PKPrefix returns the partition key prefix for the item type's sort key.
func (t ItemType) SKPrefix() string {
	switch t {
	case ItemTypeSecret:
		return skPrefixSecret
	default:
		return skPrefixConfig
	}
}

// Item is the canonical in-memory representation of a single stored entry.
type Item struct {
	Project   string
	Env       string
	Key       string
	Value     string // plaintext for config; base64 AES-GCM ciphertext for secret
	Type      ItemType
	Encrypted bool
	KeyID     string // fingerprint of encryption key; empty for configs
	Version   int64
	Checksum  string // SHA-256 of Value (stored form)
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// PK returns the DynamoDB partition key for this item.
func (i *Item) PK() string {
	return pkFor(i.Project, i.Env)
}

// SK returns the DynamoDB sort key for this item.
func (i *Item) SK() string {
	return i.Type.SKPrefix() + i.Key
}
