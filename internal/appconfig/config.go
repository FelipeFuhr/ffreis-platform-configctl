package appconfig

import (
	"errors"
	"os"
)

// Config holds all runtime configuration resolved from environment variables
// and CLI flags. No hardcoded defaults exist for security-sensitive fields.
type Config struct {
	// AWS
	AWSRegion string
	// DynamoDB
	TableName string
	// Encryption — never log this value
	SecretKey    string
	OldSecretKey string // used during key rotation only
	// Logging
	LogLevel string
}

// ErrMissingTable is returned when no table name is configured.
var ErrMissingTable = errors.New("CONFIGCTL_TABLE environment variable is required")

// Load resolves Config from environment variables.
// Callers may override individual fields after calling Load (e.g. from CLI flags).
func Load() (*Config, error) {
	table := os.Getenv("CONFIGCTL_TABLE")
	if table == "" {
		return nil, ErrMissingTable
	}

	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}

	level := os.Getenv("CONFIGCTL_LOG_LEVEL")
	if level == "" {
		level = "info"
	}

	return &Config{
		AWSRegion:    region,
		TableName:    table,
		SecretKey:    os.Getenv("CONFIGCTL_SECRET_KEY"),
		OldSecretKey: os.Getenv("CONFIGCTL_OLD_SECRET_KEY"),
		LogLevel:     level,
	}, nil
}

// RequireSecretKey returns an error if SecretKey is not set.
// Call this before any secret operation.
func (c *Config) RequireSecretKey() error {
	if c.SecretKey == "" {
		return errors.New("CONFIGCTL_SECRET_KEY environment variable is required for secret operations")
	}
	return nil
}
