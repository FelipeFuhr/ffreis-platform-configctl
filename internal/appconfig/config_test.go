package appconfig

import "testing"

func TestLoad_MissingTable(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	_, err := Load()
	if err != ErrMissingTable {
		t.Fatalf("Load() err = %v, want %v", err, ErrMissingTable)
	}
}

func TestLoad_UsesRegionAndDefaultLevel(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "tbl")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("CONFIGCTL_LOG_LEVEL", "")
	t.Setenv("CONFIGCTL_SECRET_KEY", "")
	t.Setenv("CONFIGCTL_OLD_SECRET_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	if cfg.TableName != "tbl" {
		t.Fatalf("TableName = %q, want %q", cfg.TableName, "tbl")
	}
	if cfg.AWSRegion != "us-east-1" {
		t.Fatalf("AWSRegion = %q, want %q", cfg.AWSRegion, "us-east-1")
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestLoad_PrefersAWSDefaultRegion(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "tbl")
	t.Setenv("AWS_DEFAULT_REGION", "sa-east-1")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("CONFIGCTL_LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	if cfg.AWSRegion != "sa-east-1" {
		t.Fatalf("AWSRegion = %q, want %q", cfg.AWSRegion, "sa-east-1")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestLoadOptional_ResolvesSecretKeys(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	t.Setenv("CONFIGCTL_SECRET_KEY", "current-key")
	t.Setenv("CONFIGCTL_OLD_SECRET_KEY", "old-key")

	cfg := LoadOptional()
	if cfg.TableName != "" {
		t.Fatalf("TableName = %q, want empty", cfg.TableName)
	}
	if cfg.SecretKey != "current-key" {
		t.Fatalf("SecretKey = %q, want current-key", cfg.SecretKey)
	}
	if cfg.OldSecretKey != "old-key" {
		t.Fatalf("OldSecretKey = %q, want old-key", cfg.OldSecretKey)
	}
}

func TestRequireSecretKey(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	if err := cfg.RequireSecretKey(); err == nil {
		t.Fatal("RequireSecretKey() = nil, want error when SecretKey is empty")
	}

	cfg.SecretKey = "k"
	if err := cfg.RequireSecretKey(); err != nil {
		t.Fatalf("RequireSecretKey() = %v, want nil when SecretKey is set", err)
	}
}
