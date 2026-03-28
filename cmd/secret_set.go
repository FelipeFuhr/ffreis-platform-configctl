package cmd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/logger"
	"github.com/ffreis/platform-configctl/internal/store"
)

func newSecretSetCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "set <key>",
		Short: "Set a secret value — reads plaintext from stdin to avoid shell history",
		Long: `set reads the secret value from stdin.

Example:
  echo -n "mysecret" | platform-configctl secret set mykey --project myproject --env prod
  platform-configctl secret set mykey --project myproject --env prod  (then type and press Ctrl-D)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretSet(cmd.Context(), d, project, env, args[0], os.Stdin)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	_ = gf
	return cmd
}

func runSecretSet(ctx context.Context, d *deps, project, env, key string, stdin io.Reader) error {
	if err := requireProjectEnv(project, env); err != nil {
		return err
	}
	if err := d.cfg.RequireSecretKey(); err != nil {
		return err
	}

	plaintext, err := readSecretValueFromStdin(stdin)
	if err != nil {
		return err
	}

	ciphertext, keyID, err := encryptSecretValue(d, project, env, plaintext)
	if err != nil {
		return err
	}

	d.log.Debug("encrypting secret",
		zap.String("key", key),
		logger.Masked(keyValue),
	)

	version, createdAt, err := existingSecretVersion(ctx, d.store, project, env, key)
	if err != nil {
		return err
	}

	item := buildSecretItem(project, env, key, ciphertext, keyID, version, createdAt, callerIdentity(ctx, d))
	if err := d.store.Set(ctx, item); err != nil {
		return fmt.Errorf("set secret: %w", err)
	}

	d.log.Info("secret set",
		zap.String(keyProject, project),
		zap.String("env", env),
		zap.String("key", key),
		zap.String("key_id", keyID),
	)
	return nil
}

func readSecretValueFromStdin(stdin io.Reader) ([]byte, error) {
	// Read plaintext from stdin — never from args or flags.
	plaintext, err := readStdin(stdin)
	if err != nil {
		return nil, fmt.Errorf("read secret from stdin: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("secret value must not be empty")
	}
	return plaintext, nil
}

func encryptSecretValue(d *deps, project, env string, plaintext []byte) ([]byte, string, error) {
	enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, project, env)
	if err != nil {
		return nil, "", err
	}

	ciphertext, keyID, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt secret: %w", err)
	}
	return ciphertext, keyID, nil
}

func existingSecretVersion(ctx context.Context, st store.Store, project, env, key string) (int64, time.Time, error) {
	existing, err := st.Get(ctx, project, env, store.ItemTypeSecret, key)
	if err != nil && err != store.ErrNotFound {
		return 0, time.Time{}, fmt.Errorf("get existing: %w", err)
	}
	if existing == nil {
		return 0, time.Time{}, nil
	}
	return existing.Version, existing.CreatedAt, nil
}

func buildSecretItem(project, env, key string, ciphertext []byte, keyID string, version int64, createdAt time.Time, updatedBy string) *store.Item {
	h := sha256.Sum256(ciphertext)
	return &store.Item{
		Project:   project,
		Env:       env,
		Key:       key,
		Value:     string(ciphertext),
		Type:      store.ItemTypeSecret,
		Encrypted: true,
		KeyID:     keyID,
		Version:   version,
		Checksum:  fmt.Sprintf(checksumFormatSHA256, h),
		CreatedAt: createdAt,
		UpdatedBy: updatedBy,
	}
}

// readStdin reads all bytes from stdin, trimming trailing newlines.
func readStdin(stdin io.Reader) ([]byte, error) {
	reader := bufio.NewReader(stdin)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	// Trim a single trailing newline (common from echo | piping).
	s := strings.TrimRight(string(raw), "\n\r")
	return []byte(s), nil
}
