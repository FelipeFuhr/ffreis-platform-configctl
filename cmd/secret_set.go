package cmd

import (
	"bufio"
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
			key := args[0]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}
			if err := d.cfg.RequireSecretKey(); err != nil {
				return err
			}

			// Read plaintext from stdin — never from args or flags.
			plaintext, err := readStdin()
			if err != nil {
				return fmt.Errorf("read secret from stdin: %w", err)
			}
			if len(plaintext) == 0 {
				return fmt.Errorf("secret value must not be empty")
			}

			enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, project, env)
			if err != nil {
				return err
			}

			ciphertext, keyID, err := enc.Encrypt(plaintext)
			if err != nil {
				return fmt.Errorf("encrypt secret: %w", err)
			}

			d.log.Debug("encrypting secret",
				zap.String("key", key),
				logger.Masked(keyValue),
			)

			// Check for existing item to preserve version.
			existing, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeSecret, key)
			if err != nil && err != store.ErrNotFound {
				return fmt.Errorf("get existing: %w", err)
			}

			var version int64
			var createdAt time.Time
			if existing != nil {
				version = existing.Version
				createdAt = existing.CreatedAt
			}

			h := sha256.Sum256(ciphertext)
			item := &store.Item{
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
				UpdatedBy: callerIdentity(cmd.Context(), d),
			}

			if err := d.store.Set(cmd.Context(), item); err != nil {
				return fmt.Errorf("set secret: %w", err)
			}

			d.log.Info("secret set",
				zap.String(keyProject, project),
				zap.String("env", env),
				zap.String("key", key),
				zap.String("key_id", keyID),
			)
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	_ = gf
	return cmd
}

// readStdin reads all bytes from os.Stdin, tripping trailing newlines.
func readStdin() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	// Trim a single trailing newline (common from echo | piping).
	s := strings.TrimRight(string(raw), "\n\r")
	return []byte(s), nil
}
