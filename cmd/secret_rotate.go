package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

// rotateStatus is the outcome of processing a single secret during rotation.
type rotateStatus string

const (
	// rotateStatusAlreadyRotated means the item's stored key_id already
	// matches the new key; it was defensively re-verified and left untouched.
	rotateStatusAlreadyRotated rotateStatus = "already_rotated"
	// rotateStatusRotated means the item was decrypted with the old key,
	// re-encrypted with the new key, verified, and written back.
	rotateStatusRotated rotateStatus = "rotated"
	// rotateStatusWouldRotate is the pre-commit state of an item that passed
	// verification and is queued to be written (dry-run terminal state).
	rotateStatusWouldRotate rotateStatus = "would_rotate"
	// rotateStatusFailed means verification or the write failed; the item's
	// stored ciphertext was left untouched.
	rotateStatusFailed rotateStatus = "failed"
)

// rotatePlanItem tracks one secret through the two-phase rotate pipeline:
// verify (Phase 1, always read-only) then commit (Phase 2, writes only
// items still in rotateStatusWouldRotate).
type rotatePlanItem struct {
	item          *store.Item
	status        rotateStatus
	newCiphertext []byte
	newKeyID      string
	err           error
}

type secretRotateOpts struct {
	project, env    string
	dryRun          bool
	continueOnError bool
	output          string
}

// rotateReport is the machine- and human-readable summary of a rotate run.
// It never carries ciphertext, plaintext, or key material — only key names,
// statuses, and error text (which itself is limited to key_id fingerprints
// and sentinel messages, never secret values).
type rotateReport struct {
	Project        string             `json:"project"`
	Env            string             `json:"env"`
	DryRun         bool               `json:"dry_run"`
	Total          int                `json:"total"`
	AlreadyRotated int                `json:"already_rotated"`
	Rotated        int                `json:"rotated"`
	WouldRotate    int                `json:"would_rotate,omitempty"`
	Failed         int                `json:"failed"`
	Items          []rotateReportItem `json:"items"`
}

type rotateReportItem struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func newSecretRotateCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string
	var dryRun, continueOnError bool

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Re-encrypt every secret in project+env from the old key to the new key",
		Long: `rotate re-encrypts every secret for --project/--env from the passphrase in
CONFIGCTL_OLD_SECRET_KEY to the passphrase in CONFIGCTL_SECRET_KEY.

Every secret is decrypted with the old key and the resulting plaintext is
re-encrypted and round-trip-verified with the new key BEFORE any write
happens (a two-phase verify-then-commit design). By default, if any single
secret fails verification nothing is written at all — pass
--continue-on-error to rotate the secrets that do verify and report the rest
as failed instead of aborting the whole run.

The operation is safely resumable: an item already encrypted under the new
key is detected via its stored key_id and left untouched, so re-running
rotate after a partial failure (or an interrupted process) only rewrites the
secrets that are still on the old key — there is never a window where an
item's on-disk state is ambiguous, because the stored key_id (visible via
'secret list' / 'secret get') is always the source of truth for what has and
has not been rotated.

Run with --dry-run first: it performs the full verification phase (proving
every secret can be decrypted with the old key and re-encrypted with the new
key) and reports exactly what would happen, without writing anything.

Example:
  export CONFIGCTL_SECRET_KEY="new-passphrase"
  export CONFIGCTL_OLD_SECRET_KEY="old-passphrase"
  platform-configctl secret rotate --project payments --env prod --dry-run
  platform-configctl secret rotate --project payments --env prod`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretRotate(cmd.Context(), d, secretRotateOpts{
				project:         project,
				env:             env,
				dryRun:          dryRun,
				continueOnError: continueOnError,
				output:          gf.output,
			}, cmd.OutOrStdout(), callerIdentity)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Verify and report without writing anything")
	cmd.Flags().BoolVar(&continueOnError, "continue-on-error", false,
		"Rotate the secrets that verify OK even if some fail (default: abort all on any verification failure)")
	return cmd
}

func runSecretRotate(
	ctx context.Context,
	d *deps,
	opts secretRotateOpts,
	stdout io.Writer,
	updatedBy func(context.Context, *deps) string,
) error {
	if err := requireProjectEnv(opts.project, opts.env); err != nil {
		return err
	}
	if err := d.cfg.RequireSecretKey(); err != nil {
		return err
	}

	items, err := d.store.List(ctx, opts.project, opts.env, store.ItemTypeSecret)
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	newKeyID, err := probeKeyID(d.cfg.SecretKey, opts.project, opts.env)
	if err != nil {
		return err
	}
	oldKeyAvailable := d.cfg.OldSecretKey != ""

	plan := buildRotationPlan(d, opts, items, newKeyID, oldKeyAvailable)
	failed := countStatus(plan, rotateStatusFailed)
	verifyAborted := failed > 0 && !opts.continueOnError

	if !opts.dryRun && !verifyAborted {
		commitRotationPlan(ctx, d, opts, plan, updatedBy)
	}

	report := buildRotateReport(opts, plan)
	logRotateReport(d, opts, plan, report)
	if writeErr := writeRotateReport(stdout, opts.output, report); writeErr != nil {
		return writeErr
	}

	switch {
	case verifyAborted:
		return fmt.Errorf(
			"rotation aborted: %d of %d secret(s) failed verification and nothing was written; "+
				"fix CONFIGCTL_OLD_SECRET_KEY or rerun with --continue-on-error",
			failed, len(items),
		)
	case report.Failed > 0:
		return fmt.Errorf("%d of %d secret(s) failed to rotate", report.Failed, report.Total)
	}
	return nil
}

// probeKeyID derives the key_id fingerprint for a passphrase without binding
// it to any particular secret's AAD. This is safe because key_id depends only
// on the derived key (passphrase + project+env salt), never on the per-secret
// key name used for AAD — see internal/crypto.NewAESGCMEncryptor.
func probeKeyID(passphrase, project, env string) (string, error) {
	enc, err := crypto.NewAESGCMEncryptor(passphrase, project, env, "")
	if err != nil {
		return "", err
	}
	return enc.KeyID(), nil
}

// buildRotationPlan is Phase 1: read-only classification and verification.
// It never calls store.Set and never returns early on a single item's
// failure — every item is evaluated so the caller gets a complete report.
func buildRotationPlan(d *deps, opts secretRotateOpts, items []*store.Item, newKeyID string, oldKeyAvailable bool) []*rotatePlanItem {
	plan := make([]*rotatePlanItem, 0, len(items))
	for _, item := range items {
		if item.KeyID == newKeyID {
			plan = append(plan, verifyAlreadyRotated(d, opts, item))
			continue
		}
		plan = append(plan, verifyNeedsRotation(d, opts, item, oldKeyAvailable))
	}
	return plan
}

func verifyAlreadyRotated(d *deps, opts secretRotateOpts, item *store.Item) *rotatePlanItem {
	pi := &rotatePlanItem{item: item}

	enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, opts.project, opts.env, item.Key)
	if err != nil {
		pi.status, pi.err = rotateStatusFailed, err
		return pi
	}
	if _, derr := decryptTolerant(enc, item); derr != nil {
		pi.status = rotateStatusFailed
		pi.err = fmt.Errorf("already on target key but failed to decrypt: %w", derr)
		return pi
	}

	pi.status = rotateStatusAlreadyRotated
	return pi
}

func verifyNeedsRotation(d *deps, opts secretRotateOpts, item *store.Item, oldKeyAvailable bool) *rotatePlanItem {
	pi := &rotatePlanItem{item: item}

	if !oldKeyAvailable {
		pi.status = rotateStatusFailed
		pi.err = errors.New("CONFIGCTL_OLD_SECRET_KEY is required to rotate this secret (not on the current key)")
		return pi
	}

	oldEnc, err := crypto.NewAESGCMEncryptor(d.cfg.OldSecretKey, opts.project, opts.env, item.Key)
	if err != nil {
		pi.status, pi.err = rotateStatusFailed, err
		return pi
	}
	plaintext, derr := decryptTolerant(oldEnc, item)
	if derr != nil {
		pi.status = rotateStatusFailed
		pi.err = fmt.Errorf("decrypt with old key: %w", derr)
		return pi
	}

	newEnc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, opts.project, opts.env, item.Key)
	if err != nil {
		pi.status, pi.err = rotateStatusFailed, err
		return pi
	}
	newCiphertext, newKeyID, err := newEnc.Encrypt(plaintext)
	if err != nil {
		pi.status = rotateStatusFailed
		pi.err = fmt.Errorf("encrypt with new key: %w", err)
		return pi
	}

	// Round-trip verify BEFORE this ciphertext is allowed anywhere near a write.
	roundTrip, err := newEnc.Decrypt(newCiphertext, newKeyID)
	if err != nil || !bytes.Equal(roundTrip, plaintext) {
		pi.status = rotateStatusFailed
		pi.err = errors.New("round-trip verification failed after re-encryption")
		return pi
	}

	pi.status = rotateStatusWouldRotate
	pi.newCiphertext = newCiphertext
	pi.newKeyID = newKeyID
	return pi
}

// decryptTolerant decrypts an item, treating the legacy-AAD fallback as a
// success (matching the existing 'secret get' behaviour) rather than an
// error, so pre-v2 ciphertexts remain rotatable.
func decryptTolerant(enc crypto.Encryptor, item *store.Item) ([]byte, error) {
	plaintext, err := enc.Decrypt([]byte(item.Value), item.KeyID)
	if errors.Is(err, crypto.ErrLegacyAAD) {
		return plaintext, nil
	}
	return plaintext, err
}

// commitRotationPlan is Phase 2: writes only items left in
// rotateStatusWouldRotate by Phase 1. A write failure on one item (e.g. an
// optimistic-lock conflict from a concurrent 'secret set') does not stop the
// rest — every remaining item still gets attempted, and the failure is
// recorded on that item alone.
func commitRotationPlan(
	ctx context.Context,
	d *deps,
	opts secretRotateOpts,
	plan []*rotatePlanItem,
	updatedBy func(context.Context, *deps) string,
) {
	for _, pi := range plan {
		if pi.status != rotateStatusWouldRotate {
			continue
		}

		h := sha256.Sum256(pi.newCiphertext)
		newItem := &store.Item{
			Project:   opts.project,
			Env:       opts.env,
			Key:       pi.item.Key,
			Value:     string(pi.newCiphertext),
			Type:      store.ItemTypeSecret,
			Encrypted: true,
			KeyID:     pi.newKeyID,
			Version:   pi.item.Version,
			Checksum:  fmt.Sprintf(checksumFormatSHA256, h),
			CreatedAt: pi.item.CreatedAt,
			UpdatedBy: updatedBy(ctx, d),
		}

		if err := d.store.Set(ctx, newItem); err != nil {
			pi.status = rotateStatusFailed
			pi.err = fmt.Errorf("write rotated secret: %w", err)
			continue
		}
		pi.status = rotateStatusRotated
	}
}

func countStatus(plan []*rotatePlanItem, status rotateStatus) int {
	n := 0
	for _, pi := range plan {
		if pi.status == status {
			n++
		}
	}
	return n
}

func buildRotateReport(opts secretRotateOpts, plan []*rotatePlanItem) *rotateReport {
	report := &rotateReport{
		Project: opts.project,
		Env:     opts.env,
		DryRun:  opts.dryRun,
		Total:   len(plan),
		Items:   make([]rotateReportItem, 0, len(plan)),
	}

	for _, pi := range plan {
		ri := rotateReportItem{Key: pi.item.Key, Status: string(pi.status)}
		if pi.err != nil {
			ri.Error = pi.err.Error()
		}
		report.Items = append(report.Items, ri)

		switch pi.status {
		case rotateStatusAlreadyRotated:
			report.AlreadyRotated++
		case rotateStatusRotated:
			report.Rotated++
		case rotateStatusWouldRotate:
			report.WouldRotate++
		case rotateStatusFailed:
			report.Failed++
		}
	}
	return report
}

func logRotateReport(d *deps, opts secretRotateOpts, plan []*rotatePlanItem, report *rotateReport) {
	d.log.Info("secret rotation report",
		zap.String(keyProject, opts.project),
		zap.String("env", opts.env),
		zap.Bool("dry_run", opts.dryRun),
		zap.Int("total", report.Total),
		zap.Int("already_rotated", report.AlreadyRotated),
		zap.Int("rotated", report.Rotated),
		zap.Int("would_rotate", report.WouldRotate),
		zap.Int("failed", report.Failed),
	)
	for _, pi := range plan {
		if pi.status == rotateStatusFailed {
			d.log.Error("secret failed rotation", zap.String("key", pi.item.Key), zap.Error(pi.err))
		}
	}
}

func writeRotateReport(w io.Writer, outputFormat string, report *rotateReport) error {
	if outputFormat == formatJSON {
		return json.NewEncoder(w).Encode(report)
	}

	_, _ = fmt.Fprintf(w, "project=%s env=%s dry_run=%t\n", report.Project, report.Env, report.DryRun)
	_, _ = fmt.Fprintf(w, "total=%d already_rotated=%d rotated=%d would_rotate=%d failed=%d\n",
		report.Total, report.AlreadyRotated, report.Rotated, report.WouldRotate, report.Failed)
	for _, item := range report.Items {
		if item.Error != "" {
			_, _ = fmt.Fprintf(w, "  [%s] %s: %s\n", item.Status, item.Key, item.Error)
			continue
		}
		_, _ = fmt.Fprintf(w, "  [%s] %s\n", item.Status, item.Key)
	}
	return nil
}
