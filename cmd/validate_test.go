package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunValidate_Pass(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			if itemType != store.ItemTypeConfig {
				t.Fatalf("unexpected list type: %s", itemType)
			}
			return []*store.Item{{Project: project, Env: env, Key: "k1", Value: "v1", Type: store.ItemTypeConfig}}, nil
		},
	}

	var stdout, stderr bytes.Buffer
	err := runValidate(
		context.Background(),
		st,
		noopLogger{},
		validateOpts{project: "proj", env: "dev", outputFormat: "text"},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("runValidate error = %v", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunValidate_ListError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return nil, errors.New("boom")
		},
	}

	var stdout, stderr bytes.Buffer
	err := runValidate(
		context.Background(),
		st,
		noopLogger{},
		validateOpts{project: "proj", env: "dev", outputFormat: "text"},
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatalf("error = nil, want error")
	}
}

func TestRunValidate_Fail_Text(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			return []*store.Item{{Project: project, Env: env, Key: "k1", Value: "", Type: store.ItemTypeConfig, Encrypted: false}}, nil
		},
	}

	var stdout, stderr bytes.Buffer
	err := runValidate(
		context.Background(),
		st,
		noopLogger{},
		validateOpts{project: "proj", env: "dev", outputFormat: "text"},
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatalf("runValidate error = nil, want error")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "FAIL key=k1 rule=non-empty-value: value must not be empty") {
		t.Fatalf("stderr did not include expected failure, got: %q", stderr.String())
	}
}

func TestRunValidate_Fail_JSON(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
			return []*store.Item{{Project: project, Env: env, Key: "k1", Value: "", Type: store.ItemTypeConfig, Encrypted: false}}, nil
		},
	}

	var stdout, stderr bytes.Buffer
	err := runValidate(
		context.Background(),
		st,
		noopLogger{},
		validateOpts{project: "proj", env: "dev", outputFormat: formatJSON},
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatalf("runValidate error = nil, want error")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var got []validateJSONErr
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stdout: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(output) = %d, want 1", len(got))
	}
	if got[0].Key != "k1" || got[0].Rule != "non-empty-value" {
		t.Fatalf("output[0] = %#v, unexpected", got[0])
	}
}

func TestRunValidate_Fail_JSON_WriteError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
			return []*store.Item{{Project: "proj", Env: "dev", Key: "k1", Value: "", Type: store.ItemTypeConfig, Encrypted: false}}, nil
		},
	}

	var stderr bytes.Buffer
	err := runValidate(
		context.Background(),
		st,
		noopLogger{},
		validateOpts{project: "proj", env: "dev", outputFormat: formatJSON},
		errWriter{},
		&stderr,
	)
	if err == nil {
		t.Fatalf("error = nil, want error")
	}
}
