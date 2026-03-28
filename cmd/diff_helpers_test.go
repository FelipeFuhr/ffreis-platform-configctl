package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ffreis/platform-configctl/internal/backup"
	"github.com/ffreis/platform-configctl/internal/diff"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestSnapshotItemsFromBackup(t *testing.T) {
	t.Parallel()

	bf := &backup.BackupFile{
		Items: []backup.BackupItem{
			{
				Key:       "a",
				Value:     "v1",
				ItemType:  string(store.ItemTypeConfig),
				Encrypted: false,
				KeyID:     "",
				Version:   1,
			},
			{
				Key:       "b",
				Value:     "ciphertext",
				ItemType:  string(store.ItemTypeSecret),
				Encrypted: true,
				KeyID:     "kid",
				Version:   2,
			},
		},
	}

	got := snapshotItemsFromBackup("proj", "env", bf)
	if len(got) != 2 {
		t.Fatalf("len(snapshot) = %d, want 2", len(got))
	}

	if got[0].Project != "proj" || got[0].Env != "env" {
		t.Fatalf("snapshot[0] project/env = %q/%q, want proj/env", got[0].Project, got[0].Env)
	}
	if got[0].Key != "a" || got[0].Value != "v1" || got[0].Type != store.ItemTypeConfig || got[0].Encrypted || got[0].Version != 1 {
		t.Fatalf("snapshot[0] = %#v, unexpected", got[0])
	}

	if got[1].Key != "b" || got[1].Value != "ciphertext" || got[1].Type != store.ItemTypeSecret || !got[1].Encrypted || got[1].KeyID != "kid" || got[1].Version != 2 {
		t.Fatalf("snapshot[1] = %#v, unexpected", got[1])
	}
}

func TestWriteDiffText(t *testing.T) {
	t.Parallel()

	r := &diff.Result{
		Added: []diff.Change{
			{Kind: diff.Added, Key: "k1", ItemType: store.ItemTypeConfig, NewValue: "v1"},
		},
		Modified: []diff.Change{
			{Kind: diff.Modified, Key: "k2", ItemType: store.ItemTypeConfig, OldValue: "v2", NewValue: "v3"},
		},
		Deleted: []diff.Change{
			{Kind: diff.Deleted, Key: "k3", ItemType: store.ItemTypeSecret, OldValue: "<encrypted>"},
		},
	}

	var buf bytes.Buffer
	writeDiffText(&buf, r)

	want := "" +
		"+ [config] k1 = v1\n" +
		"~ [config] k2: v2 → v3\n" +
		"- [secret] k3 = <encrypted>\n"
	if buf.String() != want {
		t.Fatalf("diff text output mismatch\n--- got ---\n%s--- want ---\n%s", buf.String(), want)
	}
}

func TestWriteDiffOutputJSON(t *testing.T) {
	t.Parallel()

	r := &diff.Result{
		Added: []diff.Change{
			{Kind: diff.Added, Key: "k1", ItemType: store.ItemTypeConfig, NewValue: "v1"},
		},
		Unchanged: []diff.Change{
			{Kind: diff.Unchanged, Key: "k2", ItemType: store.ItemTypeConfig, OldValue: "v2", NewValue: "v2"},
		},
	}

	var buf bytes.Buffer
	if err := writeDiffOutput(&buf, formatJSON, r); err != nil {
		t.Fatalf("writeDiffOutput(json) error = %v", err)
	}

	var got []diff.Change
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(output) = %d, want 2", len(got))
	}
	if got[0].Kind != diff.Added || got[0].Key != "k1" || got[0].ItemType != store.ItemTypeConfig || got[0].NewValue != "v1" {
		t.Fatalf("output[0] = %#v, unexpected", got[0])
	}
	if got[1].Kind != diff.Unchanged || got[1].Key != "k2" || got[1].OldValue != "v2" || got[1].NewValue != "v2" {
		t.Fatalf("output[1] = %#v, unexpected", got[1])
	}
}
