package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func newTestCommandOutput() (*commandOutput, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	return newCommandOutput(cmd, nil), &out, &errOut
}

func TestCommandOutput_Line(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Line("hello")
	if out.String() != "hello\n" {
		t.Fatalf("Line() wrote %q, want %q", out.String(), "hello\n")
	}
}

func TestCommandOutput_ErrLine(t *testing.T) {
	t.Parallel()

	o, _, errOut := newTestCommandOutput()
	o.ErrLine("oops")
	if errOut.String() != "oops\n" {
		t.Fatalf("ErrLine() wrote %q, want %q", errOut.String(), "oops\n")
	}
}

func TestCommandOutput_Blank(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Blank()
	if out.String() != "\n" {
		t.Fatalf("Blank() wrote %q, want %q", out.String(), "\n")
	}
}

func TestCommandOutput_Header_NoUI(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Header("Title", "Subtitle")
	if out.String() != "Title\nSubtitle\n" {
		t.Fatalf("Header() wrote %q, want %q", out.String(), "Title\nSubtitle\n")
	}
}

func TestCommandOutput_Header_NoUI_NoSubtitle(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Header("Title", "")
	if out.String() != "Title\n" {
		t.Fatalf("Header() wrote %q, want %q", out.String(), "Title\n")
	}
}

func TestCommandOutput_Summary_NoUI_WithParts(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Summary("Done", "a=1", "", "b=2")
	want := "Done: a=1  b=2\n"
	if out.String() != want {
		t.Fatalf("Summary() wrote %q, want %q", out.String(), want)
	}
}

func TestCommandOutput_Summary_NoUI_NoParts(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Summary("Done", "", "  ")
	if out.String() != "Done\n" {
		t.Fatalf("Summary() wrote %q, want %q", out.String(), "Done\n")
	}
}

func TestCommandOutput_Status_NoUI(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	o.Status("ok", "config", "set")
	if out.String() != "[config] set\n" {
		t.Fatalf("Status() wrote %q, want %q", out.String(), "[config] set\n")
	}
}

func TestCommandOutput_ErrStatus_NoUI(t *testing.T) {
	t.Parallel()

	o, _, errOut := newTestCommandOutput()
	o.ErrStatus("fail", "secret", "not found")
	if errOut.String() != "[secret] not found\n" {
		t.Fatalf("ErrStatus() wrote %q, want %q", errOut.String(), "[secret] not found\n")
	}
}

func TestCommandOutput_Table(t *testing.T) {
	t.Parallel()

	o, out, _ := newTestCommandOutput()
	if err := o.Table([]string{"KEY", "VALUE"}, [][]string{{"a", "1"}, {"b", "2"}}); err != nil {
		t.Fatalf("Table() error = %v", err)
	}
	got := out.String()
	if got == "" {
		t.Fatal("Table() wrote nothing")
	}
	// Both header and rows must be present (tabwriter pads columns, so check substrings).
	for _, want := range []string{"KEY", "VALUE", "a", "1", "b", "2"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Errorf("Table() output missing %q, got: %s", want, got)
		}
	}
}

func TestStripANSI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no escape codes", "plain text", "plain text"},
		{"color code", "\x1b[31mred\x1b[0m", "red"},
		{"multiple codes", "\x1b[1m\x1b[32mgreen bold\x1b[0m", "green bold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stripANSI(tt.in); got != tt.want {
				t.Errorf("stripANSI(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFilterParts(t *testing.T) {
	t.Parallel()

	got := filterParts([]string{"a", "", "  ", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("filterParts() = %#v, want [a b]", got)
	}
}

func TestFilterParts_AllEmpty(t *testing.T) {
	t.Parallel()

	got := filterParts([]string{"", "  "})
	if len(got) != 0 {
		t.Fatalf("filterParts() = %#v, want empty", got)
	}
}
