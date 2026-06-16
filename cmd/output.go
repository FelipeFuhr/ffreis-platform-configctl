package cmd

import (
	"io"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	platformui "github.com/ffreis/platform-cli/pkg/ui"
)

type commandOutput struct {
	out io.Writer
	err io.Writer
	ui  *platformui.Presenter
}

func newCommandOutput(cmd *cobra.Command, presenter *platformui.Presenter) *commandOutput {
	return &commandOutput{
		out: cmd.OutOrStdout(),
		err: cmd.ErrOrStderr(),
		ui:  presenter,
	}
}

func (o *commandOutput) Line(text string) {
	writeLine(o.out, text)
}

func (o *commandOutput) ErrLine(text string) {
	writeLine(o.err, text)
}

func (o *commandOutput) Blank() {
	writeLine(o.out, "")
}

func (o *commandOutput) Header(title, subtitle string) {
	if o.ui != nil {
		o.Line(o.ui.Header(title, subtitle))
		return
	}
	o.Line(title)
	if subtitle != "" {
		o.Line(subtitle)
	}
}

func (o *commandOutput) Summary(title string, parts ...string) {
	if o.ui != nil {
		o.Line(o.ui.Summary(title, parts...))
		return
	}
	filtered := filterParts(parts)
	if len(filtered) == 0 {
		o.Line(title)
		return
	}
	o.Line(title + ": " + strings.Join(filtered, "  "))
}

func (o *commandOutput) Status(kind, label, detail string) {
	if o.ui != nil {
		o.Line(o.ui.Status(kind, label, detail))
		return
	}
	o.Line("[" + label + "] " + detail)
}

func (o *commandOutput) ErrStatus(kind, label, detail string) {
	if o.ui != nil {
		o.ErrLine(o.ui.Status(kind, label, detail))
		return
	}
	o.ErrLine("[" + label + "] " + detail)
}

func (o *commandOutput) Table(headers []string, rows [][]string) error {
	w := tabwriter.NewWriter(o.out, 0, 0, 2, ' ', 0)
	stripped := make([]string, len(headers))
	for i, h := range headers {
		stripped[i] = stripANSI(h)
	}
	_, _ = io.WriteString(w, strings.Join(stripped, "\t")+"\n")
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, cell := range row {
			cells[i] = stripANSI(cell)
		}
		_, _ = io.WriteString(w, strings.Join(cells, "\t")+"\n")
	}
	return w.Flush()
}

var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiEscapeRE.ReplaceAllString(s, "")
}

func writeLine(w io.Writer, text string) {
	_, _ = io.WriteString(w, text+"\n")
}

func filterParts(parts []string) []string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			filtered = append(filtered, part)
		}
	}
	return filtered
}
