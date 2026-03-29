package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ffreis/platform-configctl/internal/validate"
)

func TestWriteValidationErrorsText(t *testing.T) {
	t.Parallel()

	errs := []validate.ValidationError{
		{Key: "a", Rule: "r1", Msg: "m1"},
		{Key: "b", Rule: "r2", Msg: "m2"},
	}

	var buf bytes.Buffer
	writeValidationErrorsText(&buf, errs)

	want := "" +
		"FAIL key=a rule=r1: m1\n" +
		"FAIL key=b rule=r2: m2\n"
	if buf.String() != want {
		t.Fatalf("text output mismatch\n--- got ---\n%s--- want ---\n%s", buf.String(), want)
	}
}

func TestWriteValidationErrorsJSON(t *testing.T) {
	t.Parallel()

	errs := []validate.ValidationError{
		{Key: "a", Rule: "r1", Msg: "m1"},
	}

	var buf bytes.Buffer
	if err := writeValidationErrorsJSON(&buf, errs); err != nil {
		t.Fatalf("writeValidationErrorsJSON error = %v", err)
	}

	var got []validateJSONErr
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(output) = %d, want 1", len(got))
	}
	if got[0].Key != "a" || got[0].Rule != "r1" || got[0].Msg != "m1" {
		t.Fatalf("output[0] = %#v, unexpected", got[0])
	}
}
