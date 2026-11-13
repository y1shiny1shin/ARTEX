package db

import "testing"

func TestInterceptSourceModelWinsOverRuleID(t *testing.T) {
	if got := interceptSource(7, "[模型] reviewed"); got != "model" {
		t.Fatalf("model-reviewed rule hit source = %q, want model", got)
	}
	if got := interceptSource(7, "rule message"); got != "rule" {
		t.Fatalf("unreviewed rule hit source = %q, want rule", got)
	}
	if got := interceptSource(0, "[模型] reviewed"); got != "model" {
		t.Fatalf("model source = %q, want model", got)
	}
	if got := interceptSource(0, "legacy reason"); got != "unknown" {
		t.Fatalf("legacy source = %q, want unknown", got)
	}
}
