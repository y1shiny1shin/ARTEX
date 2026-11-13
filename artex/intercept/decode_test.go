package intercept

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestDecodePayloadsBase64(t *testing.T) {
	payloads := DecodePayloads([]string{`{"command":"echo cm0gLXJmIC8= | base64 -d | bash"}`})
	if len(payloads) == 0 {
		t.Fatal("expected at least one decoded payload")
	}
	found := false
	for _, p := range payloads {
		if p.Encoding == "base64" && strings.Contains(p.Text, "rm -rf /") {
			found = true
		}
	}
	if !found {
		t.Fatalf("decoded base64 not found: %+v", payloads)
	}
}

func TestDecodePayloadsURL(t *testing.T) {
	payloads := DecodePayloads([]string{"cmd=rm%20-rf%20%2Ftmp%2Fx"})
	found := false
	for _, p := range payloads {
		if p.Encoding == "url" && strings.Contains(p.Text, "rm -rf /tmp/x") {
			found = true
		}
	}
	if !found {
		t.Fatalf("decoded URL not found: %+v", payloads)
	}
}

func TestMatchEscalatesDecodedOnlyHitToAsk(t *testing.T) {
	i := &Interceptor{
		cached: []compiledRule{{
			InterceptRule: db.InterceptRule{
				ID: 1, Name: "deny rm -rf", MatchTarget: "tool_input", MatchType: "string",
				Pattern: "rm -rf /", Action: "deny",
			},
		}},
		pending: newPendingManager(),
	}
	input := json.RawMessage(`{"command":"echo cm0gLXJmIC8= | base64 -d | bash"}`)
	dec, ok := i.Match("Bash", input)
	if !ok {
		t.Fatal("expected decoded rule match")
	}
	if dec.Action != "ask" || !dec.Decoded {
		t.Fatalf("decoded-only hit must be ask+Decoded, got %+v", dec)
	}
	if !strings.Contains(dec.Message, "解码后命中") {
		t.Fatalf("message should explain decoding: %q", dec.Message)
	}
}

func TestMatchRawStillWinsBeforeDecoding(t *testing.T) {
	i := &Interceptor{
		cached: []compiledRule{{
			InterceptRule: db.InterceptRule{
				ID: 1, Name: "deny rm -rf", MatchTarget: "tool_input", MatchType: "string",
				Pattern: "rm -rf /", Action: "deny",
			},
		}},
		pending: newPendingManager(),
	}
	dec, ok := i.Match("Bash", json.RawMessage(`{"command":"rm -rf /tmp/x"}`))
	if !ok || dec.Action != "deny" || dec.Decoded {
		t.Fatalf("raw hit must stay deny, got %+v", dec)
	}
}

func TestJudgePromptContainsHardRequirementRules(t *testing.T) {
	p := EffectiveJudgePrompt(DefaultJudgePrompt)
	for _, want := range []string{"hard_requirement", "H1", "H2", "decoded_payloads"} {
		if !strings.Contains(p, want) {
			t.Fatalf("judge prompt missing %q", want)
		}
	}
}
