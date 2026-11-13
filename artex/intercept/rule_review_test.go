package intercept

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewMatchedAskLetsJudgeClearFalsePositive(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	i.SetReviewer(func(_ context.Context, _ int64, _ string, in ReviewInput) (Decision, error) {
		if in.Rule == nil {
			t.Fatal("rule_hit missing from review input")
		}
		if in.Rule.Name != "pipe" || in.Rule.Action != "ask" {
			t.Fatalf("unexpected rule_hit: %+v", in.Rule)
		}
		return Decision{Action: "allow", Message: "[模型] 实际操作：只读管道格式化；成功后的后果：仅显示 JSON；命中规则：A5", ModelFallback: true}, nil
	})
	dec, ok := i.ReviewMatchedAsk(context.Background(), "Bash",
		json.RawMessage(`{"command":"curl -s http://example.com/api | python3 -m json.tool | head -60"}`),
		Decision{Action: "ask", RuleID: 42, RuleName: "pipe", Message: "管道进入解释器"})
	if !ok {
		t.Fatal("expected judge review")
	}
	if dec.Action != "allow" || dec.RuleID != 42 || dec.RuleName != "pipe" {
		t.Fatalf("unexpected decision: %+v", dec)
	}
	if !strings.HasPrefix(dec.Message, "[模型]") || !strings.Contains(dec.Message, "pipe") {
		t.Fatalf("message should show model review + rule name: %q", dec.Message)
	}
}

func TestReviewMatchedAskKeepsRuleAskWhenJudgeDisabled(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	if _, err := i.db.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`, settingJudgeEnabled, "false"); err != nil {
		t.Fatal(err)
	}
	i.SetReviewer(func(context.Context, int64, string, ReviewInput) (Decision, error) {
		t.Fatal("reviewer must not be called when disabled")
		return Decision{}, nil
	})
	if _, ok := i.ReviewMatchedAsk(context.Background(), "Bash", json.RawMessage(`{"command":"x | python3 -m json.tool"}`),
		Decision{Action: "ask", RuleID: 1, RuleName: "pipe"}); ok {
		t.Fatal("disabled judge must leave the rule ask in place")
	}
}

func TestReviewMatchedAskDoesNotReviewDenyRules(t *testing.T) {
	i := retryTestInterceptor(t, nil)
	i.SetReviewer(func(context.Context, int64, string, ReviewInput) (Decision, error) {
		t.Fatal("deny rules are final; reviewer must not be called")
		return Decision{}, nil
	})
	if _, ok := i.ReviewMatchedAsk(context.Background(), "Bash", json.RawMessage(`{}`),
		Decision{Action: "deny", RuleID: 1, RuleName: "rm -rf"}); ok {
		t.Fatal("deny rule must not be reviewed")
	}
}
