package httpapi

import (
	"regexp"
	"strings"
)

// Task descriptions and intent summaries are free text; operators sometimes
// paste credentials into them. The BFF is the last place before the data reaches
// the phone or the Conductor, so redact obvious secrets without altering the
// rest of the text. This is best-effort defense in depth, not a vault.
var (
	reLongHex = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)
	reAPIKey  = regexp.MustCompile(`(?i)\b(sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|access[_-]?key|secret|token|password)\s*[:=]\s*[^\s,;"'）)]+)`)
	reBearer  = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`)
)

func redactText(s string) string {
	if s == "" {
		return s
	}
	s = reLongHex.ReplaceAllString(s, "[redacted]")
	s = reAPIKey.ReplaceAllStringFunc(s, func(m string) string {
		if i := strings.IndexAny(m, "=:"); i >= 0 {
			return m[:i+1] + "[redacted]"
		}
		return "[redacted]"
	})
	s = reBearer.ReplaceAllString(s, "Bearer [redacted]")
	return s
}

func redactTask(t map[string]any) {
	if t == nil {
		return
	}
	for _, k := range []string{"name", "description", "goal", "remark", "hard_requirement"} {
		if v, ok := t[k].(string); ok {
			t[k] = redactText(v)
		}
	}
}

func redactTasks(tasks []map[string]any) []map[string]any {
	for _, t := range tasks {
		redactTask(t)
	}
	return tasks
}
