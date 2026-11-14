package conductor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type Tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type Client struct {
	base  string
	key   string
	model string
	http  *http.Client
}

func New(base, key, model string) *Client {
	if strings.TrimSpace(base) == "" {
		base = "https://api.deepseek.com"
	}
	return &Client{base: strings.TrimRight(base, "/"), key: strings.TrimSpace(key), model: model, http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *Client) Configured() bool { return c != nil && c.key != "" }

func (c *Client) Chat(ctx context.Context, messages []Message, tools []Tool) (Message, error) {
	endpoint := c.base
	if !strings.Contains(endpoint, "/chat/completions") {
		if strings.HasSuffix(endpoint, "/v1") {
			endpoint += "/chat/completions"
		} else {
			endpoint += "/chat/completions"
		}
	}
	payload := map[string]any{
		"model": c.model, "messages": messages, "temperature": 0.1,
		"max_tokens": 2048, "stream": false,
	}
	if len(tools) > 0 {
		payload["tools"] = tools
		payload["tool_choice"] = "auto"
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.http.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Message{}, fmt.Errorf("deepseek HTTP %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}
	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Message{}, fmt.Errorf("deepseek decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("deepseek returned no choices")
	}
	return out.Choices[0].Message, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
