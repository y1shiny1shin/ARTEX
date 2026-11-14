package artex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is a thin adapter over the ARTEX HTTP API. The BFF never reads the
// ARTEX database directly: keeping the integration at the API boundary is what
// lets ARTEX evolve without changing the app or the Conductor contract.
type Client struct {
	base     string
	username string
	password string

	mu    sync.Mutex
	token string
	http  *http.Client
}

func New(base, token, username, password string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"), token: strings.TrimSpace(token),
		username: username, password: password,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) BaseURL() string { return c.base }

func (c *Client) Login(ctx context.Context) error {
	if c.username == "" {
		return fmt.Errorf("ARTEX_USERNAME 未配置")
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/auth/login", map[string]string{
		"username": c.username, "password": c.password,
	}, &out, true); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("ARTEX login returned an empty token")
	}
	c.mu.Lock()
	c.token = out.Token
	c.mu.Unlock()
	return nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	t := c.token
	c.mu.Unlock()
	if t != "" {
		return nil
	}
	return c.Login(ctx)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, skipAuth bool) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if !skipAuth {
			c.mu.Lock()
			t := c.token
			c.mu.Unlock()
			if t == "" {
				if err := c.Login(ctx); err != nil {
					return err
				}
				c.mu.Lock()
				t = c.token
				c.mu.Unlock()
			}
			req.Header.Set("Authorization", "Bearer "+t)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && !skipAuth && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			if err := c.Login(ctx); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("artex %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(string(raw), 500))
		}
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("artex %s %s: decode: %w", method, path, err)
			}
		}
		return nil
	}
	return fmt.Errorf("artex %s %s: auth retry exhausted", method, path)
}

func (c *Client) Health(ctx context.Context) error {
	var out map[string]any
	return c.do(ctx, http.MethodGet, "/api/health", nil, &out, true)
}

func (c *Client) Tasks(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/tasks", nil, &out, false); err != nil {
		return nil, err
	}
	if out.Tasks == nil {
		out.Tasks = []map[string]any{}
	}
	return out.Tasks, nil
}

func (c *Client) Task(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/api/tasks/"+url.PathEscape(id), nil, &out, false); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Stats(ctx context.Context, taskID string) (map[string]any, error) {
	var out map[string]any
	q := url.Values{}
	q.Set("task", taskID)
	if err := c.do(ctx, http.MethodGet, "/api/stats?"+q.Encode(), nil, &out, false); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Intents(ctx context.Context, taskID string) ([]map[string]any, error) {
	var out []map[string]any
	q := url.Values{}
	q.Set("task", taskID)
	if err := c.do(ctx, http.MethodGet, "/api/exploration/intents?"+q.Encode(), nil, &out, false); err != nil {
		return nil, err
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (c *Client) Approvals(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Pending []map[string]any `json:"pending"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/intercept/pending", nil, &out, false); err != nil {
		return nil, err
	}
	if out.Pending == nil {
		out.Pending = []map[string]any{}
	}
	return out.Pending, nil
}

func (c *Client) Decide(ctx context.Context, approvalID string, allow bool) error {
	decision := "denied"
	if allow {
		decision = "allowed"
	}
	return c.do(ctx, http.MethodPost, "/api/intercept/pending/"+url.PathEscape(approvalID)+"/decide",
		map[string]string{"decision": decision}, nil, false)
}

func (c *Client) Directive(ctx context.Context, taskID, message string) error {
	q := url.Values{}
	q.Set("task", taskID)
	return c.do(ctx, http.MethodPost, "/api/chat?"+q.Encode(), map[string]string{"message": message}, nil, false)
}

func (c *Client) Control(ctx context.Context, taskID, action string) error {
	return c.do(ctx, http.MethodPost, "/api/tasks/"+url.PathEscape(taskID)+"/control",
		map[string]string{"action": action}, nil, false)
}

func (c *Client) Steer(ctx context.Context, taskID, intentID, message, requestID string) error {
	return c.do(ctx, http.MethodPost,
		"/api/tasks/"+url.PathEscape(taskID)+"/intents/"+url.PathEscape(intentID)+"/messages",
		map[string]string{"message": message, "request_id": requestID}, nil, false)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
