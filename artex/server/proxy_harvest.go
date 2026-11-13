package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/proxy"
)

// Proxy hunting is deterministic and operator-driven on purpose:
//   - the LLM role decides WHEN to harvest and reports the result;
//   - this file decides HOW to parse, validate, deduplicate and import;
//   - no public free-proxy source is built in. A source must be supplied by the
//     operator (URL or text) for every run.
//
// The validation request goes to a neutral IP-echo endpoint, never to a target,
// so probing a proxy pool does not touch customer assets.

const (
	proxyHarvestDefaultMax       = 200
	proxyHarvestHardMax          = 500
	proxyHarvestConcurrency      = 20
	proxyHarvestPerProxyTimeout  = 10 * time.Second
	proxyHarvestSourceLimitBytes = 1 << 20
	proxyHarvestCheckURL         = "http://ip-api.com/json"
)

type proxyHarvestRequest struct {
	SourceURL    string `json:"source_url,omitempty"`
	SourceText   string `json:"source_text,omitempty"`
	CheckURL     string `json:"check_url,omitempty"`
	Protocol     string `json:"protocol,omitempty"` // http|socks5|any
	Max          int    `json:"max,omitempty"`
	Import       *bool  `json:"import,omitempty"` // default true
	AllowPrivate bool   `json:"allow_private,omitempty"`
}

type proxyHealth struct {
	URL       string `json:"url"`
	EgressIP  string `json:"egress_ip,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
}

type proxyHarvestResult struct {
	SourceURL    string        `json:"source_url,omitempty"`
	CheckURL     string        `json:"check_url"`
	Candidates   int           `json:"candidates"`
	Healthy      []proxyHealth `json:"healthy"`
	Failed       int           `json:"failed"`
	Imported     int           `json:"imported"`
	Duplicates   int           `json:"duplicates"`
	Errors       []string      `json:"errors,omitempty"`
	ImportedHint string        `json:"hint,omitempty"`
}

type proxyCandidate struct {
	URL string
}

// toolProxyHarvest is a host tool available only to the proxy_hunter agent (the
// tools-table binding decides that). It is a write tool because it can import
// entries into the pool, but it never touches a target.
func (s *Server) toolProxyHarvest() actool.CoreTool {
	return wrTool("proxy_harvest",
		"抓取/探活/导入代理池。只在操作员明确提供 source_url 或 source_text 时使用；不内置任何公开免费代理源。探活只打中立的 IP 回显地址，不打客户目标。",
		objSchema(map[string]any{
			"source_url":    strParam("可选：操作员提供的代理列表 URL（http/https），返回一行一个代理或 host:port 文本。"),
			"source_text":   strParam("可选：操作员直接给出的代理列表文本，一行一个。"),
			"check_url":     strParam("可选：探活用的中立 IP 回显地址，默认 http://ip-api.com/json（HTTP，对免费代理更友好）。"),
			"protocol":      map[string]any{"type": "string", "enum": []string{"http", "socks5", "any"}, "description": "无 scheme 的 host:port 按此协议补全；默认 any（http）。"},
			"max":           map[string]any{"type": "integer", "description": "最多验证多少个候选，默认 200，上限 500。"},
			"import":        map[string]any{"type": "boolean", "description": "是否把健康代理导入代理池，默认 true。"},
			"allow_private": map[string]any{"type": "boolean", "description": "允许 source_url/check_url 指向内网或回环地址；默认 false，防止把该工具当 SSRF 用。"},
		}),
		s.runProxyHarvestTool,
	)
}

func (s *Server) runProxyHarvestTool(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var req proxyHarvestRequest
	if err := json.Unmarshal(in, &req); err != nil {
		return actool.Errorf("参数无效: " + err.Error()), nil
	}
	if req.Max <= 0 {
		req.Max = proxyHarvestDefaultMax
	}
	if req.Max > proxyHarvestHardMax {
		req.Max = proxyHarvestHardMax
	}
	if strings.TrimSpace(req.CheckURL) == "" {
		req.CheckURL = proxyHarvestCheckURL
	}
	if req.Protocol == "" {
		req.Protocol = "any"
	}
	callCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	res, err := s.proxyHarvest(callCtx, req)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return jsonResult(res)
}

func (s *Server) proxyHarvest(ctx context.Context, req proxyHarvestRequest) (proxyHarvestResult, error) {
	res := proxyHarvestResult{SourceURL: req.SourceURL, CheckURL: req.CheckURL, Healthy: []proxyHealth{}}
	var text strings.Builder
	if strings.TrimSpace(req.SourceText) != "" {
		text.WriteString(req.SourceText)
		text.WriteString("\n")
	}
	if strings.TrimSpace(req.SourceURL) != "" {
		fetched, err := fetchProxySource(ctx, req.SourceURL, req.AllowPrivate)
		if err != nil {
			return res, fmt.Errorf("抓取 source_url 失败: %w", err)
		}
		text.WriteString(fetched)
	}
	if strings.TrimSpace(text.String()) == "" {
		return res, fmt.Errorf("没有代理来源：请提供 source_url 或 source_text；本系统不内置公开免费代理列表")
	}

	candidates := parseProxyCandidates(text.String(), req.Protocol, req.Max)
	res.Candidates = len(candidates)
	if len(candidates) == 0 {
		res.ImportedHint = "来源文本里没有解析出有效的 host:port 或 scheme://host:port"
		return res, nil
	}

	res.Healthy, res.Failed, res.Errors = validateProxyCandidates(ctx, candidates, req.CheckURL, req.AllowPrivate)

	if req.Import == nil || *req.Import {
		added, dups, err := s.importHarvestedProxies(res.Healthy)
		if err != nil {
			return res, fmt.Errorf("导入代理池失败: %w", err)
		}
		res.Imported, res.Duplicates = added, dups
	}
	for i := range res.Healthy {
		res.Healthy[i].URL = maskSecretProxy(res.Healthy[i].URL)
	}
	if len(res.Healthy) == 0 {
		res.ImportedHint = "没有健康代理。免费代理存活率很低，可增大 max、换 check_url 或稍后重试；不要把免费代理用于登录/爆破/敏感会话。"
	} else {
		res.ImportedHint = "免费代理只适合只读侦察；登录、爆破、带 Cookie 的会话请使用付费住宅代理或自建出口。"
	}
	return res, nil
}

// validateProxyCandidates runs the bounded concurrent reachability check shared
// by proxy_harvest (ad-hoc list) and proxy_hunt (configured discovery sources).
func validateProxyCandidates(ctx context.Context, candidates []proxyCandidate, checkURL string, allowPrivate bool) ([]proxyHealth, int, []string) {
	type outcome struct {
		health proxyHealth
		err    error
		url    string
	}
	sem := make(chan struct{}, proxyHarvestConcurrency)
	results := make(chan outcome, len(candidates))
	var wg sync.WaitGroup
	for _, c := range candidates {
		wg.Add(1)
		go func(c proxyCandidate) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- outcome{url: c.URL, err: ctx.Err()}
				return
			}
			h, err := checkProxy(ctx, c.URL, checkURL, allowPrivate)
			results <- outcome{health: h, err: err, url: c.URL}
		}(c)
	}
	wg.Wait()
	close(results)

	healthy := []proxyHealth{}
	failed := 0
	errs := []string{}
	for o := range results {
		if o.err != nil {
			failed++
			if len(errs) < 20 {
				errs = append(errs, maskSecretProxy(o.url)+": "+maskSecretProxy(o.err.Error()))
			}
			continue
		}
		healthy = append(healthy, o.health)
	}
	return healthy, failed, errs
}

// fetchProxySource fetches an operator-supplied list. It is deliberately not
// routed through the global proxy: the source is not a target and we do not want
// a broken pool to prevent pool repair.
func fetchProxySource(ctx context.Context, raw string, allowPrivate bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("URL 无效")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("只支持 http/https")
	}
	if !allowPrivate && hostIsPrivate(u.Hostname()) {
		return "", fmt.Errorf("source_url 指向内网/回环地址，拒绝（如确有需要，显式 allow_private=true）")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, proxyHarvestSourceLimitBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseProxyCandidates accepts the common free-list shapes:
//
//	scheme://host:port, host:port, host:port:user:pass, user:pass@host:port
//
// It intentionally does not guess credentials from arbitrary columns; malformed
// rows are dropped rather than turned into a proxy that silently fails.
func parseProxyCandidates(text, protocol string, max int) []proxyCandidate {
	if out := parseProxyJSON(text, protocol, max); len(out) > 0 {
		return out
	}
	return parseProxyLines(text, protocol, max)
}

// parseProxyJSON accepts the common API shapes: []string, {data:[...]},
// {proxies:[...]}, and objects with proxy/address/ip+port. It extracts candidate
// strings and feeds them through the same validation as line-based lists.
func parseProxyJSON(text, protocol string, max int) []proxyCandidate {
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		return nil
	}
	var lines []string
	collectProxyLines(v, &lines, 0)
	if len(lines) == 0 {
		return nil
	}
	return parseProxyLines(strings.Join(lines, "\n"), protocol, max)
}

func collectProxyLines(v any, out *[]string, depth int) {
	if depth > 6 || len(*out) > 2000 {
		return
	}
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s != "" && strings.Contains(s, ":") && len(s) < 240 {
			*out = append(*out, s)
		}
	case []any:
		for _, e := range x {
			collectProxyLines(e, out, depth+1)
		}
	case map[string]any:
		for _, key := range []string{"proxy", "address", "server"} {
			if s, ok := x[key].(string); ok && strings.TrimSpace(s) != "" {
				*out = append(*out, s)
				return
			}
		}
		ip, _ := x["ip"].(string)
		port := strings.TrimSpace(fmt.Sprint(x["port"]))
		if ip != "" && port != "" && port != "<nil>" {
			*out = append(*out, net.JoinHostPort(ip, port))
			return
		}
		for _, e := range x {
			collectProxyLines(e, out, depth+1)
		}
	}
}

func parseProxyLines(text, protocol string, max int) []proxyCandidate {
	lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' })
	out := make([]proxyCandidate, 0, min(len(lines), max))
	seen := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(strings.Trim(line, `"'`))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		raw := normalizeProxyLine(line, protocol)
		if raw == "" {
			continue
		}
		u, err := traffic.ValidateProxyURL(raw)
		if err != nil {
			continue
		}
		key := strings.ToLower(u.Scheme + "://" + u.Host)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, proxyCandidate{URL: u.String()})
		if len(out) >= max {
			break
		}
	}
	return out
}

func normalizeProxyLine(line, protocol string) string {
	line = strings.TrimSpace(line)
	if strings.Contains(line, "://") {
		return line
	}
	if strings.Contains(line, "@") {
		return "http://" + line
	}
	parts := strings.Split(line, ":")
	switch len(parts) {
	case 2:
		scheme := "http"
		if protocol == "socks5" {
			scheme = "socks5"
		}
		return scheme + "://" + line
	case 4:
		// host:port:user:pass — the most common CSV-ish free-list shape.
		return "http://" + url.UserPassword(parts[2], parts[3]).String() + "@" + net.JoinHostPort(parts[0], parts[1])
	default:
		return ""
	}
}

func checkProxy(ctx context.Context, raw, checkURL string, allowPrivate bool) (proxyHealth, error) {
	h := proxyHealth{URL: raw}
	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		return h, err
	}
	if !allowPrivate && hostIsPrivate(u.Hostname()) {
		return h, fmt.Errorf("内网/回环代理地址被拒绝")
	}
	cu, err := url.Parse(checkURL)
	if err != nil || cu.Host == "" || (cu.Scheme != "http" && cu.Scheme != "https") {
		return h, fmt.Errorf("check_url 无效")
	}
	if !allowPrivate && hostIsPrivate(cu.Hostname()) {
		return h, fmt.Errorf("check_url 指向内网/回环地址")
	}

	tr := &http.Transport{
		// Validation must work through proxies with self-signed/MITM certs; we are
		// checking reachability and egress IP, not trusting the proxy's certificate.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	switch u.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pass}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return h, err
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			type dialResult struct {
				c   net.Conn
				err error
			}
			ch := make(chan dialResult, 1)
			go func() {
				c, err := d.Dial(network, addr)
				ch <- dialResult{c: c, err: err}
			}()
			select {
			case r := <-ch:
				return r.c, r.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	default:
		return h, fmt.Errorf("不支持的代理协议 %s", u.Scheme)
	}

	client := &http.Client{Transport: tr, Timeout: proxyHarvestPerProxyTimeout}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cu.String(), nil)
	if err != nil {
		return h, err
	}
	req.Header.Set("User-Agent", "curl/8.5.0")
	resp, err := client.Do(req)
	if err != nil {
		return h, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return h, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	h.LatencyMS = time.Since(start).Milliseconds()
	h.EgressIP = extractEgressIP(body)
	return h, nil
}

var reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func extractEgressIP(body []byte) string {
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		for _, k := range []string{"ip", "origin", "query", "address"} {
			if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(strings.Split(v, ",")[0])
			}
		}
	}
	return reIPv4.FindString(string(body))
}

func (s *Server) importHarvestedProxies(healthy []proxyHealth) (added, duplicates int, err error) {
	entries := s.m.proxyPoolEntries()
	seen := map[string]bool{}
	for _, e := range entries {
		seen[proxyURLKeyRaw(e.RawURL)] = true
	}
	now := time.Now().UTC()
	for i, h := range healthy {
		u, err := traffic.ValidateProxyURL(h.URL)
		if err != nil {
			continue
		}
		key := proxyURLKeyRaw(u.String())
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		entries = append(entries, proxyPoolEntry{
			ProxyPoolEntry: ProxyPoolEntry{
				ID:            fmt.Sprintf("proxy-harvest-%d-%d", now.UnixNano(), i+1),
				URL:           h.URL,
				Name:          "proxy_hunter",
				Enabled:       true,
				EgressIP:      h.EgressIP,
				LatencyMS:     h.LatencyMS,
				LastCheckedAt: now,
				Health:        "healthy",
			},
			RawURL: u.String(),
		})
		added++
	}
	if added == 0 {
		return 0, duplicates, nil
	}
	active := s.m.proxyPoolActiveID()
	if active != "" {
		found := false
		for _, e := range entries {
			if e.ID == active {
				found = true
				break
			}
		}
		if !found {
			active = ""
		}
	}
	if err := s.m.setProxyPoolEntries(entries, active); err != nil {
		return 0, duplicates, err
	}
	return added, duplicates, nil
}

// hostIsPrivate resolves a hostname to IPs and reports whether any address is
// loopback/private/link-local. Used to keep proxy_harvest from becoming an SSRF
// primitive; operators can opt out with allow_private=true.
func hostIsPrivate(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false // let the HTTP client report the real resolution error
	}
	for _, a := range ips {
		if a.IP.IsLoopback() || a.IP.IsPrivate() || a.IP.IsLinkLocalUnicast() || a.IP.IsUnspecified() || a.IP.IsMulticast() {
			return true
		}
	}
	return false
}

var reProxyUserInfo = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s]+@`)

func maskSecretProxy(s string) string {
	// Proxy URLs and transport errors can contain user:pass. Redact the password
	// before the string reaches a chat transcript or an approval record.
	s = reProxyUserInfo.ReplaceAllString(s, "${1}***@")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// seedProxyHunter creates the operator-facing role once. It deliberately does
// NOT install a scheduled crawler: the role only acts when the operator supplies
// a source. This matches the product constraint "no built-in public proxy lists".
func (s *Server) seedProxyHunter() {
	const flag = "proxy_hunter_seed_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()

	harvest := s.toolProxyHarvest()
	schema, _ := json.Marshal(harvest.InputSchema())
	if err := s.m.pg.SeedTool(harvest.Name(), harvest.Description(), schema, json.RawMessage(`["proxy_hunter"]`)); err != nil {
		return
	}
	hunt := s.toolProxyHunt()
	huntSchema, _ := json.Marshal(hunt.InputSchema())
	if err := s.m.pg.SeedTool(hunt.Name(), hunt.Description(), huntSchema, json.RawMessage(`["proxy_hunter"]`)); err != nil {
		return
	}
	a, err := s.m.pg.GetAgentByKey("proxy_hunter")
	if err != nil {
		return
	}
	if a == nil {
		a, err = s.m.pg.CreateAgent("proxy_hunter", "代理猎手",
			"代理池维护角色：只在操作员显式给出代理来源时抓取、探活、去重并导入代理池；不内置公开免费代理源。")
		if err != nil {
			return
		}
		if err := s.m.pg.SeedPromptIfEmpty(a.ID, agent.ProxyHunterDefaultPrompt); err != nil {
			return
		}
		_ = s.m.pg.SetAgentMaxTurns("proxy_hunter", 8)
	}
	_ = s.m.pg.AddAgentToToolBinding("proxy_hunter", []string{"proxy_harvest", "proxy_hunt"})
	// Let the hunter discover candidate source pages itself when no configured
	// source is available. The global web-search switch still gates actual use.
	_ = s.m.pg.SetAgentWebSearch("proxy_hunter", true)
	// Make the harvest tool visible to the LLM judge on existing DBs whose
	// intercept_enabled_tools setting was already saved.
	if tools, err := s.m.interceptor.GetEnabledTools(); err == nil {
		found := false
		for _, t := range tools {
			if t == "proxy_harvest" {
				found = true
				break
			}
		}
		if !found {
			_ = s.m.interceptor.SetEnabledTools(append(tools, "proxy_harvest"))
		}
	}
}

// seedProxyHunterV2 upgrades an already-seeded proxy_hunter to the active hunter:
// it adds the proxy_hunt tool, binds it, enables web_search, and (only when the
// stored prompt is still the old passive default) replaces the prompt with the
// discovery-first version. A user-edited prompt is left untouched.
func (s *Server) seedProxyHunterV2() {
	const flag = "proxy_hunter_hunt_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	hunt := s.toolProxyHunt()
	schema, _ := json.Marshal(hunt.InputSchema())
	if err := s.m.pg.SeedTool(hunt.Name(), hunt.Description(), schema, json.RawMessage(`["proxy_hunter"]`)); err != nil {
		return
	}
	_ = s.m.pg.AddAgentToToolBinding("proxy_hunter", []string{"proxy_harvest", "proxy_hunt"})
	_ = s.m.pg.SetAgentWebSearch("proxy_hunter", true)
	if a, err := s.m.pg.GetAgentByKey("proxy_hunter"); err == nil && a != nil {
		if cur, err := s.m.pg.CurrentPrompt(a.ID); err == nil {
			// Only replace our old passive prompt; never clobber an operator edit.
			if strings.Contains(cur, "当操作员明确给出代理来源") || strings.Contains(cur, "你的唯一职责是：当操作员") {
				_, _ = s.m.pg.SavePrompt(a.ID, agent.ProxyHunterDefaultPrompt, "代理猎手 v2：主动发现源 + 探活 + 入池", "system")
			}
		}
	}
	if tools, err := s.m.interceptor.GetEnabledTools(); err == nil {
		found := map[string]bool{}
		for _, t := range tools {
			found[t] = true
		}
		changed := false
		for _, t := range []string{"proxy_harvest", "proxy_hunt"} {
			if !found[t] {
				tools = append(tools, t)
				changed = true
			}
		}
		if changed {
			_ = s.m.interceptor.SetEnabledTools(tools)
		}
	}
}

// seedProxyHunterV3 upgrades the stored v2 prompt to the version that mentions
// Hunter as a discovery source. Only the exact v2 wording is replaced, so an
// operator-edited prompt is left untouched.
func (s *Server) seedProxyHunterV3() {
	const flag = "proxy_hunter_hunt_v3"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	a, err := s.m.pg.GetAgentByKey("proxy_hunter")
	if err != nil || a == nil {
		return
	}
	cur, err := s.m.pg.CurrentPrompt(a.ID)
	if err == nil && strings.Contains(cur, "FOFA API 或 HTTP 列表") {
		_, _ = s.m.pg.SavePrompt(a.ID, agent.ProxyHunterDefaultPrompt, "代理猎手 v3：加入 Hunter 源", "system")
	}
}

// seedProxyHunterV4 refreshes the proxy tool descriptions/schemas and the stored
// hunter prompt after the default check URL changed to a proxy-friendly HTTP
// endpoint. RefreshToolDefaults preserves each tool's agent binding/enabled flag.
func (s *Server) seedProxyHunterV4() {
	const flag = "proxy_hunter_hunt_v4"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	for _, tool := range []actool.CoreTool{s.toolProxyHarvest(), s.toolProxyHunt()} {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := s.m.pg.RefreshToolDefaults(tool.Name(), tool.Description(), schema); err != nil {
			return
		}
	}
	if a, err := s.m.pg.GetAgentByKey("proxy_hunter"); err == nil && a != nil {
		cur, err := s.m.pg.CurrentPrompt(a.ID)
		if err == nil && strings.Contains(cur, "如果代理池已有健康成员") && !strings.Contains(cur, "默认探活地址是") {
			_, _ = s.m.pg.SavePrompt(a.ID, agent.ProxyHunterDefaultPrompt, "代理猎手 v4：默认探活改为 HTTP", "system")
		}
	}
}
