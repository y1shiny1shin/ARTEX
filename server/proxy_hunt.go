package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

// proxy_hunt is the active half of the proxy hunter: it runs the operator's
// configured discovery sources (FOFA API / HTTP list), then validates and imports
// what they return. Nothing public is hard-coded: an empty source table produces
// a hint, not a fixed list of free-proxy sites.

// fofaBaseURL is a var so tests can point the connector at a local fake server.
var fofaBaseURL = "https://fofa.info"

type proxyHuntRequest struct {
	SourceIDs    []int64 `json:"source_ids,omitempty"`
	SourceURL    string  `json:"source_url,omitempty"`
	SourceText   string  `json:"source_text,omitempty"`
	CheckURL     string  `json:"check_url,omitempty"`
	Protocol     string  `json:"protocol,omitempty"`
	Max          int     `json:"max,omitempty"`
	Import       *bool   `json:"import,omitempty"`
	AllowPrivate bool    `json:"allow_private,omitempty"`
}

type proxyHuntSourceResult struct {
	ID         int64  `json:"id,omitempty"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Candidates int    `json:"candidates"`
	Error      string `json:"error,omitempty"`
}

type proxyHuntResult struct {
	Sources    []proxyHuntSourceResult `json:"sources"`
	Candidates int                     `json:"candidates"`
	Healthy    []proxyHealth           `json:"healthy"`
	Failed     int                     `json:"failed"`
	Imported   int                     `json:"imported"`
	Duplicates int                     `json:"duplicates"`
	Errors     []string                `json:"errors,omitempty"`
	Hint       string                  `json:"hint,omitempty"`
}

func (s *Server) toolProxyHunt() actool.CoreTool {
	return wrTool("proxy_hunt",
		"主动运行已配置的代理发现源（FOFA API / Hunter API / HTTP 列表），把候选代理探活、去重并导入代理池。没有配置源时返回提示——不要编造来源；可以用 web_search 找候选页面后交给 proxy_harvest。",
		objSchema(map[string]any{
			"source_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "可选：只运行这些源 id；省略=所有启用的源。"},
			"source_url":    strParam("可选：额外运行一个临时 HTTP 列表 URL（操作员明确给出时）。"),
			"source_text":   strParam("可选：额外解析一段临时代理列表文本。"),
			"check_url":     strParam("可选：探活用的中立 IP 回显地址，默认 http://ip-api.com/json（HTTP，对免费代理更友好）。"),
			"protocol":      map[string]any{"type": "string", "enum": []string{"http", "socks5", "any"}, "description": "无 scheme 的 host:port 按此协议补全；默认 any（http）。"},
			"max":           map[string]any{"type": "integer", "description": "最多验证多少个候选，默认 200，上限 500。"},
			"import":        map[string]any{"type": "boolean", "description": "是否把健康代理导入代理池，默认 true。"},
			"allow_private": map[string]any{"type": "boolean", "description": "允许源/检查地址指向内网；默认 false。"},
		}),
		s.runProxyHuntTool,
	)
}

func (s *Server) runProxyHuntTool(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var req proxyHuntRequest
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
	callCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	res, err := s.proxyHunt(callCtx, req)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return jsonResult(res)
}

func (s *Server) proxyHunt(ctx context.Context, req proxyHuntRequest) (proxyHuntResult, error) {
	res := proxyHuntResult{Sources: []proxyHuntSourceResult{}, Healthy: []proxyHealth{}}
	if s.m.pg == nil {
		return res, fmt.Errorf("数据库未就绪")
	}

	var sources []*db.ProxySource
	if len(req.SourceIDs) == 0 {
		all, err := s.m.pg.ListProxySources()
		if err != nil {
			return res, err
		}
		for _, src := range all {
			if src.Enabled {
				sources = append(sources, src)
			}
		}
	} else {
		for _, id := range req.SourceIDs {
			src, err := s.m.pg.GetProxySource(id)
			if err != nil {
				return res, err
			}
			if src != nil {
				sources = append(sources, src)
			}
		}
	}

	var candidates []proxyCandidate
	seen := map[string]bool{}
	addCandidates := func(cands []proxyCandidate) {
		for _, c := range cands {
			key := strings.ToLower(c.URL)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, c)
		}
	}

	for _, src := range sources {
		cands, err := s.sourceCandidates(ctx, src, req)
		status := "ok"
		errMsg := ""
		if err != nil {
			status, errMsg = "error", err.Error()
		} else if len(cands) == 0 {
			status = "empty"
			errMsg = "查询返回 0 条：检查查询语句、Key 权限/额度；Hunter 查 SOCKS5 时已默认 is_web=0"
		}
		_ = s.m.pg.MarkProxySourceRun(src.ID, status, errMsg)
		res.Sources = append(res.Sources, proxyHuntSourceResult{
			ID: src.ID, Name: src.Name, Kind: src.Kind, Candidates: len(cands), Error: errMsg,
		})
		addCandidates(cands)
	}

	if strings.TrimSpace(req.SourceText) != "" {
		cands := parseProxyCandidates(req.SourceText, req.Protocol, req.Max)
		res.Sources = append(res.Sources, proxyHuntSourceResult{Name: "ad-hoc text", Kind: "text", Candidates: len(cands)})
		addCandidates(cands)
	}
	if strings.TrimSpace(req.SourceURL) != "" {
		text, err := fetchProxySource(ctx, req.SourceURL, req.AllowPrivate)
		if err != nil {
			res.Sources = append(res.Sources, proxyHuntSourceResult{Name: "ad-hoc url", Kind: "url", Error: err.Error()})
		} else {
			cands := parseProxyCandidates(text, req.Protocol, req.Max)
			res.Sources = append(res.Sources, proxyHuntSourceResult{Name: "ad-hoc url", Kind: "url", Candidates: len(cands)})
			addCandidates(cands)
		}
	}

	if len(sources) == 0 && strings.TrimSpace(req.SourceURL) == "" && strings.TrimSpace(req.SourceText) == "" {
		res.Hint = "没有配置代理发现源。请在系统设置里配置 FOFA API 或 HTTP 列表源；也可以先 web_search 找候选代理列表/API 页面，再把 URL 交给 proxy_harvest。"
		return res, nil
	}
	if len(candidates) > req.Max {
		candidates = candidates[:req.Max]
	}
	res.Candidates = len(candidates)
	if len(candidates) == 0 {
		res.Hint = "来源没有解析出有效候选；检查源 URL、FOFA/Hunter 查询与凭据，以及源页数。"
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
		res.Hint = "没有健康代理。免费代理存活率很低，可增大 max/页数、换 check_url 或稍后重试；不要把免费代理用于登录/爆破/敏感会话。"
	} else {
		res.Hint = "免费代理只适合只读侦察；登录、爆破、带 Cookie 的会话请使用付费住宅代理或自建出口。"
	}
	return res, nil
}

func (s *Server) sourceCandidates(ctx context.Context, src *db.ProxySource, req proxyHuntRequest) ([]proxyCandidate, error) {
	switch src.Kind {
	case "http_list":
		if strings.TrimSpace(src.URL) == "" {
			return nil, fmt.Errorf("HTTP 列表源缺少 URL")
		}
		text, err := fetchProxySource(ctx, src.URL, req.AllowPrivate)
		if err != nil {
			return nil, err
		}
		return parseProxyCandidates(text, req.Protocol, req.Max), nil
	case "fofa":
		return fofaCandidates(ctx, src, req.Max)
	case "hunter":
		return hunterCandidates(ctx, src, req.Max)
	default:
		return nil, fmt.Errorf("未知源类型 %q", src.Kind)
	}
}

// fofaCandidates mirrors the TunnelProxy idea: query FOFA for exposed SOCKS/HTTP
// proxy services, then hand the ip:port rows to the same validator. Credentials
// and the query are stored on the source, never hard-coded.
func fofaCandidates(ctx context.Context, src *db.ProxySource, max int) ([]proxyCandidate, error) {
	var creds struct {
		Email string `json:"email"`
		Key   string `json:"key"`
	}
	if len(src.Headers) > 0 {
		if err := json.Unmarshal(src.Headers, &creds); err != nil {
			return nil, fmt.Errorf("FOFA 凭据格式无效")
		}
	}
	creds.Email, creds.Key = strings.TrimSpace(creds.Email), strings.TrimSpace(creds.Key)
	if creds.Email == "" || creds.Key == "" {
		return nil, fmt.Errorf("FOFA 源未配置 email/key")
	}
	query := strings.TrimSpace(src.Query)
	if query == "" {
		query = `protocol=="socks5" && "Version:5 Method:No Authentication(0x00)"`
	}
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
	pages := src.Pages
	if pages < 1 {
		pages = 1
	}
	if pages > 10 {
		pages = 10
	}
	client := &http.Client{Timeout: 30 * time.Second}
	out := []proxyCandidate{}
	seen := map[string]bool{}
	for page := 1; page <= pages && len(out) < max; page++ {
		apiURL := fmt.Sprintf("%s/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=100&page=%d&fields=host,ip,port,protocol",
			fofaBaseURL,
			url.QueryEscape(creds.Email), url.QueryEscape(creds.Key), url.QueryEscape(qbase64), page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("User-Agent", "RyAgent-proxy-hunter/1.0")
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return out, fmt.Errorf("FOFA HTTP %d: %s", resp.StatusCode, maskSecretProxy(string(body)))
		}
		var parsed struct {
			Error   bool            `json:"error"`
			ErrMsg  string          `json:"errmsg"`
			Results json.RawMessage `json:"results"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return out, fmt.Errorf("FOFA 返回非 JSON: %w", err)
		}
		if parsed.Error {
			return out, fmt.Errorf("FOFA: %s", parsed.ErrMsg)
		}
		var rows []any
		_ = json.Unmarshal(parsed.Results, &rows)
		for _, row := range rows {
			host, ip, port, proto := "", "", "", ""
			switch v := row.(type) {
			case []any:
				if len(v) > 0 {
					host = strings.TrimSpace(fmt.Sprint(v[0]))
				}
				if len(v) > 1 {
					ip = strings.TrimSpace(fmt.Sprint(v[1]))
				}
				if len(v) > 2 {
					port = strings.TrimSpace(fmt.Sprint(v[2]))
				}
				if len(v) > 3 {
					proto = strings.TrimSpace(fmt.Sprint(v[3]))
				}
			case map[string]any:
				host = strings.TrimSpace(fmt.Sprint(v["host"]))
				ip = strings.TrimSpace(fmt.Sprint(v["ip"]))
				port = strings.TrimSpace(fmt.Sprint(v["port"]))
				proto = strings.TrimSpace(fmt.Sprint(v["protocol"]))
			}
			raw := ""
			if strings.Contains(host, "://") {
				raw = host
			} else if host != "" && strings.Contains(host, ":") {
				raw = host
			} else if ip != "" && port != "" && port != "<nil>" {
				raw = net.JoinHostPort(ip, port)
			}
			if raw == "" {
				continue
			}
			scheme := strings.ToLower(proto)
			switch scheme {
			case "http", "https", "socks5", "socks5h":
			default:
				scheme = "socks5"
			}
			if !strings.Contains(raw, "://") {
				raw = scheme + "://" + raw
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
		if page < pages {
			time.Sleep(1 * time.Second)
		}
	}
	return out, nil
}

// hunterBaseURL is a var so tests can point the connector at a local fake server.
var hunterBaseURL = "https://hunter.qianxin.com"

// hunterCandidates queries the Qianxin Hunter open API for exposed proxy
// services. Hunter uses an api-key (no email) and a base64 query; the operator
// configures both on the proxy source, never in a global settings screen.
func hunterCandidates(ctx context.Context, src *db.ProxySource, max int) ([]proxyCandidate, error) {
	var creds struct {
		Key    string `json:"key"`
		APIKey string `json:"api_key"`
	}
	if len(src.Headers) > 0 {
		if err := json.Unmarshal(src.Headers, &creds); err != nil {
			return nil, fmt.Errorf("Hunter 凭据格式无效")
		}
	}
	key := strings.TrimSpace(creds.Key)
	if key == "" {
		key = strings.TrimSpace(creds.APIKey)
	}
	if key == "" {
		return nil, fmt.Errorf("Hunter 源未配置 API Key")
	}
	query := strings.TrimSpace(src.Query)
	if query == "" {
		// "No Authentication" is the banner filter that makes Hunter useful for
		// proxy discovery: protocol alone returns millions of mostly-dead assets.
		query = `protocol="socks5" && banner="No Authentication"`
	}
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
	pages := src.Pages
	if pages < 1 {
		pages = 1
	}
	if pages > 10 {
		pages = 10
	}
	client := &http.Client{Timeout: 30 * time.Second}
	out := []proxyCandidate{}
	seen := map[string]bool{}
	for page := 1; page <= pages && len(out) < max; page++ {
		apiURL := fmt.Sprintf("%s/openApi/search?api-key=%s&search=%s&page=%d&page_size=100&is_web=0",
			hunterBaseURL, url.QueryEscape(key), url.QueryEscape(qbase64), page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("User-Agent", "RyAgent-proxy-hunter/1.0")
		var parsed struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Arr  []map[string]any `json:"arr"`
				List []map[string]any `json:"list"`
			} `json:"data"`
		}
		var lastErr error
		for attempt := 0; attempt < 3; attempt++ {
			attemptReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
			if err != nil {
				return out, err
			}
			attemptReq.Header.Set("User-Agent", "RyAgent-proxy-hunter/1.0")
			resp, err := client.Do(attemptReq)
			if err != nil {
				lastErr = err
				break
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			_ = resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				lastErr = fmt.Errorf("Hunter HTTP %d: %s", resp.StatusCode, maskSecretProxy(string(body)))
				break
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				lastErr = fmt.Errorf("Hunter 返回非 JSON: %w", err)
				break
			}
			if parsed.Code == 429 {
				lastErr = fmt.Errorf("Hunter 限流: %s", parsed.Message)
				if attempt < 2 {
					time.Sleep(5 * time.Second)
					continue
				}
				break
			}
			if parsed.Code != 200 {
				lastErr = fmt.Errorf("Hunter: %s", parsed.Message)
			}
			break
		}
		if lastErr != nil {
			return out, lastErr
		}
		rows := parsed.Data.Arr
		if len(rows) == 0 {
			rows = parsed.Data.List
		}
		for _, row := range rows {
			ip := strings.TrimSpace(fmt.Sprint(row["ip"]))
			port := strings.TrimSpace(fmt.Sprint(row["port"]))
			proto := strings.TrimSpace(fmt.Sprint(row["protocol"]))
			if ip == "" || port == "" || port == "<nil>" {
				continue
			}
			scheme := strings.ToLower(proto)
			switch scheme {
			case "http", "https", "socks5", "socks5h":
			default:
				scheme = "socks5"
			}
			u, err := traffic.ValidateProxyURL(scheme + "://" + net.JoinHostPort(ip, port))
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
		if page < pages {
			time.Sleep(1 * time.Second)
		}
	}
	return out, nil
}
