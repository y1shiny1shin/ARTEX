package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Proxy source management API. Credentials live in proxy_sources.headers and are
// never returned; the UI only sees has_credentials. The agent uses source ids,
// so it never needs to read the secret back.

type proxySourceDTO struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	URL            string     `json:"url"`
	Query          string     `json:"query"`
	Pages          int        `json:"pages"`
	Enabled        bool       `json:"enabled"`
	HasCredentials bool       `json:"has_credentials"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	LastStatus     string     `json:"last_status"`
	LastError      string     `json:"last_error"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func proxySourceToDTO(s *db.ProxySource) proxySourceDTO {
	has := false
	var headers map[string]any
	if len(s.Headers) > 0 && json.Unmarshal(s.Headers, &headers) == nil {
		for _, v := range headers {
			if strings.TrimSpace(toString(v)) != "" {
				has = true
				break
			}
		}
	}
	return proxySourceDTO{
		ID: s.ID, Name: s.Name, Kind: s.Kind, URL: s.URL, Query: s.Query,
		Pages: s.Pages, Enabled: s.Enabled, HasCredentials: has,
		LastRunAt: s.LastRunAt, LastStatus: s.LastStatus, LastError: s.LastError,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (s *Server) listProxySources(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, "数据库未就绪")
		return
	}
	rows, err := s.m.pg.ListProxySources()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]proxySourceDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, proxySourceToDTO(row))
	}
	writeJSON(w, 200, map[string]any{"sources": out})
}

type proxySourceReq struct {
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	URL     string          `json:"url"`
	Query   string          `json:"query"`
	Email   string          `json:"email"`
	Key     string          `json:"key"`
	Headers json.RawMessage `json:"headers"`
	Pages   int             `json:"pages"`
	Enabled *bool           `json:"enabled"`
}

func buildProxySourceHeaders(req proxySourceReq) json.RawMessage {
	if len(req.Headers) > 0 && string(req.Headers) != "null" {
		return req.Headers
	}
	if strings.TrimSpace(req.Email) != "" || strings.TrimSpace(req.Key) != "" {
		b, _ := json.Marshal(map[string]string{"email": strings.TrimSpace(req.Email), "key": strings.TrimSpace(req.Key)})
		return b
	}
	return nil
}

func (s *Server) createProxySource(w http.ResponseWriter, r *http.Request) {
	var req proxySourceReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	src, err := s.m.pg.CreateProxySource(req.Name, req.Kind, req.URL, req.Query, buildProxySourceHeaders(req), req.Pages, enabled)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, proxySourceToDTO(src))
}

func (s *Server) updateProxySource(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "源 id 无效")
		return
	}
	var req proxySourceReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	src, err := s.m.pg.UpdateProxySource(id, req.Name, req.Kind, req.URL, req.Query, buildProxySourceHeaders(req), req.Pages, enabled)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if src == nil {
		writeErr(w, 404, "源不存在")
		return
	}
	writeJSON(w, 200, proxySourceToDTO(src))
}

func (s *Server) deleteProxySource(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "源 id 无效")
		return
	}
	if err := s.m.pg.DeleteProxySource(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}
