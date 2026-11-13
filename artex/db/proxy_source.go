package db

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// ProxySource is an operator-configured proxy discovery source. The hunter role
// runs enabled sources to find candidates, then validates and imports them.
//
// Headers is a JSON object with source-specific credentials. For FOFA it holds
// {"email":"...","key":"..."}. Headers is never returned by the API; callers use
// HasCredentials to render "configured".
type ProxySource struct {
	ID         int64           `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"` // http_list | fofa
	URL        string          `json:"url"`
	Query      string          `json:"query"`
	Headers    json.RawMessage `json:"headers,omitempty"`
	Pages      int             `json:"pages"`
	Enabled    bool            `json:"enabled"`
	LastRunAt  *time.Time      `json:"last_run_at,omitempty"`
	LastStatus string          `json:"last_status"`
	LastError  string          `json:"last_error"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

const proxySourceCols = `id, name, kind, url, query, headers, pages, enabled, last_run_at, last_status, last_error, created_at, updated_at`

func scanProxySource(row interface{ Scan(...any) error }) (*ProxySource, error) {
	var s ProxySource
	var headers []byte
	var lastRun sql.NullTime
	if err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.URL, &s.Query, &headers, &s.Pages, &s.Enabled, &lastRun, &s.LastStatus, &s.LastError, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	if len(headers) > 0 {
		s.Headers = json.RawMessage(headers)
	}
	if lastRun.Valid {
		s.LastRunAt = &lastRun.Time
	}
	return &s, nil
}

// ListProxySources returns all configured sources, enabled first then newest.
func (d *DB) ListProxySources() ([]*ProxySource, error) {
	rows, err := d.Query(`SELECT ` + proxySourceCols + ` FROM proxy_sources ORDER BY enabled DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProxySource{}
	for rows.Next() {
		s, err := scanProxySource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetProxySource returns one source (nil, nil if absent).
func (d *DB) GetProxySource(id int64) (*ProxySource, error) {
	s, err := scanProxySource(d.QueryRow(`SELECT `+proxySourceCols+` FROM proxy_sources WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

// CreateProxySource inserts a new discovery source.
func (d *DB) CreateProxySource(name, kind, url, query string, headers json.RawMessage, pages int, enabled bool) (*ProxySource, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errText("源名称不能为空")
	}
	if kind != "http_list" && kind != "fofa" && kind != "hunter" {
		return nil, errText("源类型必须是 http_list、fofa 或 hunter")
	}
	if pages < 1 {
		pages = 1
	}
	if pages > 10 {
		pages = 10
	}
	if len(headers) == 0 {
		headers = json.RawMessage(`{}`)
	}
	s, err := scanProxySource(d.QueryRow(`
INSERT INTO proxy_sources(name, kind, url, query, headers, pages, enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+proxySourceCols,
		name, kind, strings.TrimSpace(url), strings.TrimSpace(query), headers, pages, enabled))
	return s, err
}

// UpdateProxySource updates a source. A nil headers argument keeps the stored
// credentials; a non-nil one replaces them.
func (d *DB) UpdateProxySource(id int64, name, kind, url, query string, headers json.RawMessage, pages int, enabled bool) (*ProxySource, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errText("源名称不能为空")
	}
	if kind != "http_list" && kind != "fofa" && kind != "hunter" {
		return nil, errText("源类型必须是 http_list、fofa 或 hunter")
	}
	if pages < 1 {
		pages = 1
	}
	if pages > 10 {
		pages = 10
	}
	var s *ProxySource
	var err error
	if headers == nil {
		s, err = scanProxySource(d.QueryRow(`
UPDATE proxy_sources SET name=$2, kind=$3, url=$4, query=$5, pages=$6, enabled=$7
WHERE id=$1 RETURNING `+proxySourceCols,
			id, name, kind, strings.TrimSpace(url), strings.TrimSpace(query), pages, enabled))
	} else {
		if len(headers) == 0 {
			headers = json.RawMessage(`{}`)
		}
		s, err = scanProxySource(d.QueryRow(`
UPDATE proxy_sources SET name=$2, kind=$3, url=$4, query=$5, headers=$6, pages=$7, enabled=$8
WHERE id=$1 RETURNING `+proxySourceCols,
			id, name, kind, strings.TrimSpace(url), strings.TrimSpace(query), headers, pages, enabled))
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

// DeleteProxySource removes a source.
func (d *DB) DeleteProxySource(id int64) error {
	_, err := d.Exec(`DELETE FROM proxy_sources WHERE id=$1`, id)
	return err
}

// MarkProxySourceRun records the outcome of one hunt against a source.
func (d *DB) MarkProxySourceRun(id int64, status, errMsg string) error {
	_, err := d.Exec(`UPDATE proxy_sources SET last_run_at=now(), last_status=$2, last_error=$3 WHERE id=$1`, id, status, errMsg)
	return err
}

type errText string

func (e errText) Error() string { return string(e) }
