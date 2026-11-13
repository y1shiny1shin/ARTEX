package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestNormalizeProxyLine(t *testing.T) {
	authURL := "http://" + url.UserPassword("u", "p").String() + "@1.2.3.4:8080"
	cases := []struct{ in, protocol, want string }{
		{"1.2.3.4:8080", "any", "http://1.2.3.4:8080"},
		{"1.2.3.4:1080", "socks5", "socks5://1.2.3.4:1080"},
		{"1.2.3.4:8080:u:p", "any", authURL},
		{"http://1.2.3.4:8080", "any", "http://1.2.3.4:8080"},
		{"u:p@1.2.3.4:8080", "any", authURL},
	}
	for _, c := range cases {
		if got := normalizeProxyLine(c.in, c.protocol); got != c.want {
			t.Errorf("normalizeProxyLine(%q,%q)=%q want %q", c.in, c.protocol, got, c.want)
		}
	}
}

func TestParseProxyCandidates(t *testing.T) {
	text := "# comment\n1.2.3.4:8080\n1.2.3.4:8080\n5.6.7.8:3128\nbad-line\n"
	got := parseProxyCandidates(text, "any", 10)
	if len(got) != 2 {
		t.Fatalf("got %d candidates: %+v", len(got), got)
	}
	if got[0].URL != "http://1.2.3.4:8080" || got[1].URL != "http://5.6.7.8:3128" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}

func TestParseProxyCandidatesRespectsMax(t *testing.T) {
	text := "1.1.1.1:1\n2.2.2.2:2\n3.3.3.3:3\n"
	if got := parseProxyCandidates(text, "any", 2); len(got) != 2 {
		t.Fatalf("max not respected: %+v", got)
	}
}

func TestExtractEgressIP(t *testing.T) {
	if got := extractEgressIP([]byte(`{"ip":"8.8.8.8"}`)); got != "8.8.8.8" {
		t.Fatalf("json ip = %q", got)
	}
	if got := extractEgressIP([]byte("your ip is 9.9.9.9\n")); got != "9.9.9.9" {
		t.Fatalf("plain ip = %q", got)
	}
	if got := extractEgressIP([]byte(`{"origin":"1.1.1.1, 2.2.2.2"}`)); got != "1.1.1.1" {
		t.Fatalf("origin ip = %q", got)
	}
}

func TestHostIsPrivateLiterals(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "::1", "fd00::1"} {
		if !hostIsPrivate(h) {
			t.Errorf("%s should be private", h)
		}
	}
	for _, h := range []string{"8.8.8.8", "1.1.1.1"} {
		if hostIsPrivate(h) {
			t.Errorf("%s should be public", h)
		}
	}
}

func TestDecodeJSONObject(t *testing.T) {
	var out struct {
		Compliant bool   `json:"compliant"`
		Reason    string `json:"reason"`
	}
	if err := decodeJSONObject(`{"compliant":false,"reason":"x"}`, &out); err != nil || out.Compliant || out.Reason != "x" {
		t.Fatalf("bare json: %+v %v", out, err)
	}
	out = struct {
		Compliant bool   `json:"compliant"`
		Reason    string `json:"reason"`
	}{}
	if err := decodeJSONObject("```json\n{\"compliant\":true,\"reason\":\"ok\"}\n```", &out); err != nil || !out.Compliant {
		t.Fatalf("fenced json: %+v %v", out, err)
	}
	if err := decodeJSONObject(`not json`, &out); err == nil {
		t.Fatal("expected error for non-json")
	}
}

func TestToolProxyHarvestSchemaIsValidJSON(t *testing.T) {
	s := &Server{}
	tool := s.toolProxyHarvest()
	if _, err := json.Marshal(tool.InputSchema()); err != nil {
		t.Fatalf("schema not serializable: %v", err)
	}
	if tool.Name() != "proxy_harvest" {
		t.Fatalf("tool name = %q", tool.Name())
	}
}

func TestCheckProxyHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4"}`))
	}))
	defer srv.Close()
	h, err := checkProxy(context.Background(), srv.URL, "http://example.com/ip", true)
	if err != nil {
		t.Fatalf("checkProxy: %v", err)
	}
	if h.EgressIP != "1.2.3.4" {
		t.Fatalf("egress ip = %q", h.EgressIP)
	}
	if h.LatencyMS < 0 {
		t.Fatalf("latency = %d", h.LatencyMS)
	}
}

func TestParseProxyJSONShapes(t *testing.T) {
	cases := []string{
		`["1.2.3.4:8080","5.6.7.8:3128"]`,
		`{"data":["1.2.3.4:8080","5.6.7.8:3128"]}`,
		`{"proxies":[{"proxy":"1.2.3.4:8080"},{"ip":"5.6.7.8","port":3128}]}`,
	}
	for _, in := range cases {
		got := parseProxyCandidates(in, "any", 10)
		if len(got) != 2 {
			t.Fatalf("parse %s => %+v", in, got)
		}
	}
}

func TestProxySourceDTOHidesCredentials(t *testing.T) {
	dto := proxySourceToDTO(&db.ProxySource{
		ID: 1, Name: "fofa", Kind: "fofa",
		Headers: json.RawMessage(`{"email":"test@example.com","key":"test-key"}`),
	})
	if !dto.HasCredentials {
		t.Fatal("HasCredentials should be true")
	}
	if dto.Name != "fofa" || dto.Kind != "fofa" {
		t.Fatalf("unexpected dto: %+v", dto)
	}
	// The DTO type has no Headers field by construction; this is a compile-time
	// guarantee, and the JSON path is covered by the server handler.
}

func TestFofaCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/search/all" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("email") != "test@example.com" || r.URL.Query().Get("key") != "test-key" {
			t.Fatalf("credentials not forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"results":[["1.2.3.4:1080","1.2.3.4","1080","socks5"],["5.6.7.8:8080","5.6.7.8","8080","http"]]}`))
	}))
	defer srv.Close()
	old := fofaBaseURL
	fofaBaseURL = srv.URL
	defer func() { fofaBaseURL = old }()
	src := &db.ProxySource{
		Name: "fofa", Kind: "fofa", Query: `protocol=="socks5"`, Pages: 1,
		Headers: json.RawMessage(`{"email":"test@example.com","key":"test-key"}`),
	}
	got, err := fofaCandidates(context.Background(), src, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].URL != "socks5://1.2.3.4:1080" || got[1].URL != "http://5.6.7.8:8080" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}

func TestHunterCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openApi/search" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("api-key") != "test-hunter-key" {
			t.Fatalf("api key not forwarded")
		}
		if r.URL.Query().Get("search") == "" {
			t.Fatalf("search query not forwarded")
		}
		if r.URL.Query().Get("is_web") != "0" {
			t.Fatalf("is_web must be 0 for SOCKS5 discovery, got %q", r.URL.Query().Get("is_web"))
		}
		decoded, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("search"))
		if err != nil || !strings.Contains(string(decoded), `banner="No Authentication"`) {
			t.Fatalf("default Hunter query should filter no-auth banners, got %q", string(decoded))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"message":"success","data":{"total":2,"arr":[{"ip":"1.2.3.4","port":1080,"protocol":"socks5"},{"ip":"5.6.7.8","port":8080,"protocol":"http"}]}}`))
	}))
	defer srv.Close()
	old := hunterBaseURL
	hunterBaseURL = srv.URL
	defer func() { hunterBaseURL = old }()
	src := &db.ProxySource{
		Name: "hunter", Kind: "hunter", Pages: 1,
		Headers: json.RawMessage(`{"key":"test-hunter-key"}`),
	}
	got, err := hunterCandidates(context.Background(), src, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].URL != "socks5://1.2.3.4:1080" || got[1].URL != "http://5.6.7.8:8080" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}
