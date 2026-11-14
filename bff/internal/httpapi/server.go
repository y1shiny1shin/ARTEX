package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/y1shiny1shin/ryagent/bff/internal/artex"
	"github.com/y1shiny1shin/ryagent/bff/internal/conductor"
	"github.com/y1shiny1shin/ryagent/bff/internal/store"
)

type Server struct {
	store         *store.Store
	artex         *artex.Client
	ds            *conductor.Client
	ownerPassword string
}

func New(st *store.Store, ac *artex.Client, ds *conductor.Client, ownerPassword string) *Server {
	return &Server{store: st, artex: ac, ds: ds, ownerPassword: ownerPassword}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /v1/auth/pair", s.pair)
	mux.HandleFunc("GET /v1/overview", s.auth(s.overview))
	mux.HandleFunc("GET /v1/tasks", s.auth(s.tasks))
	mux.HandleFunc("GET /v1/tasks/{id}/progress", s.auth(s.taskProgress))
	mux.HandleFunc("GET /v1/approvals", s.auth(s.approvals))
	mux.HandleFunc("POST /v1/approvals/{id}/decide", s.auth(s.decideApproval))
	mux.HandleFunc("POST /v1/tasks/{id}/directive", s.auth(s.taskDirective))
	mux.HandleFunc("POST /v1/tasks/{id}/control", s.auth(s.taskControl))
	mux.HandleFunc("POST /v1/tasks/{id}/intents/{iid}/steer", s.auth(s.taskSteer))
	mux.HandleFunc("POST /v1/conductor/messages", s.auth(s.conductorMessage))
	mux.HandleFunc("GET /v1/messages", s.auth(s.messages))
	mux.HandleFunc("GET /v1/confirmations", s.auth(s.listConfirmations))
	mux.HandleFunc("GET /v1/confirmations/{id}", s.auth(s.getConfirmation))
	mux.HandleFunc("POST /v1/confirmations/{id}", s.auth(s.resolveConfirmation))
	mux.HandleFunc("GET /v1/audit", s.auth(s.audit))
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const deviceKey ctxKey = 1

type deviceInfo struct{ ID, Name string }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, 401, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		d, ok := s.store.DeviceByTokenHash(store.HashToken(token))
		if !ok || d.RevokedAt != nil {
			writeErr(w, 401, "invalid or revoked device token")
			return
		}
		s.store.TouchDevice(d.ID)
		ctx := context.WithValue(r.Context(), deviceKey, deviceInfo{ID: d.ID, Name: d.Name})
		next(w, r.WithContext(ctx))
	}
}

func deviceFrom(r *http.Request) deviceInfo {
	d, _ := r.Context().Value(deviceKey).(deviceInfo)
	return d
}

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.ownerPassword) == "" {
		writeErr(w, 503, "RYAGENT_OWNER_PASSWORD 未配置")
		return
	}
	var req struct {
		Password   string `json:"password"`
		DeviceName string `json:"device_name"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.ownerPassword)) != 1 {
		writeErr(w, 403, "invalid owner password")
		return
	}
	name := strings.TrimSpace(req.DeviceName)
	if name == "" {
		name = "Android device"
	}
	deviceID := "dev_" + randomHex(6)
	token := randomToken()
	now := time.Now().UTC()
	if err := s.store.CreateDevice(store.Device{
		ID: deviceID, Name: name, TokenHash: store.HashToken(token), CreatedAt: now, LastSeen: now,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.store.AppendAudit(deviceID, "device.pair", "", "paired "+name)
	writeJSON(w, 200, map[string]any{"device_id": deviceID, "device_name": name, "token": token})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.artex.Tasks(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	redactTasks(tasks)
	approvals, err := s.artex.Approvals(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	running := 0
	for _, t := range tasks {
		if fmt.Sprint(t["status"]) == "running" && !truthy(t["paused"]) {
			running++
		}
	}
	writeJSON(w, 200, map[string]any{
		"tasks": tasks, "approvals": approvals,
		"counts": map[string]any{"tasks": len(tasks), "running": running, "approvals": len(approvals)},
	})
}

func (s *Server) tasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.artex.Tasks(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	redactTasks(tasks)
	writeJSON(w, 200, map[string]any{"tasks": tasks})
}

func (s *Server) taskProgress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, 400, "task id required")
		return
	}
	data, err := s.progressData(r.Context(), id)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, data)
}

func (s *Server) progressData(ctx context.Context, taskID string) (map[string]any, error) {
	task, err := s.artex.Task(ctx, taskID)
	if err != nil {
		return nil, err
	}
	redactTask(task)
	stats, _ := s.artex.Stats(ctx, taskID)
	// The task DTO does not always carry the live goal counters; active_task in
	// /api/stats is the authoritative runtime view. Merge it into the task card.
	if at, ok := stats["active_task"].(map[string]any); ok {
		for _, k := range []string{"status", "paused", "goals_total", "goals_met", "in_flight", "findings"} {
			if v, exists := at[k]; exists {
				task[k] = v
			}
		}
	}
	intents, _ := s.artex.Intents(ctx, taskID)
	approvals, _ := s.artex.Approvals(ctx)
	filtered := make([]map[string]any, 0)
	for _, a := range approvals {
		if fmt.Sprint(a["task_id"]) == taskID {
			if v, ok := a["reason"].(string); ok {
				a["reason"] = redactText(v)
			}
			filtered = append(filtered, a)
		}
	}
	writeIntents := make([]map[string]any, 0, len(intents))
	running := 0
	for _, in := range intents {
		state := fmt.Sprint(in["state"])
		summary := redactText(intentSummary(in))
		writeIntents = append(writeIntents, map[string]any{
			"id": in["id"], "state": state, "summary": summary,
		})
		if state == "running" {
			running++
		}
	}
	writeJSONMap := map[string]any{
		"task": task, "stats": stats, "intents": writeIntents, "approvals": filtered,
		"summary": map[string]any{
			"task_id": taskID, "status": task["status"], "paused": truthy(task["paused"]),
			"goals_total": task["goals_total"], "goals_met": task["goals_met"],
			"running_intents": running, "pending_approvals": len(filtered),
		},
	}
	return writeJSONMap, nil
}

func intentSummary(in map[string]any) string {
	// ARTEX /exploration/intents returns payload as a JSON *string*, not an
	// object. Parse it here so the app and the Conductor see a stable summary.
	switch p := in["payload"].(type) {
	case string:
		var obj map[string]any
		if json.Unmarshal([]byte(p), &obj) == nil {
			return fmt.Sprint(obj["summary"])
		}
	case map[string]any:
		return fmt.Sprint(p["summary"])
	}
	return ""
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	approvals, err := s.artex.Approvals(r.Context())
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"approvals": approvals})
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Decision string `json:"decision"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Decision != "allowed" && req.Decision != "denied" {
		writeErr(w, 400, "decision must be allowed or denied")
		return
	}
	if err := s.artex.Decide(r.Context(), id, req.Decision == "allowed"); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	d := deviceFrom(r)
	s.store.AppendAudit(d.ID, "artex.approval.decide", digest(id+req.Decision), req.Decision)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) taskDirective(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Message string `json:"message"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		writeErr(w, 400, "message is required")
		return
	}
	if len([]rune(msg)) > 4000 {
		writeErr(w, 400, "message too long")
		return
	}
	if err := s.artex.Directive(r.Context(), id, msg); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	d := deviceFrom(r)
	s.store.AppendAudit(d.ID, "artex.task.directive", digest(msg), "sent to task "+id)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) taskControl(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Action string `json:"action"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Action != "pause" && req.Action != "resume" {
		writeErr(w, 400, "action must be pause or resume")
		return
	}
	if err := s.artex.Control(r.Context(), id, req.Action); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	d := deviceFrom(r)
	s.store.AppendAudit(d.ID, "artex.task.control", digest(id+req.Action), req.Action)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) taskSteer(w http.ResponseWriter, r *http.Request) {
	id, iid := r.PathValue("id"), r.PathValue("iid")
	var req struct {
		Message string `json:"message"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		writeErr(w, 400, "message is required")
		return
	}
	if err := s.artex.Steer(r.Context(), id, iid, msg, "bff-"+randomHex(8)); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	d := deviceFrom(r)
	s.store.AppendAudit(d.ID, "artex.task.steer", digest(id+iid+msg), "steered intent "+iid)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) messages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"messages": s.store.Messages()})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"audit": s.store.Audit()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("empty body")
	}
	return json.Unmarshal(raw, v)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x != 0
	default:
		return false
	}
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func logf(format string, args ...any) { log.Printf(format, args...) }
