package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/y1shiny1shin/ryagent/bff/internal/store"
)

func (s *Server) listConfirmations(w http.ResponseWriter, r *http.Request) {
	all := s.store.ListConfirmations()
	now := time.Now().UTC()
	out := make([]store.Confirmation, 0, len(all))
	for _, c := range all {
		if c.State == "pending" && now.Before(c.ExpiresAt) {
			out = append(out, c)
		}
	}
	writeJSON(w, 200, map[string]any{"confirmations": out})
}

func (s *Server) getConfirmation(w http.ResponseWriter, r *http.Request) {
	c, ok := s.store.GetConfirmation(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "confirmation not found")
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) resolveConfirmation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := s.store.GetConfirmation(id)
	if !ok {
		writeErr(w, 404, "confirmation not found")
		return
	}
	if c.State != "pending" {
		writeErr(w, 409, "confirmation already resolved: "+c.State)
		return
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		_ = s.store.ResolveConfirmation(id, "expired", "expired before decision")
		writeErr(w, 409, "confirmation expired")
		return
	}
	var req struct {
		Approve bool `json:"approve"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	d := deviceFrom(r)
	if !req.Approve {
		_ = s.store.ResolveConfirmation(id, "rejected", "rejected by device")
		s.store.AppendAudit(d.ID, "confirmation.reject", digest(c.Capability+c.Input), c.Summary)
		writeJSON(w, 200, map[string]any{"ok": true, "state": "rejected"})
		return
	}
	if err := s.executeConfirmed(r.Context(), c); err != nil {
		_ = s.store.ResolveConfirmation(id, "failed", err.Error())
		s.store.AppendAudit(d.ID, "confirmation.failed", digest(c.Capability+c.Input), err.Error())
		writeErr(w, 502, err.Error())
		return
	}
	_ = s.store.ResolveConfirmation(id, "done", "executed")
	s.store.AppendAudit(d.ID, "confirmation.approve", digest(c.Capability+c.Input), c.Summary)
	writeJSON(w, 200, map[string]any{"ok": true, "state": "done"})
}

func (s *Server) executeConfirmed(ctx context.Context, c store.Confirmation) error {
	var input map[string]any
	if err := json.Unmarshal([]byte(c.Input), &input); err != nil {
		return fmt.Errorf("invalid confirmation input: %w", err)
	}
	switch c.Capability {
	case "artex_approval_decide":
		approvalID := argString(input, "approval_id")
		decision := argString(input, "decision")
		if approvalID == "" || (decision != "allowed" && decision != "denied") {
			return fmt.Errorf("invalid approval decision input")
		}
		return s.artex.Decide(ctx, approvalID, decision == "allowed")
	case "artex_task_directive":
		taskID, message := argString(input, "task_id"), argString(input, "message")
		if taskID == "" || message == "" {
			return fmt.Errorf("invalid directive input")
		}
		return s.artex.Directive(ctx, taskID, message)
	case "artex_task_control":
		taskID, action := argString(input, "task_id"), argString(input, "action")
		if taskID == "" || (action != "pause" && action != "resume") {
			return fmt.Errorf("invalid task control input")
		}
		return s.artex.Control(ctx, taskID, action)
	case "artex_task_steer":
		taskID, intentID := argString(input, "task_id"), argString(input, "intent_id")
		message := argString(input, "message")
		if taskID == "" || intentID == "" || message == "" {
			return fmt.Errorf("invalid steer input")
		}
		return s.artex.Steer(ctx, taskID, intentID, message, "bff-"+randomHex(8))
	default:
		return fmt.Errorf("unknown capability %q", c.Capability)
	}
}
