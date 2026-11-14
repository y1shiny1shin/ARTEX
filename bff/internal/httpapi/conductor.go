package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/y1shiny1shin/ryagent/bff/internal/conductor"
	"github.com/y1shiny1shin/ryagent/bff/internal/store"
)

const conductorSystemPrompt = `你是 RyAgent 主控台（个人单用户，中文）。你可以查询 ARTEX 的任务、进度、审批，并在用户确认后下发指令、暂停/恢复任务、审批。

规则：
1. 先查数据再回答；不要编造任务、审批或进度。
2. 写操作只能通过工具提议。工具返回 confirmation_required 时，明确告诉用户“已准备，等待确认”，不要声称已经执行。
3. 用户说“如果……就……”时，先查当前状态，再决定是否提议写操作；不确定就追问。
4. 审批/指令/暂停的确认由 App 完成，你只负责提议和解释。
5. 输出简洁中文；不要输出完整脚本或命令原文，只给摘要。`

func (s *Server) conductorTools() []conductor.Tool {
	tool := func(name, desc string, props map[string]any, required ...string) conductor.Tool {
		t := conductor.Tool{Type: "function"}
		t.Function.Name = name
		t.Function.Description = desc
		t.Function.Parameters = map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			t.Function.Parameters["required"] = required
		}
		return t
	}
	return []conductor.Tool{
		tool("artex_task_list", "列出 ARTEX 任务及状态。", map[string]any{}),
		tool("artex_task_progress", "读取一个任务的进度：状态、目标、当前意图、待审批、统计。", map[string]any{
			"task_id": map[string]any{"type": "string", "description": "ARTEX 任务 id"},
		}, "task_id"),
		tool("artex_approval_list", "列出 ARTEX 待审批记录。", map[string]any{}),
		tool("artex_approval_decide", "提议批准或拒绝一条 ARTEX 审批；需要用户确认后才会执行。", map[string]any{
			"approval_id": map[string]any{"type": "string"},
			"decision":    map[string]any{"type": "string", "enum": []string{"allowed", "denied"}},
		}, "approval_id", "decision"),
		tool("artex_task_directive", "提议向 ARTEX 任务主 Agent 发送 OPERATOR DIRECTIVE；需要用户确认。", map[string]any{
			"task_id": map[string]any{"type": "string"},
			"message": map[string]any{"type": "string", "description": "给任务主 Agent 的指令，简洁明确"},
		}, "task_id", "message"),
		tool("artex_task_control", "提议暂停或恢复一个 ARTEX 任务；需要用户确认。", map[string]any{
			"task_id": map[string]any{"type": "string"},
			"action":  map[string]any{"type": "string", "enum": []string{"pause", "resume"}},
		}, "task_id", "action"),
		tool("artex_task_steer", "提议给某个正在运行的意图发送纠偏消息；需要用户确认。", map[string]any{
			"task_id":   map[string]any{"type": "string"},
			"intent_id": map[string]any{"type": "string"},
			"message":   map[string]any{"type": "string"},
		}, "task_id", "intent_id", "message"),
	}
}

func (s *Server) conductorMessage(w http.ResponseWriter, r *http.Request) {
	if !s.ds.Configured() {
		writeErr(w, 503, "DEEPSEEK_API_KEY 未配置；请使用直接按钮或配置模型")
		return
	}
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
	reply, confirmations, err := s.runConductor(r.Context(), deviceFrom(r), msg)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reply": reply, "confirmations": confirmations})
}

func (s *Server) runConductor(ctx context.Context, device deviceInfo, userMsg string) (string, []store.Confirmation, error) {
	history := s.store.Messages()
	start := 0
	if len(history) > 20 {
		start = len(history) - 20
	}
	messages := []conductor.Message{{Role: "system", Content: conductorSystemPrompt}}
	for _, m := range history[start:] {
		if m.Role == "user" || m.Role == "assistant" {
			messages = append(messages, conductor.Message{Role: m.Role, Content: m.Content})
		}
	}
	messages = append(messages, conductor.Message{Role: "user", Content: userMsg})
	s.store.AppendMessage("user", userMsg)

	tools := s.conductorTools()
	confirmations := []store.Confirmation{}
	for round := 0; round < 4; round++ {
		resp, err := s.ds.Chat(ctx, messages, tools)
		if err != nil {
			return "", nil, err
		}
		messages = append(messages, resp)
		if len(resp.ToolCalls) == 0 {
			reply := strings.TrimSpace(resp.Content)
			if reply == "" {
				reply = "（模型没有返回内容）"
			}
			s.store.AppendMessage("assistant", reply)
			return reply, confirmations, nil
		}
		for _, call := range resp.ToolCalls {
			result, conf, err := s.executeTool(ctx, device, call)
			content := string(result)
			if err != nil {
				content = `{"error":` + jsonString(err.Error()) + `}`
			}
			messages = append(messages, conductor.Message{Role: "tool", ToolCallID: call.ID, Content: content})
			if conf != nil {
				confirmations = append(confirmations, *conf)
			}
		}
	}
	reply := "已执行查询，但模型未在限定轮次内收束。请查看工具结果或继续追问。"
	s.store.AppendMessage("assistant", reply)
	return reply, confirmations, nil
}

func (s *Server) executeTool(ctx context.Context, device deviceInfo, call conductor.ToolCall) (json.RawMessage, *store.Confirmation, error) {
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
		return nil, nil, fmt.Errorf("invalid tool arguments: %w", err)
	}
	switch call.Function.Name {
	case "artex_task_list":
		data, err := s.artex.Tasks(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonBytes(map[string]any{"tasks": data}), nil, nil
	case "artex_task_progress":
		taskID := argString(args, "task_id")
		if taskID == "" {
			return nil, nil, fmt.Errorf("task_id is required")
		}
		data, err := s.progressData(ctx, taskID)
		if err != nil {
			return nil, nil, err
		}
		return jsonBytes(data), nil, nil
	case "artex_approval_list":
		data, err := s.artex.Approvals(ctx)
		if err != nil {
			return nil, nil, err
		}
		return jsonBytes(map[string]any{"approvals": data}), nil, nil
	case "artex_approval_decide":
		input := map[string]any{
			"approval_id": argString(args, "approval_id"),
			"decision":    argString(args, "decision"),
		}
		if input["approval_id"] == "" || (input["decision"] != "allowed" && input["decision"] != "denied") {
			return nil, nil, fmt.Errorf("approval_id and decision (allowed|denied) are required")
		}
		summary := fmt.Sprintf("审批 #%v：%v", input["approval_id"], input["decision"])
		conf, err := s.createConfirmation(device, call.Function.Name, input, summary)
		if err != nil {
			return nil, nil, err
		}
		return confirmationJSON(conf), &conf, nil
	case "artex_task_directive":
		input := map[string]any{
			"task_id": argString(args, "task_id"),
			"message": argString(args, "message"),
		}
		if input["task_id"] == "" || input["message"] == "" {
			return nil, nil, fmt.Errorf("task_id and message are required")
		}
		conf, err := s.createConfirmation(device, call.Function.Name, input,
			fmt.Sprintf("向 task %v 发送指令：%v", input["task_id"], input["message"]))
		if err != nil {
			return nil, nil, err
		}
		return confirmationJSON(conf), &conf, nil
	case "artex_task_control":
		input := map[string]any{
			"task_id": argString(args, "task_id"),
			"action":  argString(args, "action"),
		}
		if input["task_id"] == "" || (input["action"] != "pause" && input["action"] != "resume") {
			return nil, nil, fmt.Errorf("task_id and action (pause|resume) are required")
		}
		conf, err := s.createConfirmation(device, call.Function.Name, input,
			fmt.Sprintf("%v task %v", input["action"], input["task_id"]))
		if err != nil {
			return nil, nil, err
		}
		return confirmationJSON(conf), &conf, nil
	case "artex_task_steer":
		input := map[string]any{
			"task_id":   argString(args, "task_id"),
			"intent_id": argString(args, "intent_id"),
			"message":   argString(args, "message"),
		}
		if input["task_id"] == "" || input["intent_id"] == "" || input["message"] == "" {
			return nil, nil, fmt.Errorf("task_id, intent_id and message are required")
		}
		conf, err := s.createConfirmation(device, call.Function.Name, input,
			fmt.Sprintf("向 task %v 的意图 #%v 发送纠偏：%v", input["task_id"], input["intent_id"], input["message"]))
		if err != nil {
			return nil, nil, err
		}
		return confirmationJSON(conf), &conf, nil
	default:
		return nil, nil, fmt.Errorf("unknown tool %q", call.Function.Name)
	}
}

func (s *Server) createConfirmation(device deviceInfo, capability string, input map[string]any, summary string) (store.Confirmation, error) {
	raw, _ := json.Marshal(input)
	now := time.Now().UTC()
	c := store.Confirmation{
		ID: "cfm_" + randomHex(8), DeviceID: device.ID, Capability: capability,
		Input: string(raw), Summary: summary, State: "pending",
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	if err := s.store.CreateConfirmation(c); err != nil {
		return store.Confirmation{}, err
	}
	return c, nil
}

func confirmationJSON(c store.Confirmation) json.RawMessage {
	return jsonBytes(map[string]any{
		"status": "confirmation_required", "confirmation_id": c.ID,
		"summary": c.Summary, "expires_at": c.ExpiresAt,
	})
}

func argString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func jsonBytes(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
