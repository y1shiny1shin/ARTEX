package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxTaskNameRunes           = 200
	maxTaskMetadataRequestSize = 16 << 10
)

// updateTaskMetadata updates editable metadata and the live asset-sharing policy.
func (s *Server) updateTaskMetadata(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskMetadataRequestSize)
	var request struct {
		Name              *string `json:"name"`
		Remark            *string `json:"remark"`
		Pinned            *bool   `json:"pinned"`
		ShareGlobalAssets *bool   `json:"share_global_assets"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	if request.Name == nil && request.Pinned == nil && request.Remark == nil && request.ShareGlobalAssets == nil {
		writeErr(w, http.StatusBadRequest, "至少需要提供 name、pinned、remark 或 share_global_assets")
		return
	}
	if request.Name != nil {
		name := strings.TrimSpace(*request.Name)
		if name == "" {
			writeErr(w, http.StatusBadRequest, "任务名称不能为空")
			return
		}
		if utf8.RuneCountInString(name) > maxTaskNameRunes {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("任务名称最多 %d 个字符", maxTaskNameRunes))
			return
		}
		request.Name = &name
	}

	if request.Remark != nil {
		remark, err := normalizeRemark(*request.Remark)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		request.Remark = &remark
	}
	task, err := s.m.UpdateTaskMetadata(taskID, db.TaskPatch{Name: request.Name, Pinned: request.Pinned, Remark: request.Remark, ShareGlobalAssets: request.ShareGlobalAssets})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if task == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(task, s.resolvedTaskStatus(task)))
}

// updateTaskHardRequirement is the ONLY endpoint that changes a task's hard
// requirement. It is intentionally not exposed as an agent tool, so the model
// cannot rewrite the requirement mid-conversation. Every change is audited in
// task_hard_requirement_audit by db.SetTaskHardRequirement.
func (s *Server) updateTaskHardRequirement(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	task, ok := s.m.Task(taskID)
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskMetadataRequestSize)
	var request struct {
		Text     string `json:"text"`
		Password string `json:"password"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	// Re-auth with the operator password. The agent has no password, so even if it
	// obtains a JWT it cannot rewrite the requirement through this endpoint.
	hash, ok, err := s.m.pg.GetSetting(authPassKey)
	if err != nil || !ok || hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(request.Password)) != nil {
		writeErr(w, http.StatusForbidden, "修改硬性要求需要管理员密码")
		return
	}
	id, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad task id")
		return
	}
	updated, err := s.m.PG().SetTaskHardRequirement(id, request.Text, "human")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Keep the live handle in sync for prompts/DTO. The DB read path is still the
	// source of truth; this only avoids a stale UI until the next reload.
	task.HardRequirement = updated.HardRequirement
	writeJSON(w, http.StatusOK, taskDTO(task, s.resolvedTaskStatus(task)))
}
