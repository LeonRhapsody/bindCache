package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type nsEventAction struct {
	EventID   string     `json:"eventId"`
	Action    string     `json:"action"`
	Reason    string     `json:"reason"`
	Actor     string     `json:"actor"`
	ActorRole string     `json:"actorRole"`
	ActedAt   time.Time  `json:"actedAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type nsEventActionRequest struct {
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expiresAt"`
}

type nsWhitelistScope struct {
	RiskType string
	Domain   string
	Expires  time.Time
}

func (s *nsMonitorServer) v1EventAction(w http.ResponseWriter, r *http.Request, eventID string) {
	writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "内存调试模式不支持处置写操作"})
}

func (s *nsPersistentMonitorServer) v1EventAction(w http.ResponseWriter, r *http.Request, eventID string) {
	if r.Method != http.MethodPost {
		writeNSJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	user, ok := requireNSWriteRole(w, r, "operator")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	defer r.Body.Close()
	var request nsEventActionRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "无效请求: " + err.Error()})
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Action != "confirm" && request.Action != "ignore" && request.Action != "whitelist" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "action 仅支持 confirm、ignore、whitelist"})
		return
	}
	if (request.Action == "ignore" || request.Action == "whitelist") && request.Reason == "" {
		writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "忽略或加入白名单必须填写理由"})
		return
	}
	var expiresAt *time.Time
	if request.Action == "whitelist" {
		if request.ExpiresAt == "" {
			writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "白名单必须设置 expiresAt"})
			return
		}
		value, err := time.Parse(time.RFC3339, request.ExpiresAt)
		if err != nil || !value.After(time.Now()) {
			writeNSJSON(w, http.StatusBadRequest, map[string]string{"error": "expiresAt 必须是未来的 RFC3339 时间"})
			return
		}
		value = value.UTC()
		expiresAt = &value
	}
	ctx, cancel := context.WithTimeout(r.Context(), nsWebQueryTimeout)
	defer cancel()
	if _, err := s.store.eventByID(ctx, eventID); errors.Is(err, errNSPersistentNotFound) {
		if _, auxErr := s.store.auxEventByID(ctx, eventID); errors.Is(auxErr, errNSPersistentNotFound) {
			writeNSJSON(w, http.StatusNotFound, map[string]string{"error": "事件不存在"})
			return
		} else if auxErr != nil {
			nsPersistentError(w, auxErr)
			return
		}
	} else if err != nil {
		nsPersistentError(w, err)
		return
	}
	action := nsEventAction{
		EventID: eventID, Action: request.Action, Reason: request.Reason,
		Actor: user.Username, ActorRole: user.Role, ActedAt: time.Now().UTC(), ExpiresAt: expiresAt,
	}
	var expires any
	if expiresAt != nil {
		expires = *expiresAt
	}
	details, _ := json.Marshal(map[string]string{"remote_addr": r.RemoteAddr, "user_agent": r.UserAgent()})
	if _, err := s.store.db.ExecContext(ctx, `INSERT INTO ns_event_actions
		(event_id, action, reason, actor, actor_role, acted_at, expires_at, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		action.EventID, action.Action, action.Reason, action.Actor, action.ActorRole, action.ActedAt, expires, string(details)); err != nil {
		nsPersistentError(w, err)
		return
	}
	writeNSJSON(w, http.StatusCreated, action)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("请求只能包含一个 JSON 对象")
	}
	return nil
}

func (s *nsPersistentStore) latestEventActions(ctx context.Context) (map[string]nsEventAction, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,
		argMax(action, acted_at), argMax(reason, acted_at), argMax(actor, acted_at),
		argMax(actor_role, acted_at), max(acted_at), argMax(expires_at, acted_at)
		FROM ns_event_actions
		GROUP BY event_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]nsEventAction)
	for rows.Next() {
		var action nsEventAction
		var expires sql.NullTime
		if err := rows.Scan(&action.EventID, &action.Action, &action.Reason, &action.Actor, &action.ActorRole, &action.ActedAt, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			value := expires.Time
			action.ExpiresAt = &value
		}
		if action.Action == "whitelist" && action.ExpiresAt != nil && !time.Now().UTC().Before(*action.ExpiresAt) {
			continue
		}
		result[action.EventID] = action
	}
	return result, rows.Err()
}

func (s *nsPersistentStore) latestEventAction(ctx context.Context, eventID string) (*nsEventAction, error) {
	var action nsEventAction
	var expires sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT event_id, action, reason, actor, actor_role, acted_at, expires_at
		FROM ns_event_actions WHERE event_id = ? ORDER BY acted_at DESC LIMIT 1`, eventID).Scan(
		&action.EventID, &action.Action, &action.Reason, &action.Actor, &action.ActorRole, &action.ActedAt, &expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		value := expires.Time
		action.ExpiresAt = &value
	}
	if action.Action == "whitelist" && action.ExpiresAt != nil && !time.Now().UTC().Before(*action.ExpiresAt) {
		return nil, nil
	}
	return &action, nil
}

func applyV1EventAction(item *nsV1RiskEvent, action *nsEventAction) {
	if item == nil || action == nil {
		return
	}
	if item.Extra == nil {
		item.Extra = make(map[string]any)
	}
	item.Extra["action"] = action
	switch action.Action {
	case "confirm":
		item.Status = "confirmed"
	case "ignore", "whitelist":
		item.Status = "ignored"
		item.Extra["whitelisted"] = action.Action == "whitelist"
		item.Extra["whitelistReason"] = action.Reason
	}
}

func loadActiveNSWhitelistScopes(ctx context.Context, db *sql.DB) (map[string]nsWhitelistScope, error) {
	rows, err := db.QueryContext(ctx, `SELECT e.risk_type, e.domain, a.expires_at
		FROM (
			SELECT event_id, argMax(action, acted_at) AS action, argMax(expires_at, acted_at) AS expires_at
			FROM ns_event_actions GROUP BY event_id
		) AS a
		INNER JOIN (
			SELECT event_id, 'ns_change' AS risk_type, domain FROM ns_change_events FINAL
			UNION ALL
			SELECT event_id, risk_type, domain FROM ns_risk_events FINAL
		) AS e ON a.event_id = e.event_id
		WHERE a.action = 'whitelist' AND a.expires_at IS NOT NULL AND a.expires_at > now64(3)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]nsWhitelistScope)
	for rows.Next() {
		var scope nsWhitelistScope
		if err := rows.Scan(&scope.RiskType, &scope.Domain, &scope.Expires); err != nil {
			return nil, err
		}
		scope.Domain = normalizeFQDN(scope.Domain)
		result[scope.RiskType+"\x00"+scope.Domain] = scope
	}
	return result, rows.Err()
}

func filterWhitelistedNSChangeEvents(events []NSChangeEvent, scopes map[string]nsWhitelistScope) []NSChangeEvent {
	if len(scopes) == 0 {
		return events
	}
	result := make([]NSChangeEvent, 0, len(events))
	for _, event := range events {
		if _, suppressed := scopes["ns_change\x00"+normalizeFQDN(event.Domain)]; !suppressed {
			result = append(result, event)
		}
	}
	return result
}
