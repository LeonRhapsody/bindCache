package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type nsAuthenticatedUser struct {
	Username string
	Role     string
}

type nsAuthContextKey struct{}

func validateNSWebAuthConfig(config WebRuntimeConfig) error {
	if !config.AuthEnabled {
		return nil
	}
	if len(config.Users) == 0 {
		return fmt.Errorf("web.auth_enabled=true 但 web.users 为空")
	}
	seen := make(map[string]struct{})
	for _, user := range config.Users {
		username := strings.TrimSpace(user.Username)
		role := strings.ToLower(strings.TrimSpace(user.Role))
		if username == "" || strings.TrimSpace(user.PasswordEnv) == "" {
			return fmt.Errorf("web.users 的 username 和 password_env 不能为空")
		}
		if role != "observer" && role != "operator" && role != "admin" {
			return fmt.Errorf("用户 %s 的 role=%q 无效", username, user.Role)
		}
		if _, exists := seen[username]; exists {
			return fmt.Errorf("web.users 用户名 %s 重复", username)
		}
		seen[username] = struct{}{}
		if os.Getenv(user.PasswordEnv) == "" {
			return fmt.Errorf("用户 %s 的密码环境变量 %s 未设置", username, user.PasswordEnv)
		}
	}
	return nil
}

func nsMonitorAuth(next http.Handler, config WebRuntimeConfig) http.Handler {
	if !config.AuthEnabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="bind-cache-analyze", charset="UTF-8"`)
			writeNSJSON(w, http.StatusUnauthorized, map[string]string{"error": "需要登录"})
			return
		}
		for _, configured := range config.Users {
			expected := os.Getenv(configured.PasswordEnv)
			if subtle.ConstantTimeCompare([]byte(username), []byte(configured.Username)) == 1 &&
				subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1 {
				user := nsAuthenticatedUser{Username: configured.Username, Role: strings.ToLower(configured.Role)}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nsAuthContextKey{}, user)))
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="bind-cache-analyze", charset="UTF-8"`)
		writeNSJSON(w, http.StatusUnauthorized, map[string]string{"error": "用户名或密码错误"})
	})
}

func requireNSWriteRole(w http.ResponseWriter, r *http.Request, required string) (nsAuthenticatedUser, bool) {
	if !GlobalConfig.Web.AuthEnabled {
		writeNSJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "写操作已禁用：请先配置 web.auth_enabled 与 web.users"})
		return nsAuthenticatedUser{}, false
	}
	if r.Header.Get("X-Requested-With") != "bind-cache-analyze" {
		writeNSJSON(w, http.StatusForbidden, map[string]string{"error": "缺少同源写请求标识"})
		return nsAuthenticatedUser{}, false
	}
	user, ok := r.Context().Value(nsAuthContextKey{}).(nsAuthenticatedUser)
	if !ok {
		writeNSJSON(w, http.StatusUnauthorized, map[string]string{"error": "未认证"})
		return nsAuthenticatedUser{}, false
	}
	rank := map[string]int{"observer": 1, "operator": 2, "admin": 3}
	if rank[user.Role] < rank[required] {
		writeNSJSON(w, http.StatusForbidden, map[string]string{"error": "当前角色无权执行该操作"})
		return nsAuthenticatedUser{}, false
	}
	return user, true
}

func v1Session(w http.ResponseWriter, r *http.Request) {
	if !requireNSMethod(w, r) {
		return
	}
	if !GlobalConfig.Web.AuthEnabled {
		writeNSJSON(w, http.StatusOK, map[string]any{
			"authenticated": false, "username": "", "role": "disabled",
			"canOperate": false, "canAdmin": false,
			"warning": "Web 认证未启用，所有写操作已禁用",
		})
		return
	}
	user, ok := r.Context().Value(nsAuthContextKey{}).(nsAuthenticatedUser)
	if !ok {
		writeNSJSON(w, http.StatusUnauthorized, map[string]string{"error": "未认证"})
		return
	}
	writeNSJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "username": user.Username, "role": user.Role,
		"canOperate": user.Role == "operator" || user.Role == "admin",
		"canAdmin":   user.Role == "admin",
	})
}
