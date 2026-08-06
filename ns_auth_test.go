package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestNSMonitorAuthRequiresConfiguredBasicCredentials(t *testing.T) {
	t.Setenv("TEST_NS_WEB_PASSWORD", "strong-test-password")
	config := WebRuntimeConfig{
		AuthEnabled: true,
		Users:       []WebUserConfig{{Username: "dnsops", PasswordEnv: "TEST_NS_WEB_PASSWORD", Role: "operator"}},
	}
	if err := validateNSWebAuthConfig(config); err != nil {
		t.Fatal(err)
	}
	handler := nsMonitorAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(nsAuthContextKey{}).(nsAuthenticatedUser)
		if !ok || user.Username != "dnsops" || user.Role != "operator" {
			t.Fatalf("unexpected user %#v", user)
		}
		w.WriteHeader(http.StatusNoContent)
	}), config)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized response = %d %#v", unauthorized.Code, unauthorized.Header())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	request.SetBasicAuth("dnsops", "strong-test-password")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", authorized.Code)
	}
}

func TestWriteAppConfigAtomicallyRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	config := DefaultAppConfig()
	config.DumpMonitor.Directory = "/data/test-dumps"
	if err := writeAppConfigAtomically(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAppConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DumpMonitor.Directory != "/data/test-dumps" {
		t.Fatalf("directory = %q", loaded.DumpMonitor.Directory)
	}
}

func TestV1SessionReflectsReadOnlyAndOperatorCapabilities(t *testing.T) {
	original := GlobalConfig
	t.Cleanup(func() { GlobalConfig = original })

	GlobalConfig.Web.AuthEnabled = false
	recorder := httptest.NewRecorder()
	v1Session(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	var disabled map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || disabled["canOperate"] != false || disabled["canAdmin"] != false {
		t.Fatalf("disabled session = %#v", disabled)
	}

	GlobalConfig.Web.AuthEnabled = true
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request = request.WithContext(context.WithValue(request.Context(), nsAuthContextKey{}, nsAuthenticatedUser{Username: "dnsops", Role: "operator"}))
	recorder = httptest.NewRecorder()
	v1Session(recorder, request)
	var operator map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &operator); err != nil {
		t.Fatal(err)
	}
	if operator["canOperate"] != true || operator["canAdmin"] != false {
		t.Fatalf("operator session = %#v", operator)
	}
}
