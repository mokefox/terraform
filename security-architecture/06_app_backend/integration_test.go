package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFullSecurityPipelineIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/api/csrf-token", handleCSRFToken)
	mux.HandleFunc("/api/data", handleSecureAPI)

	rl := NewRateLimiter(50.0, 100)
	handler := SecurityMiddleware(mux, rl)
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	// 1. ヘルスチェック & セキュリティヘッダー検証
	respHealth, err := client.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("Healthcheck request failed: %v", err)
	}
	defer respHealth.Body.Close()

	if respHealth.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for healthcheck, got %d", respHealth.StatusCode)
	}

	headers := respHealth.Header
	if !strings.EqualFold(headers.Get("X-Frame-Options"), "DENY") {
		t.Errorf("Missing or invalid X-Frame-Options: %s", headers.Get("X-Frame-Options"))
	}
	if !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") {
		t.Errorf("Missing or invalid X-Content-Type-Options: %s", headers.Get("X-Content-Type-Options"))
	}
	if !strings.Contains(headers.Get("Strict-Transport-Security"), "max-age=") {
		t.Errorf("Missing or invalid HSTS header: %s", headers.Get("Strict-Transport-Security"))
	}

	// 2. CSRF トークン取得
	respToken, err := client.Get(server.URL + "/api/csrf-token")
	if err != nil {
		t.Fatalf("CSRF token request failed: %v", err)
	}
	defer respToken.Body.Close()

	var tokenBody map[string]string
	if err := json.NewDecoder(respToken.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("Failed to decode token body: %v", err)
	}
	csrfToken := tokenBody["csrf_token"]
	if csrfToken == "" {
		t.Fatalf("Received empty CSRF token")
	}

	// 3. CSRF トークンなしでの POST (403 Forbidden になるべき)
	reqNoToken, _ := http.NewRequest(http.MethodPost, server.URL+"/api/data", strings.NewReader(`{"input":"unauthorized"}`))
	reqNoToken.Header.Set("Content-Type", "application/json")
	respNoToken, err := client.Do(reqNoToken)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer respNoToken.Body.Close()

	if respNoToken.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden without CSRF token, got %d", respNoToken.StatusCode)
	}

	// 4. 不正なトークンでの POST (403 Forbidden になるべき)
	reqFakeToken, _ := http.NewRequest(http.MethodPost, server.URL+"/api/data", strings.NewReader(`{"input":"tampered"}`))
	reqFakeToken.Header.Set("Content-Type", "application/json")
	reqFakeToken.Header.Set("X-CSRF-Token", "fake-tampered-token-12345")
	respFakeToken, err := client.Do(reqFakeToken)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer respFakeToken.Body.Close()

	if respFakeToken.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden with fake CSRF token, got %d", respFakeToken.StatusCode)
	}

	// 5. 正常なトークン + XSS ペイロード (200 OK & エスケープされるべき)
	xssPayload := `{"input":"<script>alert('xss')</script> Hello Safe World!"}`
	reqValid, _ := http.NewRequest(http.MethodPost, server.URL+"/api/data", strings.NewReader(xssPayload))
	reqValid.Header.Set("Content-Type", "application/json")
	reqValid.Header.Set("X-CSRF-Token", csrfToken)

	respValid, err := client.Do(reqValid)
	if err != nil {
		t.Fatalf("Valid request failed: %v", err)
	}
	defer respValid.Body.Close()

	if respValid.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respValid.Body)
		t.Fatalf("Expected 200 OK for valid request, got %d. Body: %s", respValid.StatusCode, string(body))
	}

	var dataResp SecureDataResponse
	if err := json.NewDecoder(respValid.Body).Decode(&dataResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if strings.Contains(dataResp.SanitizedInput, "<script>") {
		t.Errorf("Sanitized output contains raw unescaped script tag: %s", dataResp.SanitizedInput)
	}
	if !strings.Contains(dataResp.SanitizedInput, "&lt;script&gt;") {
		t.Errorf("Sanitized output missing HTML-escaped script tag: %s", dataResp.SanitizedInput)
	}
}
