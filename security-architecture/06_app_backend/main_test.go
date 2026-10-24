package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFTokenGenerationAndValidation(t *testing.T) {
	token, err := generateCSRFToken()
	if err != nil {
		t.Fatalf("Failed to generate CSRF token: %v", err)
	}

	if !validateCSRFToken(token) {
		t.Errorf("Expected token to be valid, but validation failed: %s", token)
	}

	// 不正なトークンの検証
	if validateCSRFToken("invalid-token-payload") {
		t.Errorf("Expected invalid token to fail, but passed")
	}

	tamperedToken := token[:len(token)-5] + "AAAAA"
	if validateCSRFToken(tamperedToken) {
		t.Errorf("Expected tampered token to fail, but passed")
	}
}

func TestSecurityHeadersAndCSRFMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/csrf-token", handleCSRFToken)
	mux.HandleFunc("/api/data", handleSecureAPI)

	rl := NewRateLimiter(10.0, 10)
	handler := SecurityMiddleware(mux, rl)

	// 1. CSRF トークン取得
	reqToken := httptest.NewRequest(http.MethodGet, "/api/csrf-token", nil)
	wToken := httptest.NewRecorder()
	handler.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", wToken.Code)
	}

	// セキュリティヘッダーの検証
	if wToken.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Missing nosniff header")
	}
	if wToken.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("Missing X-Frame-Options DENY")
	}
	if !strings.Contains(wToken.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Errorf("Missing HSTS header")
	}

	var csrfBody map[string]string
	if err := json.NewDecoder(wToken.Body).Decode(&csrfBody); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}
	token := csrfBody["csrf_token"]
	if token == "" {
		t.Fatalf("Token empty in response")
	}

	// 2. CSRF トークンなしでの POST (403 Forbidden になるべき)
	reqNoToken := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader(`{"input":"hello"}`))
	wNoToken := httptest.NewRecorder()
	handler.ServeHTTP(wNoToken, reqNoToken)

	if wNoToken.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for request without CSRF token, got %d", wNoToken.Code)
	}

	// 3. 有効な CSRF トークンを付与しての POST (200 OK & XSS サニタイズ)
	payload := `{"input":"<script>alert('xss')</script>Hello"}`
	reqValid := httptest.NewRequest(http.MethodPost, "/api/data", bytes.NewBufferString(payload))
	reqValid.Header.Set("X-CSRF-Token", token)
	reqValid.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	handler.ServeHTTP(wValid, reqValid)

	if wValid.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid request, got %d. Body: %s", wValid.Code, wValid.Body.String())
	}

	var resp SecureDataResponse
	if err := json.NewDecoder(wValid.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to parse API response: %v", err)
	}

	// XSS エスケープの検証
	if strings.Contains(resp.SanitizedInput, "<script>") {
		t.Errorf("Sanitized input contains raw script tags: %s", resp.SanitizedInput)
	}
	if !strings.Contains(resp.SanitizedInput, "&lt;script&gt;") {
		t.Errorf("Sanitized input was not properly HTML-escaped: %s", resp.SanitizedInput)
	}
}
