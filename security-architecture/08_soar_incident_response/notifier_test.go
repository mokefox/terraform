package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildSlackBlockKit(t *testing.T) {
	event := WAFBlockEvent{
		Timestamp:  "2026-10-24T05:00:00Z",
		ClientIP:   "198.51.100.42",
		Country:    "US",
		Action:     "BLOCK",
		RuleName:   "AWSManagedRulesSQLiRuleSet",
		HTTPMethod: "POST",
		URI:        "/login",
		UserAgent:  "Mozilla/5.0",
		Host:       "secure.example.corp",
		IncidentID: "inc-12345",
	}

	msg := BuildSlackBlockKit(event)
	if len(msg.Blocks) < 4 {
		t.Fatalf("Expected at least 4 blocks, got %d", len(msg.Blocks))
	}

	// Verify header
	headerBlock := msg.Blocks[0]
	if headerBlock["type"] != "header" {
		t.Errorf("Expected first block to be header, got %v", headerBlock["type"])
	}

	// Marshal and verify JSON contents
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal Block Kit message: %v", err)
	}
	raw := string(data)

	if !contains(raw, "AWSManagedRulesSQLiRuleSet") {
		t.Errorf("Block Kit missing rule name")
	}
	if !contains(raw, "198.51.100.42") {
		t.Errorf("Block Kit missing client IP")
	}
}

func TestDispatchSlackNotification(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	event := WAFBlockEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ClientIP:   "203.0.113.195",
		Country:    "JP",
		Action:     "BLOCK",
		RuleName:   "RateLimitPerIP",
		HTTPMethod: "GET",
		URI:        "/api/search",
		UserAgent:  "curl/8.4.0",
		Host:       "api.example.corp",
		IncidentID: "inc-rate-limit-99",
	}

	err := DispatchSlackNotification(context.Background(), server.Client(), server.URL, event)
	if err != nil {
		t.Fatalf("DispatchSlackNotification failed: %v", err)
	}

	if receivedPayload == nil {
		t.Fatalf("Server did not receive payload")
	}

	blocks, ok := receivedPayload["blocks"].([]interface{})
	if !ok || len(blocks) == 0 {
		t.Errorf("Payload does not contain valid blocks")
	}
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 || (len(str) > 0 && len(substr) > 0 && indexOf(str, substr) >= 0))
}

func indexOf(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}
