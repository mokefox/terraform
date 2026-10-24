package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// WAFBlockEvent represents an incident event dispatched when AWS WAF blocks malicious traffic.
type WAFBlockEvent struct {
	Timestamp   string `json:"timestamp"`
	ClientIP    string `json:"client_ip"`
	Country     string `json:"country"`
	Action      string `json:"action"` // BLOCK / COUNT
	RuleName    string `json:"rule_name"`
	HTTPMethod  string `json:"http_method"`
	URI         string `json:"uri"`
	UserAgent   string `json:"user_agent"`
	Host        string `json:"host"`
	IncidentID  string `json:"incident_id"`
}

// SlackBlockKitMessage defines the payload structure for Slack incoming webhooks.
type SlackBlockKitMessage struct {
	Blocks []map[string]interface{} `json:"blocks"`
}

// BuildSlackBlockKit formats a security incident into Slack Block Kit cards.
func BuildSlackBlockKit(event WAFBlockEvent) SlackBlockKitMessage {
	headerText := fmt.Sprintf("🚨 [WAF SOAR Alert] Malicious Traffic Blocked: %s", event.RuleName)

	fields := []map[string]interface{}{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Action:*\n`%s`", event.Action)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Client IP:*\n`%s` (%s)", event.ClientIP, event.Country)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Target:*\n`%s %s`", event.HTTPMethod, event.URI)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Rule:*\n`%s`", event.RuleName)},
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  headerText,
				"emoji": true,
			},
		},
		{
			"type":   "section",
			"fields": fields,
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*User-Agent:*\n`%s`\n*Host:*\n`%s`", event.UserAgent, event.Host),
			},
		},
		{
			"type": "context",
			"elements": []map[string]interface{}{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("⏱ *Timestamp:* `%s` | 🆔 *Incident ID:* `%s` | 🛡️ *Provider:* `AWS WAF v2 SOAR`", event.Timestamp, event.IncidentID),
				},
			},
		},
	}

	return SlackBlockKitMessage{Blocks: blocks}
}

// DispatchSlackNotification sends the Block Kit payload to the configured Slack webhook URL.
func DispatchSlackNotification(ctx context.Context, client *http.Client, webhookURL string, event WAFBlockEvent) error {
	if webhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL is not configured")
	}

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	payload := BuildSlackBlockKit(event)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack webhook returned non-200 status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// LambdaHandler is the entrypoint for AWS Lambda invocations.
func LambdaHandler(ctx context.Context, eventBytes []byte) error {
	var event WAFBlockEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		return fmt.Errorf("failed to unmarshal WAF incident event: %w", err)
	}

	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	client := &http.Client{Timeout: 5 * time.Second}

	return DispatchSlackNotification(ctx, client, webhookURL, event)
}

func main() {
	// Local execution / debugging entrypoint
	sampleEvent := WAFBlockEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ClientIP:    "198.51.100.23",
		Country:     "T1 (Tor Exit Node)",
		Action:      "BLOCK",
		RuleName:    "AWSManagedRulesAnonymousIpList",
		HTTPMethod:  "POST",
		URI:         "/api/data",
		UserAgent:   "sqlmap/1.7.2#stable",
		Host:        "api.example.corp",
		IncidentID:  "inc-waf-8921a4f0",
	}

	fmt.Println("[INFO] Generated Slack Block Kit Payload:")
	msg := BuildSlackBlockKit(sampleEvent)
	out, _ := json.MarshalIndent(msg, "", "  ")
	fmt.Println(string(out))
}
