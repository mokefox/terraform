package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	csrfSecretKey = []byte(getEnvOrDefault("CSRF_SECRET_KEY", "super-secret-key-32-bytes-minimum!"))
)

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// -----------------------------------------------------------------------------
// 1. レートリミッター (Token Bucket による In-Memory 防御)
// -----------------------------------------------------------------------------
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
	rate    float64 // tokens per second
	burst   int
}

type clientBucket struct {
	tokens     float64
	lastUpdate time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientBucket),
		rate:    rate,
		burst:   burst,
	}
	// 定期的な古いエントリのGC
	go func() {
		for {
			time.Sleep(3 * time.Minute)
			rl.mu.Lock()
			now := time.Now()
			for ip, b := range rl.clients {
				if now.Sub(b.lastUpdate) > 10*time.Minute {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.clients[ip]
	if !exists {
		rl.clients[ip] = &clientBucket{
			tokens:     float64(rl.burst - 1),
			lastUpdate: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.lastUpdate = now
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// 2. CSRF トークン生成 & 暗号学的検証 (HMAC-SHA256)
// -----------------------------------------------------------------------------
func generateCSRFToken() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, csrfSecretKey)
	h.Write(randomBytes)
	signature := h.Sum(nil)
	tokenPayload := append(randomBytes, signature...)
	return base64.URLEncoding.EncodeToString(tokenPayload), nil
}

func validateCSRFToken(tokenStr string) bool {
	raw, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil || len(raw) != 64 {
		return false
	}
	randomBytes := raw[:32]
	expectedSig := raw[32:]

	h := hmac.New(sha256.New, csrfSecretKey)
	h.Write(randomBytes)
	actualSig := h.Sum(nil)

	// タイミング攻撃を防ぐ ConstantTimeCompare
	return subtle.ConstantTimeCompare(expectedSig, actualSig) == 1
}

// -----------------------------------------------------------------------------
// 3. セキュリティミドルウェア
// -----------------------------------------------------------------------------
func SecurityMiddleware(next http.Handler, rl *RateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// (a) セキュリティヘッダーの付与
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none';")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// (b) レート制限検証
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !rl.Allow(clientIP) {
			http.Error(w, `{"error":"Too Many Requests"}`, http.StatusTooManyRequests)
			return
		}

		// (c) 状態変更メソッド (POST/PUT/DELETE/PATCH) に対する CSRF 検証
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// ヘルスチェック等の除外パス
			if r.URL.Path != "/healthz" && r.URL.Path != "/api/csrf-token" {
				token := r.Header.Get("X-CSRF-Token")
				if token == "" || !validateCSRFToken(token) {
					http.Error(w, `{"error":"Forbidden: Invalid or missing CSRF token"}`, http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------------
// 4. ハンドラー関数群
// -----------------------------------------------------------------------------
type SecureDataRequest struct {
	Input string `json:"input"`
}

type SecureDataResponse struct {
	SanitizedInput string `json:"sanitized_input"`
	Timestamp      string `json:"timestamp"`
	Status         string `json:"status"`
}

func handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token, err := generateCSRFToken()
	if err != nil {
		http.Error(w, `{"error":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// 機密トークンはブラウザキャッシュを禁止
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"csrf_token": token,
	})
}

func handleSecureAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. ボディサイズの制限 (MaxBytesReader でバッファ枯渇攻撃を防御)
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB 制限

	var req SecureDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Bad Request or payload too large"}`, http.StatusBadRequest)
		return
	}

	// 2. XSS サニタイズ
	sanitized := html.EscapeString(req.Input)

	resp := SecureDataResponse{
		SanitizedInput: sanitized,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Status:         "Verified & Protected",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("healthy\n"))
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

// -----------------------------------------------------------------------------
// 5. 堅牢な HTTP サーバー起動 (Slowloris/DoS 対策のタイムアウト設定)
// -----------------------------------------------------------------------------
func main() {
	port := getEnvOrDefault("PORT", "8080")
	rateLimiter := NewRateLimiter(20.0, 50) // 20 req/sec, burst 50

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/api/csrf-token", handleCSRFToken)
	mux.HandleFunc("/api/data", handleSecureAPI)

	// TLS 1.3 / 1.2 強制構成
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: false,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           SecurityMiddleware(mux, rateLimiter),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,  // Slowloris 攻撃防止
		ReadTimeout:       15 * time.Second, // 読み取りタイムアウト
		WriteTimeout:      15 * time.Second, // 書き込みタイムアウト
		IdleTimeout:       60 * time.Second, // アイドルキープアライブ
		MaxHeaderBytes:    1 << 20,          // 1MB
	}

	// グレースフルシャットダウン処理
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INFO] Zero-Trust Secure Server listening on port %s", port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] Server failed: %v", err)
		}
	}()

	<-stopChan
	log.Println("[INFO] Shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[ERROR] Server forced to shutdown: %v", err)
	}

	log.Println("[INFO] Server exited successfully.")
}
