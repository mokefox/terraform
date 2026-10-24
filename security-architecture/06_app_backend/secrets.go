package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// 現場の必須要件: 安全なシークレットプロバイダー
// 環境変数の平文露出を避け、動的フェッチ & キャッシュ & 定期ローテーションを行う
// -----------------------------------------------------------------------------

type SecretProvider interface {
	GetSecret(ctx context.Context, key string) (string, error)
}

// EnvSecretProvider (開発・フォールバック用)
type EnvSecretProvider struct{}

func (e *EnvSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", fmt.Errorf("secret key %s not found in environment", key)
	}
	return val, nil
}

// CachedSecretProvider (AWS Secrets Manager / Vault 等の呼び出し削減 & TTL管理)
type CachedSecretProvider struct {
	upstream SecretProvider
	ttl      time.Duration
	cache    map[string]secretCacheEntry
	mu       sync.RWMutex
}

type secretCacheEntry struct {
	value     string
	expiresAt time.Time
}

func NewCachedSecretProvider(upstream SecretProvider, ttl time.Duration) *CachedSecretProvider {
	return &CachedSecretProvider{
		upstream: upstream,
		ttl:      ttl,
		cache:    make(map[string]secretCacheEntry),
	}
}

func (c *CachedSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	c.mu.RLock()
	entry, found := c.cache[key]
	c.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.value, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check locking
	if entry, found := c.cache[key]; found && time.Now().Before(entry.expiresAt) {
		return entry.value, nil
	}

	val, err := c.upstream.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}

	c.cache[key] = secretCacheEntry{
		value:     strings.TrimSpace(val),
		expiresAt: time.Now().Add(c.ttl),
	}

	return val, nil
}
