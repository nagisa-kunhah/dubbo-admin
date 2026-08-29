package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTVerifierMiddlewareAndKeyRotation(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]*rsa.PublicKey{"key-1": &key1.PublicKey}
	var mu sync.Mutex
	requests := 0
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		body := jwksForTest(keys)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer jwksServer.Close()

	verifier, err := NewJWTVerifier(JWTAuthConfig{JWKSURL: jwksServer.URL, Issuer: "dubbo-admin", Audience: "dubbo-admin-ai"}, jwksServer.Client())
	if err != nil {
		t.Fatalf("NewJWTVerifier() error = %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware())
	router.Use(verifier.Middleware())
	router.GET("/health", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.GET("/api/v1/ai/test", func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok || claims.Subject == "" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})

	valid := signAITestToken(t, key1, "key-1", "dubbo-admin", "dubbo-admin-ai", "user:1", time.Now().Add(time.Minute), time.Now())
	assertAIStatus(t, router, http.MethodGet, "/api/v1/ai/test", "Bearer "+valid, http.StatusNoContent)
	assertAIStatus(t, router, http.MethodGet, "/api/v1/ai/test", "", http.StatusUnauthorized)
	health := assertAIStatus(t, router, http.MethodGet, "/health", "", http.StatusNoContent)
	if health.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("health has challenge %q", health.Header().Get("WWW-Authenticate"))
	}
	assertAIStatus(t, router, http.MethodOptions, "/api/v1/ai/test", "", http.StatusNoContent)

	mu.Lock()
	keys = map[string]*rsa.PublicKey{"key-1": &key1.PublicKey, "key-2": &key2.PublicKey}
	mu.Unlock()
	rotated := signAITestToken(t, key2, "key-2", "dubbo-admin", "dubbo-admin-ai", "user:2", time.Now().Add(time.Minute), time.Now())
	assertAIStatus(t, router, http.MethodGet, "/api/v1/ai/test", "Bearer "+rotated, http.StatusNoContent)
	mu.Lock()
	gotRequests := requests
	mu.Unlock()
	if gotRequests != 2 {
		t.Fatalf("JWKS requests = %d, want initial load + one unknown-kid refresh", gotRequests)
	}
}

func TestJWTVerifierRejectsInvalidTokens(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksForTest(map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
	}))
	defer jwksServer.Close()
	verifier, err := NewJWTVerifier(JWTAuthConfig{JWKSURL: jwksServer.URL, Issuer: "dubbo-admin", Audience: "dubbo-admin-ai"}, jwksServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(verifier.Middleware())
	router.GET("/api/v1/ai/test", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	now := time.Now()
	tests := []struct {
		name  string
		token string
	}{
		{name: "malformed", token: "not-a-token"},
		{name: "expired", token: signAITestToken(t, key, "key-1", "dubbo-admin", "dubbo-admin-ai", "user", now.Add(-time.Minute), now.Add(-time.Hour))},
		{name: "bad signature", token: signAITestToken(t, other, "key-1", "dubbo-admin", "dubbo-admin-ai", "user", now.Add(time.Minute), now)},
		{name: "unknown kid", token: signAITestToken(t, key, "missing", "dubbo-admin", "dubbo-admin-ai", "user", now.Add(time.Minute), now)},
		{name: "issuer", token: signAITestToken(t, key, "key-1", "wrong", "dubbo-admin-ai", "user", now.Add(time.Minute), now)},
		{name: "audience", token: signAITestToken(t, key, "key-1", "dubbo-admin", "wrong", "user", now.Add(time.Minute), now)},
		{name: "future issued at", token: signAITestToken(t, key, "key-1", "dubbo-admin", "dubbo-admin-ai", "user", now.Add(time.Minute), now.Add(time.Minute))},
		{name: "empty subject", token: signAITestToken(t, key, "key-1", "dubbo-admin", "dubbo-admin-ai", "", now.Add(time.Minute), now)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := assertAIStatus(t, router, http.MethodGet, "/api/v1/ai/test", "Bearer "+tt.token, http.StatusUnauthorized)
			if resp.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("WWW-Authenticate = %q", resp.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func assertAIStatus(t *testing.T, router http.Handler, method, path, authorization string, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != want {
		t.Fatalf("%s %s status = %d, want %d; body = %s", method, path, recorder.Code, want, recorder.Body.String())
	}
	return recorder
}

func signAITestToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, subject string, expires, issuedAt time.Time) string {
	t.Helper()
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: subject, Audience: jwt.ClaimStrings{audience}, ExpiresAt: jwt.NewNumericDate(expires), IssuedAt: jwt.NewNumericDate(issuedAt),
	}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func jwksForTest(keys map[string]*rsa.PublicKey) map[string]any {
	items := make([]map[string]any, 0, len(keys))
	for kid, key := range keys {
		items = append(items, map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		})
	}
	return map[string]any{"keys": items}
}
