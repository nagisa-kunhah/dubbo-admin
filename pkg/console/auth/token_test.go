/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	configauth "github.com/apache/dubbo-admin/pkg/config/console/auth"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestTokenIssuerSignsPrincipalClaimsAndPublishesPublicJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewTokenIssuer(&configauth.AccessTokenConfig{
		Enabled: true, Issuer: "dubbo-admin", KeyID: "admin-key-1", TTL: 1800,
		Audiences: []string{"dubbo-admin-ai"}, PrivateKey: key,
	})
	if err != nil {
		t.Fatalf("NewTokenIssuer() error = %v", err)
	}
	principal := Principal{
		Subject: "github:123", Username: "alice", Email: "alice@example.com", Groups: []string{"engineering"},
		Roles: []string{"operator"}, AuthType: "oauth", Provider: "github",
	}
	now := time.Unix(1_787_458_200, 0)
	response, err := issuer.Issue(principal, now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if response.TokenType != "Bearer" || response.ExpiresIn != 1800 || response.ExpiresAt != now.Add(1800*time.Second).Unix() {
		t.Fatalf("response = %+v", response)
	}
	parsed, err := josejwt.ParseSigned(response.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID != "admin-key-1" || parsed.Headers[0].Algorithm != string(jose.RS256) {
		t.Fatalf("headers = %+v", parsed.Headers)
	}
	var claims AccessTokenClaims
	if err := parsed.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatalf("verify claims: %v", err)
	}
	if claims.Subject != principal.Subject || claims.Username != principal.Username || claims.AuthType != principal.AuthType || claims.Provider != principal.Provider || claims.ID == "" {
		t.Fatalf("claims = %+v", claims)
	}
	if !claims.Audience.Contains("dubbo-admin-ai") || claims.Issuer != "dubbo-admin" || claims.Expiry.Time().Unix() != response.ExpiresAt {
		t.Fatalf("standard claims = %+v", claims.Claims)
	}

	jwks := issuer.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "admin-key-1" || jwks.Keys[0].Algorithm != string(jose.RS256) || jwks.Keys[0].Use != "sig" {
		t.Fatalf("JWKS = %+v", jwks)
	}
	if _, ok := jwks.Keys[0].Key.(*rsa.PublicKey); !ok {
		t.Fatalf("JWKS key type = %T, want *rsa.PublicKey", jwks.Keys[0].Key)
	}
	raw, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	for _, secretField := range []string{`"d":`, `"p":`, `"q":`} {
		if strings.Contains(string(raw), secretField) {
			t.Fatalf("JWKS leaks private field %s: %s", secretField, raw)
		}
	}
}

func TestTokenIssuerDisabled(t *testing.T) {
	issuer, err := NewTokenIssuer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Enabled() {
		t.Fatal("Enabled() = true")
	}
	if _, err := issuer.Issue(LocalPrincipal("admin"), time.Now()); err == nil {
		t.Fatal("Issue() succeeded while disabled")
	}
}
