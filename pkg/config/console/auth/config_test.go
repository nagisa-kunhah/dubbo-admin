/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() *Config {
	return &Config{User: "admin", Password: "secret", ExpirationTime: 3600}
}

func TestConfigValidateDefaultsPasswordOnly(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(cfg.Methods) != 1 || cfg.Methods[0] != MethodPassword {
		t.Fatalf("Methods = %v, want [%s]", cfg.Methods, MethodPassword)
	}
	if cfg.SessionSecret != DefaultSessionSecret {
		t.Fatalf("SessionSecret = %q, want legacy default", cfg.SessionSecret)
	}
}

func TestConfigValidateProviders(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		provider ProviderConfig
		wantErr  string
	}{
		{name: "unsafe id", id: "../github", provider: validGitHubProvider("../github"), wantErr: "provider id"},
		{name: "unknown type", id: "github", provider: ProviderConfig{Type: "oauth", ClientID: "id", ClientSecret: "secret", RedirectURL: "https://admin.example/api/v1/auth/providers/github/callback", PostLoginRedirectURL: "https://admin.example/admin/"}, wantErr: "type"},
		{name: "bad redirect", id: "github", provider: ProviderConfig{Type: ProviderTypeGitHub, ClientID: "id", ClientSecret: "secret", RedirectURL: "://bad", PostLoginRedirectURL: "https://admin.example/admin/"}, wantErr: "redirectUrl"},
		{name: "wrong callback", id: "github", provider: ProviderConfig{Type: ProviderTypeGitHub, ClientID: "id", ClientSecret: "secret", RedirectURL: "https://admin.example/wrong", PostLoginRedirectURL: "https://admin.example/admin/"}, wantErr: "callback"},
		{name: "oidc missing issuer", id: "sso", provider: ProviderConfig{Type: ProviderTypeOIDC, ClientID: "id", ClientSecret: "secret", RedirectURL: "https://admin.example/api/v1/auth/providers/sso/callback", PostLoginRedirectURL: "https://admin.example/admin/"}, wantErr: "issuer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Providers = map[string]ProviderConfig{tt.id: tt.provider}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateProviderScopeDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.Providers = map[string]ProviderConfig{
		"github": validGitHubProvider("github"),
		"sso": {
			Type: ProviderTypeOIDC, Issuer: "https://sso.example", ClientID: "id", ClientSecret: "secret",
			RedirectURL: "https://admin.example/api/v1/auth/providers/sso/callback", PostLoginRedirectURL: "https://admin.example/admin/",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := strings.Join(cfg.Providers["github"].Scopes, " "); got != "read:user user:email" {
		t.Fatalf("GitHub scopes = %q", got)
	}
	if got := strings.Join(cfg.Providers["sso"].Scopes, " "); got != "openid profile email" {
		t.Fatalf("OIDC scopes = %q", got)
	}
}

func TestConfigValidateOIDCRequiresOpenIDScope(t *testing.T) {
	cfg := validConfig()
	cfg.Providers = map[string]ProviderConfig{
		"sso": {
			Type: ProviderTypeOIDC, Issuer: "https://sso.example", ClientID: "id", ClientSecret: "secret",
			RedirectURL: "https://admin.example/api/v1/auth/providers/sso/callback", PostLoginRedirectURL: "https://admin.example/admin/", Scopes: []string{"profile"},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "openid") {
		t.Fatalf("Validate() error = %v, want openid error", err)
	}
}

func TestAccessTokenConfigValidation(t *testing.T) {
	t.Run("disabled does not load key", func(t *testing.T) {
		cfg := validConfig()
		cfg.AccessToken = &AccessTokenConfig{PrivateKeyFile: "/does/not/exist"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("required fields", func(t *testing.T) {
		cfg := validConfig()
		cfg.AccessToken = &AccessTokenConfig{Enabled: true}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "privateKeyFile") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		cfg := validConfig()
		cfg.AccessToken = validAccessTokenConfig("/does/not/exist")
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "private key") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("non RSA PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := validConfig()
		cfg.AccessToken = validAccessTokenConfig(path)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "RSA") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("undersized RSA", func(t *testing.T) {
		path := writeRSAKey(t, 1024, false)
		cfg := validConfig()
		cfg.AccessToken = validAccessTokenConfig(path)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "2048") {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	for _, pkcs8 := range []bool{false, true} {
		name := "PKCS1"
		if pkcs8 {
			name = "PKCS8"
		}
		t.Run(name, func(t *testing.T) {
			path := writeRSAKey(t, 2048, pkcs8)
			cfg := validConfig()
			cfg.AccessToken = validAccessTokenConfig(path)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if cfg.AccessToken.PrivateKey == nil || cfg.AccessToken.TTL != DefaultAccessTokenTTL {
				t.Fatalf("validated access token = %+v", cfg.AccessToken)
			}
		})
	}
}

func validGitHubProvider(id string) ProviderConfig {
	return ProviderConfig{
		Type: ProviderTypeGitHub, ClientID: "id", ClientSecret: "secret",
		RedirectURL: "https://admin.example/api/v1/auth/providers/" + id + "/callback", PostLoginRedirectURL: "https://admin.example/admin/",
	}
}

func validAccessTokenConfig(path string) *AccessTokenConfig {
	return &AccessTokenConfig{Enabled: true, Issuer: "dubbo-admin", KeyID: "key-1", PrivateKeyFile: path, Audiences: []string{"dubbo-admin-ai"}}
}

func writeRSAKey(t *testing.T, bits int, pkcs8 bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	blockType := "RSA PRIVATE KEY"
	if pkcs8 {
		der, err = x509.MarshalPKCS8PrivateKey(key)
		blockType = "PRIVATE KEY"
	} else {
		der = x509.MarshalPKCS1PrivateKey(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
