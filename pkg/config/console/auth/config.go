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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/apache/dubbo-admin/pkg/config"
)

const (
	DefaultExpirationTime = 7200
	DefaultSessionSecret  = "secret"
	DefaultAccessTokenTTL = 1800

	MethodPassword     = "password"
	ProviderTypeGitHub = "github"
	ProviderTypeOIDC   = "oidc"
)

var providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type ProviderConfig struct {
	Type                 string   `json:"type" yaml:"type"`
	DisplayName          string   `json:"displayName" yaml:"displayName"`
	Issuer               string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	ClientID             string   `json:"clientId" yaml:"clientId"`
	ClientSecret         string   `json:"clientSecret" yaml:"clientSecret"`
	RedirectURL          string   `json:"redirectUrl" yaml:"redirectUrl"`
	PostLoginRedirectURL string   `json:"postLoginRedirectUrl" yaml:"postLoginRedirectUrl"`
	Scopes               []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
}

type AccessTokenConfig struct {
	Enabled        bool            `json:"enabled" yaml:"enabled"`
	Issuer         string          `json:"issuer" yaml:"issuer"`
	KeyID          string          `json:"keyId" yaml:"keyId"`
	PrivateKeyFile string          `json:"privateKeyFile" yaml:"privateKeyFile"`
	TTL            int             `json:"ttl" yaml:"ttl"`
	Audiences      []string        `json:"audiences" yaml:"audiences"`
	PrivateKey     *rsa.PrivateKey `json:"-" yaml:"-"`
}

// Config AuthConfig configure the valid user and password
type Config struct {
	config.BaseConfig
	Methods             []string                  `json:"methods" yaml:"methods"`
	User                string                    `json:"user" yaml:"user"`
	Password            string                    `json:"password" yaml:"password"`
	ExpirationTime      int                       `json:"expirationTime" yaml:"expirationTime"`
	SessionSecret       string                    `json:"sessionSecret" yaml:"sessionSecret"`
	SessionCookieSecure bool                      `json:"sessionCookieSecure" yaml:"sessionCookieSecure"`
	AccessToken         *AccessTokenConfig        `json:"accessToken,omitempty" yaml:"accessToken,omitempty"`
	Providers           map[string]ProviderConfig `json:"providers,omitempty" yaml:"providers,omitempty"`
}

func (c *Config) Sanitize() {
	c.Password = config.SanitizedValue
	c.SessionSecret = config.SanitizedValue
	for id, provider := range c.Providers {
		provider.ClientSecret = config.SanitizedValue
		c.Providers[id] = provider
	}
}

func (c *Config) Validate() error {
	if len(c.Methods) == 0 {
		c.Methods = []string{MethodPassword}
	}
	for _, method := range c.Methods {
		if method != MethodPassword {
			return fmt.Errorf("auth: unsupported method %q", method)
		}
	}
	if slices.Contains(c.Methods, MethodPassword) && (c.User == "" || c.Password == "") {
		return errors.New("auth: user or password is needed, but found empty")
	}
	if c.ExpirationTime <= 0 || c.ExpirationTime >= 24*60*60 {
		return errors.New("auth: expirationTime should be greater than 0 and less than 86400")
	}
	if c.SessionSecret == "" {
		c.SessionSecret = DefaultSessionSecret
	}
	for id, provider := range c.Providers {
		if err := validateProvider(id, &provider); err != nil {
			return err
		}
		c.Providers[id] = provider
	}
	if c.AccessToken != nil {
		if err := c.AccessToken.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *AccessTokenConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.PrivateKeyFile) == "" {
		return errors.New("auth accessToken: privateKeyFile is required")
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("auth accessToken: issuer is required")
	}
	if strings.TrimSpace(c.KeyID) == "" {
		return errors.New("auth accessToken: keyId is required")
	}
	if len(c.Audiences) == 0 {
		return errors.New("auth accessToken: at least one audience is required")
	}
	for _, audience := range c.Audiences {
		if strings.TrimSpace(audience) == "" {
			return errors.New("auth accessToken: audiences must not contain an empty value")
		}
	}
	if c.TTL == 0 {
		c.TTL = DefaultAccessTokenTTL
	}
	if c.TTL < 0 {
		return errors.New("auth accessToken: ttl must be greater than 0")
	}
	key, err := loadRSAPrivateKey(c.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("auth accessToken: invalid RSA private key: %w", err)
	}
	if key.N.BitLen() < 2048 {
		return fmt.Errorf("auth accessToken: RSA private key must be at least 2048 bits")
	}
	c.PrivateKey = key
	return nil
}

func validateProvider(id string, provider *ProviderConfig) error {
	if !providerIDPattern.MatchString(id) {
		return fmt.Errorf("auth: invalid provider id %q", id)
	}
	if provider.Type != ProviderTypeGitHub && provider.Type != ProviderTypeOIDC {
		return fmt.Errorf("auth provider %q: unsupported type %q", id, provider.Type)
	}
	if provider.DisplayName == "" {
		provider.DisplayName = id
	}
	if provider.ClientID == "" || provider.ClientSecret == "" {
		return fmt.Errorf("auth provider %q: clientId and clientSecret are required", id)
	}
	redirect, err := validateHTTPURL(provider.RedirectURL)
	if err != nil {
		return fmt.Errorf("auth provider %q: invalid redirectUrl: %w", id, err)
	}
	expectedPath := "/api/v1/auth/providers/" + id + "/callback"
	if redirect.Path != expectedPath {
		return fmt.Errorf("auth provider %q: redirectUrl must use callback path %q", id, expectedPath)
	}
	if _, err := validateHTTPURL(provider.PostLoginRedirectURL); err != nil {
		return fmt.Errorf("auth provider %q: invalid postLoginRedirectUrl: %w", id, err)
	}
	switch provider.Type {
	case ProviderTypeGitHub:
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"read:user", "user:email"}
		}
	case ProviderTypeOIDC:
		if _, err := validateHTTPURL(provider.Issuer); err != nil {
			return fmt.Errorf("auth provider %q: invalid issuer: %w", id, err)
		}
		if len(provider.Scopes) == 0 {
			provider.Scopes = []string{"openid", "profile", "email"}
		}
		if !slices.Contains(provider.Scopes, "openid") {
			return fmt.Errorf("auth provider %q: OIDC scopes must include openid", id)
		}
	}
	return nil
}

func validateHTTPURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("must be an absolute HTTP or HTTPS URL")
	}
	return parsed, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("PEM block is missing")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM does not contain an RSA private key")
	}
	return key, nil
}
