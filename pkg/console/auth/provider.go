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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"

	configauth "github.com/apache/dubbo-admin/pkg/config/console/auth"
)

var (
	ErrProviderNotFound = errors.New("authentication provider not found")
	ErrProviderMismatch = errors.New("OAuth callback provider does not match transaction")
	ErrStateMismatch    = errors.New("OAuth callback state does not match transaction")
)

type Provider interface {
	ID() string
	DisplayName() string
	NeedsNonce() bool
	PostLoginRedirectURL() string
	AuthorizationURL(transaction OAuthTransaction) string
	Authenticate(ctx context.Context, code, codeVerifier, nonce string) (Principal, error)
}

type PublicProvider struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type Service struct {
	providers map[string]Provider
	public    []PublicProvider
}

func NewService(ctx context.Context, configs map[string]configauth.ProviderConfig, client *http.Client) (*Service, error) {
	ids := make([]string, 0, len(configs))
	for id := range configs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	providers := make([]Provider, 0, len(ids))
	for _, id := range ids {
		cfg := configs[id]
		switch cfg.Type {
		case configauth.ProviderTypeGitHub:
			providers = append(providers, NewGitHubProvider(id, cfg))
		case configauth.ProviderTypeOIDC:
			provider, err := NewOIDCProvider(ctx, id, cfg, client)
			if err != nil {
				return nil, err
			}
			providers = append(providers, provider)
		default:
			return nil, fmt.Errorf("unsupported authentication provider type %q", cfg.Type)
		}
	}
	return newService(providers)
}

func newService(providers []Provider) (*Service, error) {
	service := &Service{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		if provider == nil || provider.ID() == "" {
			return nil, errors.New("authentication provider must have an ID")
		}
		if _, exists := service.providers[provider.ID()]; exists {
			return nil, fmt.Errorf("duplicate authentication provider %q", provider.ID())
		}
		service.providers[provider.ID()] = provider
		service.public = append(service.public, PublicProvider{ID: provider.ID(), DisplayName: provider.DisplayName()})
	}
	sort.Slice(service.public, func(i, j int) bool { return service.public[i].ID < service.public[j].ID })
	return service, nil
}

func NewServiceFromProviders(providers ...Provider) (*Service, error) {
	return newService(providers)
}

func (s *Service) PublicProviders() []PublicProvider {
	return append([]PublicProvider{}, s.public...)
}

func (s *Service) Begin(providerID string) (OAuthTransaction, string, error) {
	provider, ok := s.providers[providerID]
	if !ok {
		return OAuthTransaction{}, "", ErrProviderNotFound
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return OAuthTransaction{}, "", fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier, err := randomBase64URL(32)
	if err != nil {
		return OAuthTransaction{}, "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	transaction := OAuthTransaction{ProviderID: providerID, State: state, CodeVerifier: verifier}
	if provider.NeedsNonce() {
		transaction.Nonce, err = randomBase64URL(32)
		if err != nil {
			return OAuthTransaction{}, "", fmt.Errorf("generate OIDC nonce: %w", err)
		}
	}
	return transaction, provider.AuthorizationURL(transaction), nil
}

func (s *Service) Complete(ctx context.Context, providerID, state, code string, transaction OAuthTransaction) (Principal, error) {
	if providerID != transaction.ProviderID {
		return Principal{}, ErrProviderMismatch
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(transaction.State)) != 1 {
		return Principal{}, ErrStateMismatch
	}
	provider, ok := s.providers[providerID]
	if !ok {
		return Principal{}, ErrProviderNotFound
	}
	if code == "" {
		return Principal{}, errors.New("OAuth callback code is missing")
	}
	return provider.Authenticate(ctx, code, transaction.CodeVerifier, transaction.Nonce)
}

func (s *Service) PostLoginRedirectURL(providerID string) (string, error) {
	provider, ok := s.providers[providerID]
	if !ok {
		return "", ErrProviderNotFound
	}
	return provider.PostLoginRedirectURL(), nil
}

func PKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func randomBase64URL(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
