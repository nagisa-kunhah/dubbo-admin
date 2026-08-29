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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	configauth "github.com/apache/dubbo-admin/pkg/config/console/auth"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcProfile struct {
	Nonce             string   `json:"nonce"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	Roles             []string `json:"roles"`
}

type oidcProvider struct {
	id                   string
	displayName          string
	issuer               string
	clientID             string
	postLoginRedirectURL string
	discovery            oidcDiscovery
	oauth                oauth2.Config
	httpClient           *http.Client
}

func NewOIDCProvider(ctx context.Context, id string, cfg configauth.ProviderConfig, client *http.Client) (Provider, error) {
	if client == nil {
		client = http.DefaultClient
	}
	discoveryURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var discovery oidcDiscovery
	if err := getOIDCJSON(ctx, client, discoveryURL, "", &discovery); err != nil {
		return nil, fmt.Errorf("discover OIDC provider %q: %w", id, err)
	}
	if discovery.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("OIDC provider %q discovery issuer %q does not match configured issuer %q", id, discovery.Issuer, cfg.Issuer)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return nil, fmt.Errorf("OIDC provider %q discovery is missing required endpoints", id)
	}
	provider := &oidcProvider{
		id: id, displayName: cfg.DisplayName, issuer: cfg.Issuer, clientID: cfg.ClientID,
		postLoginRedirectURL: cfg.PostLoginRedirectURL, discovery: discovery, httpClient: client,
	}
	provider.oauth = oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Scopes:   append([]string(nil), cfg.Scopes...),
		Endpoint: oauth2.Endpoint{AuthURL: discovery.AuthorizationEndpoint, TokenURL: discovery.TokenEndpoint},
	}
	return provider, nil
}

func (p *oidcProvider) ID() string                   { return p.id }
func (p *oidcProvider) DisplayName() string          { return p.displayName }
func (p *oidcProvider) NeedsNonce() bool             { return true }
func (p *oidcProvider) PostLoginRedirectURL() string { return p.postLoginRedirectURL }
func (p *oidcProvider) AuthorizationURL(transaction OAuthTransaction) string {
	return p.oauth.AuthCodeURL(transaction.State,
		oauth2.SetAuthURLParam("code_challenge", PKCEChallenge(transaction.CodeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", transaction.Nonce))
}

func (p *oidcProvider) Authenticate(ctx context.Context, code, codeVerifier, nonce string) (Principal, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	token, err := p.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return Principal{}, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Principal{}, errors.New("OIDC token response is missing id_token")
	}
	claims, profile, err := p.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return Principal{}, err
	}
	if subtle.ConstantTimeCompare([]byte(profile.Nonce), []byte(nonce)) != 1 {
		return Principal{}, errors.New("OIDC ID Token nonce does not match OAuth transaction")
	}
	if claims.Subject == "" {
		return Principal{}, errors.New("OIDC ID Token subject is missing")
	}
	if oidcUsername(profile, claims.Subject) == "" || profile.Email == "" {
		if p.discovery.UserInfoEndpoint != "" {
			var userInfo struct {
				Subject string `json:"sub"`
				oidcProfile
			}
			if err := getOIDCJSON(ctx, p.httpClient, p.discovery.UserInfoEndpoint, token.AccessToken, &userInfo); err != nil {
				return Principal{}, fmt.Errorf("read OIDC UserInfo: %w", err)
			}
			if userInfo.Subject != claims.Subject {
				return Principal{}, errors.New("OIDC UserInfo subject does not match ID Token subject")
			}
			mergeOIDCProfile(&profile, userInfo.oidcProfile)
		}
	}
	return Principal{
		Subject: p.id + ":" + claims.Subject, Username: oidcUsername(profile, claims.Subject), Email: profile.Email,
		Groups: nonNilStrings(profile.Groups), Roles: nonNilStrings(profile.Roles), AuthType: "oidc", Provider: p.id,
	}, nil
}

func (p *oidcProvider) verifyIDToken(ctx context.Context, raw string) (josejwt.Claims, oidcProfile, error) {
	token, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return josejwt.Claims{}, oidcProfile{}, fmt.Errorf("parse OIDC ID Token: %w", err)
	}
	if len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return josejwt.Claims{}, oidcProfile{}, errors.New("OIDC ID Token kid is missing")
	}
	var keySet jose.JSONWebKeySet
	if err := getOIDCJSON(ctx, p.httpClient, p.discovery.JWKSURI, "", &keySet); err != nil {
		return josejwt.Claims{}, oidcProfile{}, fmt.Errorf("read OIDC JWKS: %w", err)
	}
	keys := keySet.Key(token.Headers[0].KeyID)
	if len(keys) != 1 || keys[0].Algorithm != string(jose.RS256) {
		return josejwt.Claims{}, oidcProfile{}, errors.New("OIDC ID Token signing key is unknown or not RS256")
	}
	var claims josejwt.Claims
	var profile oidcProfile
	if err := token.Claims(keys[0].Key, &claims, &profile); err != nil {
		return josejwt.Claims{}, oidcProfile{}, fmt.Errorf("verify OIDC ID Token signature: %w", err)
	}
	if claims.Expiry == nil {
		return josejwt.Claims{}, oidcProfile{}, errors.New("OIDC ID Token expiration is missing")
	}
	if err := claims.ValidateWithLeeway(josejwt.Expected{
		Issuer: p.issuer, AnyAudience: josejwt.Audience{p.clientID}, Time: time.Now(),
	}, 0); err != nil {
		return josejwt.Claims{}, oidcProfile{}, fmt.Errorf("validate OIDC ID Token issuer, audience, or expiration: %w", err)
	}
	if claims.Subject == "" {
		return josejwt.Claims{}, oidcProfile{}, errors.New("OIDC ID Token subject is missing")
	}
	return claims, profile, nil
}

func getOIDCJSON(ctx context.Context, client *http.Client, endpoint, bearer string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func oidcUsername(profile oidcProfile, subject string) string {
	for _, candidate := range []string{profile.PreferredUsername, profile.Name, profile.Email, subject} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func mergeOIDCProfile(target *oidcProfile, fallback oidcProfile) {
	if target.PreferredUsername == "" {
		target.PreferredUsername = fallback.PreferredUsername
	}
	if target.Name == "" {
		target.Name = fallback.Name
	}
	if target.Email == "" {
		target.Email = fallback.Email
	}
	if len(target.Groups) == 0 {
		target.Groups = fallback.Groups
	}
	if len(target.Roles) == 0 {
		target.Roles = fallback.Roles
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
