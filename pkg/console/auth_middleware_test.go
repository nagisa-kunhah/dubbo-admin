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

package console

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestAnonymousAdminAllowlistIsExact(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/api/v1/auth/login", true},
		{http.MethodGet, "/api/v1/auth/login", false},
		{http.MethodGet, "/api/v1/auth/providers", true},
		{http.MethodGet, "/api/v1/auth/providers/github/login", true},
		{http.MethodGet, "/api/v1/auth/providers/company-sso/callback", true},
		{http.MethodGet, "/api/v1/auth/providers/../callback", false},
		{http.MethodGet, "/api/v1/auth/jwks", true},
		{http.MethodGet, "/api/v1/application/login", false},
		{http.MethodGet, "/health", true},
	}
	for _, tt := range tests {
		if got := isAnonymousAdminRequest(tt.method, tt.path); got != tt.want {
			t.Errorf("isAnonymousAdminRequest(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestAuthMiddlewareProtectsBusinessAPIAndLeavesPublicPathsAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &consoleWebServer{}
	r := gin.New()
	r.Use(sessions.Sessions("session", cookie.NewStore([]byte("test-secret"))))
	r.Use(server.authMiddleware())
	r.GET("/api/v1/protected", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/api/v1/auth/providers", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/admin/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	assertStatus := func(path string, want int) {
		t.Helper()
		recorder := httptest.NewRecorder()
		r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != want {
			t.Fatalf("GET %s status = %d, want %d; body = %s", path, recorder.Code, want, recorder.Body.String())
		}
	}
	assertStatus("/api/v1/protected", http.StatusUnauthorized)
	assertStatus("/api/v1/auth/providers", http.StatusNoContent)
	assertStatus("/admin/", http.StatusNoContent)
}
