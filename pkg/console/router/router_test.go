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

package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/apache/dubbo-admin/pkg/common/bizerror"
	consolemcp "github.com/apache/dubbo-admin/pkg/console/mcp"
	"github.com/apache/dubbo-admin/pkg/console/model"
)

func TestInitMCPRouterRegistersRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	InitMCPRouter(engine, nil)

	require.NotNil(t, findRoute(engine, http.MethodPost, "/api/v1/mcp"))
	require.NotNil(t, findRoute(engine, http.MethodGet, "/api/v1/mcp"))
}

func TestMCPRouteUsesSessionAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("unauthorized", func(t *testing.T) {
		engine := newMCPTestEngine(false)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)

		engine.ServeHTTP(recorder, req)

		require.Equal(t, http.StatusUnauthorized, recorder.Code)
	})

	t.Run("authorized reaches handler", func(t *testing.T) {
		engine := newMCPTestEngine(true)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", nil)
		req.Header.Set("Accept", "application/json, text/event-stream")

		engine.ServeHTTP(recorder, req)

		require.NotEqual(t, http.StatusUnauthorized, recorder.Code)
		require.Equal(t, http.StatusBadRequest, recorder.Code)
	})
}

func newMCPTestEngine(authenticated bool) *gin.Engine {
	engine := gin.New()
	engine.Use(sessions.Sessions("session", cookie.NewStore([]byte("secret"))))
	engine.Use(func(ctx *gin.Context) {
		if authenticated {
			sessions.Default(ctx).Set("user", "admin")
			ctx.Next()
			return
		}
		authErr := bizerror.New(bizerror.Unauthorized, "no access, please login")
		ctx.JSON(http.StatusUnauthorized, model.NewBizErrorResp(authErr))
		ctx.Abort()
	})
	engine.Any("/api/v1/mcp", gin.WrapH(consolemcp.NewHTTPHandler(nil)))
	return engine
}

func findRoute(engine *gin.Engine, method string, path string) *gin.RouteInfo {
	for _, route := range engine.Routes() {
		if route.Method == method && route.Path == path {
			return &route
		}
	}
	return nil
}
