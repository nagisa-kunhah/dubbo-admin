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

package mcp

import (
	"net/http"

	consolectx "github.com/apache/dubbo-admin/pkg/console/context"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewServer(ctx consolectx.Context) *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "dubbo-admin",
		Version: "v0.1.0",
	}, nil)
	RegisterDetailTools(server, ctx)
	return server
}

func NewHTTPHandler(ctx consolectx.Context) http.Handler {
	server := NewServer(ctx)
	return mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return server
	}, nil)
}
