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
	"context"
	"errors"
	"strings"

	consolectx "github.com/apache/dubbo-admin/pkg/console/context"
	"github.com/apache/dubbo-admin/pkg/console/model"
	"github.com/apache/dubbo-admin/pkg/console/service"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetApplicationDetailInput struct {
	Mesh    string `json:"mesh" jsonschema:"Dubbo Admin mesh id, required"`
	AppName string `json:"appName" jsonschema:"application name, required"`
}

type GetApplicationDetailOutput struct {
	Detail *model.ApplicationDetailResp `json:"detail"`
}

type GetInstanceDetailInput struct {
	Mesh         string `json:"mesh" jsonschema:"Dubbo Admin mesh id, required"`
	InstanceName string `json:"instanceName" jsonschema:"instance resource name, required"`
}

type GetInstanceDetailOutput struct {
	Detail *model.InstanceDetailResp `json:"detail"`
}

type GetServiceDetailInput struct {
	Mesh        string `json:"mesh" jsonschema:"Dubbo Admin mesh id, required"`
	ServiceName string `json:"serviceName" jsonschema:"service name, required"`
	Version     string `json:"version" jsonschema:"service version, optional"`
	Group       string `json:"group" jsonschema:"service group, optional"`
}

type GetServiceDetailOutput struct {
	Detail *model.ServiceDetailResp `json:"detail"`
}

type detailService interface {
	GetApplicationDetail(ctx consolectx.Context, req *model.ApplicationDetailReq) (*model.ApplicationDetailResp, error)
	GetInstanceDetail(ctx consolectx.Context, req *model.InstanceDetailReq) (*model.InstanceDetailResp, error)
	GetServiceDetail(ctx consolectx.Context, req *model.ServiceDetailReq) (*model.ServiceDetailResp, error)
}

type consoleDetailService struct{}

func (consoleDetailService) GetApplicationDetail(ctx consolectx.Context, req *model.ApplicationDetailReq) (*model.ApplicationDetailResp, error) {
	return service.GetApplicationDetail(ctx, req)
}

func (consoleDetailService) GetInstanceDetail(ctx consolectx.Context, req *model.InstanceDetailReq) (*model.InstanceDetailResp, error) {
	return service.GetInstanceDetail(ctx, req)
}

func (consoleDetailService) GetServiceDetail(ctx consolectx.Context, req *model.ServiceDetailReq) (*model.ServiceDetailResp, error) {
	return service.GetServiceDetail(ctx, req)
}

func RegisterDetailTools(server *mcpsdk.Server, ctx consolectx.Context) {
	registerDetailTools(server, ctx, consoleDetailService{})
}

func registerDetailTools(server *mcpsdk.Server, ctx consolectx.Context, svc detailService) {
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "dubbo_get_application_detail",
		Description: "Get Dubbo application detail by mesh and application name.",
	}, getApplicationDetailTool(ctx, svc))

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "dubbo_get_instance_detail",
		Description: "Get Dubbo instance detail by mesh and instance resource name.",
	}, getInstanceDetailTool(ctx, svc))

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "dubbo_get_service_detail",
		Description: "Get Dubbo service detail by mesh and service identity.",
	}, getServiceDetailTool(ctx, svc))
}

func getApplicationDetailTool(
	consoleCtx consolectx.Context,
	svc detailService,
) func(context.Context, *mcpsdk.CallToolRequest, GetApplicationDetailInput) (*mcpsdk.CallToolResult, GetApplicationDetailOutput, error) {
	return func(_ context.Context, _ *mcpsdk.CallToolRequest, input GetApplicationDetailInput) (*mcpsdk.CallToolResult, GetApplicationDetailOutput, error) {
		if strings.TrimSpace(input.Mesh) == "" {
			return nil, GetApplicationDetailOutput{}, errors.New("mesh is required")
		}
		if strings.TrimSpace(input.AppName) == "" {
			return nil, GetApplicationDetailOutput{}, errors.New("appName is required")
		}

		resp, err := svc.GetApplicationDetail(consoleCtx, &model.ApplicationDetailReq{
			Mesh:    input.Mesh,
			AppName: input.AppName,
		})
		if err != nil {
			return nil, GetApplicationDetailOutput{}, err
		}
		return nil, GetApplicationDetailOutput{Detail: resp}, nil
	}
}

func getInstanceDetailTool(
	consoleCtx consolectx.Context,
	svc detailService,
) func(context.Context, *mcpsdk.CallToolRequest, GetInstanceDetailInput) (*mcpsdk.CallToolResult, GetInstanceDetailOutput, error) {
	return func(_ context.Context, _ *mcpsdk.CallToolRequest, input GetInstanceDetailInput) (*mcpsdk.CallToolResult, GetInstanceDetailOutput, error) {
		if strings.TrimSpace(input.Mesh) == "" {
			return nil, GetInstanceDetailOutput{}, errors.New("mesh is required")
		}
		if strings.TrimSpace(input.InstanceName) == "" {
			return nil, GetInstanceDetailOutput{}, errors.New("instanceName is required")
		}

		resp, err := svc.GetInstanceDetail(consoleCtx, &model.InstanceDetailReq{
			Mesh:         input.Mesh,
			InstanceName: input.InstanceName,
		})
		if err != nil {
			return nil, GetInstanceDetailOutput{}, err
		}
		return nil, GetInstanceDetailOutput{Detail: resp}, nil
	}
}

func getServiceDetailTool(
	consoleCtx consolectx.Context,
	svc detailService,
) func(context.Context, *mcpsdk.CallToolRequest, GetServiceDetailInput) (*mcpsdk.CallToolResult, GetServiceDetailOutput, error) {
	return func(_ context.Context, _ *mcpsdk.CallToolRequest, input GetServiceDetailInput) (*mcpsdk.CallToolResult, GetServiceDetailOutput, error) {
		if strings.TrimSpace(input.Mesh) == "" {
			return nil, GetServiceDetailOutput{}, errors.New("mesh is required")
		}
		if strings.TrimSpace(input.ServiceName) == "" {
			return nil, GetServiceDetailOutput{}, errors.New("serviceName is required")
		}

		resp, err := svc.GetServiceDetail(consoleCtx, &model.ServiceDetailReq{
			Mesh:        input.Mesh,
			ServiceName: input.ServiceName,
			Version:     input.Version,
			Group:       input.Group,
		})
		if err != nil {
			return nil, GetServiceDetailOutput{}, err
		}
		return nil, GetServiceDetailOutput{Detail: resp}, nil
	}
}
