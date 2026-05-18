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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apache/dubbo-admin/pkg/config/app"
	consolectx "github.com/apache/dubbo-admin/pkg/console/context"
	"github.com/apache/dubbo-admin/pkg/console/counter"
	"github.com/apache/dubbo-admin/pkg/console/model"
	"github.com/apache/dubbo-admin/pkg/core/lock"
	"github.com/apache/dubbo-admin/pkg/core/manager"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGetApplicationDetailTool(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := &fakeDetailService{
			applicationResp: &model.ApplicationDetailResp{AppName: "demo"},
		}
		_, output, err := getApplicationDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetApplicationDetailInput{Mesh: "mesh1", AppName: "demo"},
		)

		require.NoError(t, err)
		require.Equal(t, &model.ApplicationDetailResp{AppName: "demo"}, output.Detail)
		require.Equal(t, &model.ApplicationDetailReq{Mesh: "mesh1", AppName: "demo"}, svc.applicationReq)
	})

	t.Run("mesh required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getApplicationDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetApplicationDetailInput{AppName: "demo"},
		)

		require.EqualError(t, err, "mesh is required")
		require.Nil(t, svc.applicationReq)
	})

	t.Run("appName required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getApplicationDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetApplicationDetailInput{Mesh: "mesh1"},
		)

		require.EqualError(t, err, "appName is required")
		require.Nil(t, svc.applicationReq)
	})

	t.Run("service error", func(t *testing.T) {
		serviceErr := errors.New("application not found")
		svc := &fakeDetailService{applicationErr: serviceErr}
		_, _, err := getApplicationDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetApplicationDetailInput{Mesh: "mesh1", AppName: "demo"},
		)

		require.ErrorIs(t, err, serviceErr)
		require.Equal(t, &model.ApplicationDetailReq{Mesh: "mesh1", AppName: "demo"}, svc.applicationReq)
	})
}

func TestGetInstanceDetailTool(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := &fakeDetailService{
			instanceResp: &model.InstanceDetailResp{AppName: "demo", Ip: "127.0.0.1"},
		}
		_, output, err := getInstanceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetInstanceDetailInput{Mesh: "mesh1", InstanceName: "instance1"},
		)

		require.NoError(t, err)
		require.Equal(t, &model.InstanceDetailResp{AppName: "demo", Ip: "127.0.0.1"}, output.Detail)
		require.Equal(t, &model.InstanceDetailReq{Mesh: "mesh1", InstanceName: "instance1"}, svc.instanceReq)
	})

	t.Run("mesh required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getInstanceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetInstanceDetailInput{InstanceName: "instance1"},
		)

		require.EqualError(t, err, "mesh is required")
		require.Nil(t, svc.instanceReq)
	})

	t.Run("instanceName required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getInstanceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetInstanceDetailInput{Mesh: "mesh1"},
		)

		require.EqualError(t, err, "instanceName is required")
		require.Nil(t, svc.instanceReq)
	})

	t.Run("service error", func(t *testing.T) {
		serviceErr := errors.New("instance not found")
		svc := &fakeDetailService{instanceErr: serviceErr}
		_, _, err := getInstanceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetInstanceDetailInput{Mesh: "mesh1", InstanceName: "instance1"},
		)

		require.ErrorIs(t, err, serviceErr)
		require.Equal(t, &model.InstanceDetailReq{Mesh: "mesh1", InstanceName: "instance1"}, svc.instanceReq)
	})
}

func TestGetServiceDetailTool(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := &fakeDetailService{
			serviceResp: &model.ServiceDetailResp{Language: "java", Methods: []string{"sayHello"}},
		}
		_, output, err := getServiceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetServiceDetailInput{
				Mesh:        "mesh1",
				ServiceName: "org.apache.demo.DemoService",
				Version:     "1.0.0",
				Group:       "test",
			},
		)

		require.NoError(t, err)
		require.Equal(t, &model.ServiceDetailResp{Language: "java", Methods: []string{"sayHello"}}, output.Detail)
		require.Equal(t, &model.ServiceDetailReq{
			Mesh:        "mesh1",
			ServiceName: "org.apache.demo.DemoService",
			Version:     "1.0.0",
			Group:       "test",
		}, svc.serviceReq)
	})

	t.Run("mesh required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getServiceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetServiceDetailInput{ServiceName: "org.apache.demo.DemoService"},
		)

		require.EqualError(t, err, "mesh is required")
		require.Nil(t, svc.serviceReq)
	})

	t.Run("serviceName required", func(t *testing.T) {
		svc := &fakeDetailService{}
		_, _, err := getServiceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetServiceDetailInput{Mesh: "mesh1"},
		)

		require.EqualError(t, err, "serviceName is required")
		require.Nil(t, svc.serviceReq)
	})

	t.Run("service error", func(t *testing.T) {
		serviceErr := errors.New("service not found")
		svc := &fakeDetailService{serviceErr: serviceErr}
		_, _, err := getServiceDetailTool(fakeConsoleContext{}, svc)(
			context.Background(),
			nil,
			GetServiceDetailInput{
				Mesh:        "mesh1",
				ServiceName: "org.apache.demo.DemoService",
				Version:     "1.0.0",
				Group:       "test",
			},
		)

		require.ErrorIs(t, err, serviceErr)
		require.Equal(t, &model.ServiceDetailReq{
			Mesh:        "mesh1",
			ServiceName: "org.apache.demo.DemoService",
			Version:     "1.0.0",
			Group:       "test",
		}, svc.serviceReq)
	})
}

func TestRegisterDetailTools(t *testing.T) {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "test-server"}, nil)
	registerDetailTools(server, fakeConsoleContext{}, &fakeDetailService{})

	clientSession, err := connectInMemory(t, server)
	require.NoError(t, err)
	defer clientSession.Close()

	result, err := clientSession.ListTools(context.Background(), nil)
	require.NoError(t, err)

	var names []string
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	require.ElementsMatch(t, []string{
		"dubbo_get_application_detail",
		"dubbo_get_instance_detail",
		"dubbo_get_service_detail",
	}, names)
}

func connectInMemory(t *testing.T, server *mcpsdk.Server) (*mcpsdk.ClientSession, error) {
	t.Helper()
	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		_ = serverSession.Close()
	})
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client"}, nil)
	return client.Connect(context.Background(), clientTransport, nil)
}

type fakeDetailService struct {
	applicationReq  *model.ApplicationDetailReq
	applicationResp *model.ApplicationDetailResp
	applicationErr  error

	instanceReq  *model.InstanceDetailReq
	instanceResp *model.InstanceDetailResp
	instanceErr  error

	serviceReq  *model.ServiceDetailReq
	serviceResp *model.ServiceDetailResp
	serviceErr  error
}

func (f *fakeDetailService) GetApplicationDetail(_ consolectx.Context, req *model.ApplicationDetailReq) (*model.ApplicationDetailResp, error) {
	f.applicationReq = req
	return f.applicationResp, f.applicationErr
}

func (f *fakeDetailService) GetInstanceDetail(_ consolectx.Context, req *model.InstanceDetailReq) (*model.InstanceDetailResp, error) {
	f.instanceReq = req
	return f.instanceResp, f.instanceErr
}

func (f *fakeDetailService) GetServiceDetail(_ consolectx.Context, req *model.ServiceDetailReq) (*model.ServiceDetailResp, error) {
	f.serviceReq = req
	return f.serviceResp, f.serviceErr
}

type fakeConsoleContext struct{}

func (fakeConsoleContext) ResourceManager() manager.ResourceManager {
	return nil
}

func (fakeConsoleContext) CounterManager() counter.CounterManager {
	return nil
}

func (fakeConsoleContext) Config() app.AdminConfig {
	return app.DefaultAdminConfig()
}

func (fakeConsoleContext) AppContext() context.Context {
	return context.Background()
}

func (fakeConsoleContext) LockManager() lock.Lock {
	return nil
}
