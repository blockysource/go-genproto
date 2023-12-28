// Copyright 2023 The Blocky Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: blocky/authz/admin/v1alpha/client_admin.proto

package authzadminv1alphaconnect

import (
	context "context"
	errors "errors"
	v1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	connect_go "github.com/bufbuild/connect-go"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect_go.IsAtLeastVersion0_1_0

const (
	// ClientAdminServiceName is the fully-qualified name of the ClientAdminService service.
	ClientAdminServiceName = "blocky.authz.admin.v1alpha.ClientAdminService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// ClientAdminServiceCreateClientProcedure is the fully-qualified name of the ClientAdminService's
	// CreateClient RPC.
	ClientAdminServiceCreateClientProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/CreateClient"
	// ClientAdminServiceListClientProcedure is the fully-qualified name of the ClientAdminService's
	// ListClient RPC.
	ClientAdminServiceListClientProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/ListClient"
	// ClientAdminServiceGetClientProcedure is the fully-qualified name of the ClientAdminService's
	// GetClient RPC.
	ClientAdminServiceGetClientProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/GetClient"
	// ClientAdminServiceUpdateClientProcedure is the fully-qualified name of the ClientAdminService's
	// UpdateClient RPC.
	ClientAdminServiceUpdateClientProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/UpdateClient"
	// ClientAdminServiceDeleteClientProcedure is the fully-qualified name of the ClientAdminService's
	// DeleteClient RPC.
	ClientAdminServiceDeleteClientProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/DeleteClient"
	// ClientAdminServiceCreateClientResourcePermissionProcedure is the fully-qualified name of the
	// ClientAdminService's CreateClientResourcePermission RPC.
	ClientAdminServiceCreateClientResourcePermissionProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/CreateClientResourcePermission"
	// ClientAdminServiceListClientResourcePermissionsProcedure is the fully-qualified name of the
	// ClientAdminService's ListClientResourcePermissions RPC.
	ClientAdminServiceListClientResourcePermissionsProcedure = "/blocky.authz.admin.v1alpha.ClientAdminService/ListClientResourcePermissions"
)

// ClientAdminServiceClient is a client for the blocky.authz.admin.v1alpha.ClientAdminService
// service.
type ClientAdminServiceClient interface {
	// Creates a new authorization client with the specified name,
	// and returns the new client.
	// A newly created client will have a secret generated.
	CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Lists authorization clients matching the specified filter.
	ListClient(context.Context, *connect_go.Request[v1alpha.ListClientRequest]) (*connect_go.Response[v1alpha.ListClientResponse], error)
	// Gets an authorization client by its identifier.
	GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Updates an authorization client, and returns the updated client.
	UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Deletes an authorization client.
	DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[emptypb.Empty], error)
	// CreateClientResourcePermission adds a client the permission to use given resource,
	// defined by the resource permission.
	CreateClientResourcePermission(context.Context, *connect_go.Request[v1alpha.CreateClientResourcePermissionRequest]) (*connect_go.Response[v1alpha.ClientResourcePermission], error)
	ListClientResourcePermissions(context.Context, *connect_go.Request[v1alpha.ListClientResourcePermissionsRequest]) (*connect_go.Response[v1alpha.ListClientResourcePermissionsResponse], error)
}

// NewClientAdminServiceClient constructs a client for the
// blocky.authz.admin.v1alpha.ClientAdminService service. By default, it uses the Connect protocol
// with the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed requests. To
// use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or connect.WithGRPCWeb()
// options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewClientAdminServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) ClientAdminServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &clientAdminServiceClient{
		createClient: connect_go.NewClient[v1alpha.CreateClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientAdminServiceCreateClientProcedure,
			opts...,
		),
		listClient: connect_go.NewClient[v1alpha.ListClientRequest, v1alpha.ListClientResponse](
			httpClient,
			baseURL+ClientAdminServiceListClientProcedure,
			opts...,
		),
		getClient: connect_go.NewClient[v1alpha.GetClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientAdminServiceGetClientProcedure,
			opts...,
		),
		updateClient: connect_go.NewClient[v1alpha.UpdateClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientAdminServiceUpdateClientProcedure,
			opts...,
		),
		deleteClient: connect_go.NewClient[v1alpha.DeleteClientRequest, emptypb.Empty](
			httpClient,
			baseURL+ClientAdminServiceDeleteClientProcedure,
			opts...,
		),
		createClientResourcePermission: connect_go.NewClient[v1alpha.CreateClientResourcePermissionRequest, v1alpha.ClientResourcePermission](
			httpClient,
			baseURL+ClientAdminServiceCreateClientResourcePermissionProcedure,
			opts...,
		),
		listClientResourcePermissions: connect_go.NewClient[v1alpha.ListClientResourcePermissionsRequest, v1alpha.ListClientResourcePermissionsResponse](
			httpClient,
			baseURL+ClientAdminServiceListClientResourcePermissionsProcedure,
			opts...,
		),
	}
}

// clientAdminServiceClient implements ClientAdminServiceClient.
type clientAdminServiceClient struct {
	createClient                   *connect_go.Client[v1alpha.CreateClientRequest, v1alpha.Client]
	listClient                     *connect_go.Client[v1alpha.ListClientRequest, v1alpha.ListClientResponse]
	getClient                      *connect_go.Client[v1alpha.GetClientRequest, v1alpha.Client]
	updateClient                   *connect_go.Client[v1alpha.UpdateClientRequest, v1alpha.Client]
	deleteClient                   *connect_go.Client[v1alpha.DeleteClientRequest, emptypb.Empty]
	createClientResourcePermission *connect_go.Client[v1alpha.CreateClientResourcePermissionRequest, v1alpha.ClientResourcePermission]
	listClientResourcePermissions  *connect_go.Client[v1alpha.ListClientResourcePermissionsRequest, v1alpha.ListClientResourcePermissionsResponse]
}

// CreateClient calls blocky.authz.admin.v1alpha.ClientAdminService.CreateClient.
func (c *clientAdminServiceClient) CreateClient(ctx context.Context, req *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.createClient.CallUnary(ctx, req)
}

// ListClient calls blocky.authz.admin.v1alpha.ClientAdminService.ListClient.
func (c *clientAdminServiceClient) ListClient(ctx context.Context, req *connect_go.Request[v1alpha.ListClientRequest]) (*connect_go.Response[v1alpha.ListClientResponse], error) {
	return c.listClient.CallUnary(ctx, req)
}

// GetClient calls blocky.authz.admin.v1alpha.ClientAdminService.GetClient.
func (c *clientAdminServiceClient) GetClient(ctx context.Context, req *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.getClient.CallUnary(ctx, req)
}

// UpdateClient calls blocky.authz.admin.v1alpha.ClientAdminService.UpdateClient.
func (c *clientAdminServiceClient) UpdateClient(ctx context.Context, req *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.updateClient.CallUnary(ctx, req)
}

// DeleteClient calls blocky.authz.admin.v1alpha.ClientAdminService.DeleteClient.
func (c *clientAdminServiceClient) DeleteClient(ctx context.Context, req *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[emptypb.Empty], error) {
	return c.deleteClient.CallUnary(ctx, req)
}

// CreateClientResourcePermission calls
// blocky.authz.admin.v1alpha.ClientAdminService.CreateClientResourcePermission.
func (c *clientAdminServiceClient) CreateClientResourcePermission(ctx context.Context, req *connect_go.Request[v1alpha.CreateClientResourcePermissionRequest]) (*connect_go.Response[v1alpha.ClientResourcePermission], error) {
	return c.createClientResourcePermission.CallUnary(ctx, req)
}

// ListClientResourcePermissions calls
// blocky.authz.admin.v1alpha.ClientAdminService.ListClientResourcePermissions.
func (c *clientAdminServiceClient) ListClientResourcePermissions(ctx context.Context, req *connect_go.Request[v1alpha.ListClientResourcePermissionsRequest]) (*connect_go.Response[v1alpha.ListClientResourcePermissionsResponse], error) {
	return c.listClientResourcePermissions.CallUnary(ctx, req)
}

// ClientAdminServiceHandler is an implementation of the
// blocky.authz.admin.v1alpha.ClientAdminService service.
type ClientAdminServiceHandler interface {
	// Creates a new authorization client with the specified name,
	// and returns the new client.
	// A newly created client will have a secret generated.
	CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Lists authorization clients matching the specified filter.
	ListClient(context.Context, *connect_go.Request[v1alpha.ListClientRequest]) (*connect_go.Response[v1alpha.ListClientResponse], error)
	// Gets an authorization client by its identifier.
	GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Updates an authorization client, and returns the updated client.
	UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Deletes an authorization client.
	DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[emptypb.Empty], error)
	// CreateClientResourcePermission adds a client the permission to use given resource,
	// defined by the resource permission.
	CreateClientResourcePermission(context.Context, *connect_go.Request[v1alpha.CreateClientResourcePermissionRequest]) (*connect_go.Response[v1alpha.ClientResourcePermission], error)
	ListClientResourcePermissions(context.Context, *connect_go.Request[v1alpha.ListClientResourcePermissionsRequest]) (*connect_go.Response[v1alpha.ListClientResourcePermissionsResponse], error)
}

// NewClientAdminServiceHandler builds an HTTP handler from the service implementation. It returns
// the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewClientAdminServiceHandler(svc ClientAdminServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	clientAdminServiceCreateClientHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceCreateClientProcedure,
		svc.CreateClient,
		opts...,
	)
	clientAdminServiceListClientHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceListClientProcedure,
		svc.ListClient,
		opts...,
	)
	clientAdminServiceGetClientHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceGetClientProcedure,
		svc.GetClient,
		opts...,
	)
	clientAdminServiceUpdateClientHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceUpdateClientProcedure,
		svc.UpdateClient,
		opts...,
	)
	clientAdminServiceDeleteClientHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceDeleteClientProcedure,
		svc.DeleteClient,
		opts...,
	)
	clientAdminServiceCreateClientResourcePermissionHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceCreateClientResourcePermissionProcedure,
		svc.CreateClientResourcePermission,
		opts...,
	)
	clientAdminServiceListClientResourcePermissionsHandler := connect_go.NewUnaryHandler(
		ClientAdminServiceListClientResourcePermissionsProcedure,
		svc.ListClientResourcePermissions,
		opts...,
	)
	return "/blocky.authz.admin.v1alpha.ClientAdminService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case ClientAdminServiceCreateClientProcedure:
			clientAdminServiceCreateClientHandler.ServeHTTP(w, r)
		case ClientAdminServiceListClientProcedure:
			clientAdminServiceListClientHandler.ServeHTTP(w, r)
		case ClientAdminServiceGetClientProcedure:
			clientAdminServiceGetClientHandler.ServeHTTP(w, r)
		case ClientAdminServiceUpdateClientProcedure:
			clientAdminServiceUpdateClientHandler.ServeHTTP(w, r)
		case ClientAdminServiceDeleteClientProcedure:
			clientAdminServiceDeleteClientHandler.ServeHTTP(w, r)
		case ClientAdminServiceCreateClientResourcePermissionProcedure:
			clientAdminServiceCreateClientResourcePermissionHandler.ServeHTTP(w, r)
		case ClientAdminServiceListClientResourcePermissionsProcedure:
			clientAdminServiceListClientResourcePermissionsHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedClientAdminServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedClientAdminServiceHandler struct{}

func (UnimplementedClientAdminServiceHandler) CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.CreateClient is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) ListClient(context.Context, *connect_go.Request[v1alpha.ListClientRequest]) (*connect_go.Response[v1alpha.ListClientResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.ListClient is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.GetClient is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.UpdateClient is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[emptypb.Empty], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.DeleteClient is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) CreateClientResourcePermission(context.Context, *connect_go.Request[v1alpha.CreateClientResourcePermissionRequest]) (*connect_go.Response[v1alpha.ClientResourcePermission], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.CreateClientResourcePermission is not implemented"))
}

func (UnimplementedClientAdminServiceHandler) ListClientResourcePermissions(context.Context, *connect_go.Request[v1alpha.ListClientResourcePermissionsRequest]) (*connect_go.Response[v1alpha.ListClientResourcePermissionsResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientAdminService.ListClientResourcePermissions is not implemented"))
}
