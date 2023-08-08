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
// Source: blocky/authz/admin/v1alpha/admin_clients.proto

package authzadminv1alphaconnect

import (
	context "context"
	errors "errors"
	v1alpha "github.com/blockysource/go-genproto/blocky/authz/admin/v1alpha"
	connect_go "github.com/bufbuild/connect-go"
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
	// ClientsAdminServiceName is the fully-qualified name of the ClientsAdminService service.
	ClientsAdminServiceName = "blocky.authz.admin.v1alpha.ClientsAdminService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// ClientsAdminServiceCreateClientProcedure is the fully-qualified name of the ClientsAdminService's
	// CreateClient RPC.
	ClientsAdminServiceCreateClientProcedure = "/blocky.authz.admin.v1alpha.ClientsAdminService/CreateClient"
	// ClientsAdminServiceListClientsProcedure is the fully-qualified name of the ClientsAdminService's
	// ListClients RPC.
	ClientsAdminServiceListClientsProcedure = "/blocky.authz.admin.v1alpha.ClientsAdminService/ListClients"
	// ClientsAdminServiceGetClientProcedure is the fully-qualified name of the ClientsAdminService's
	// GetClient RPC.
	ClientsAdminServiceGetClientProcedure = "/blocky.authz.admin.v1alpha.ClientsAdminService/GetClient"
	// ClientsAdminServiceUpdateClientProcedure is the fully-qualified name of the ClientsAdminService's
	// UpdateClient RPC.
	ClientsAdminServiceUpdateClientProcedure = "/blocky.authz.admin.v1alpha.ClientsAdminService/UpdateClient"
	// ClientsAdminServiceDeleteClientProcedure is the fully-qualified name of the ClientsAdminService's
	// DeleteClient RPC.
	ClientsAdminServiceDeleteClientProcedure = "/blocky.authz.admin.v1alpha.ClientsAdminService/DeleteClient"
)

// ClientsAdminServiceClient is a client for the blocky.authz.admin.v1alpha.ClientsAdminService
// service.
type ClientsAdminServiceClient interface {
	// Creates a new authorization client with the specified name,
	// and returns the new client.
	// A newly created client will have a secret generated.
	CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Lists authorization clients matching the specified filter.
	ListClients(context.Context, *connect_go.Request[v1alpha.ListClientsRequest]) (*connect_go.Response[v1alpha.ListClientsResponse], error)
	// Gets an authorization client by its identifier.
	GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Updates an authorization client, and returns the updated client.
	UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Deletes an authorization client.
	DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[v1alpha.Client], error)
}

// NewClientsAdminServiceClient constructs a client for the
// blocky.authz.admin.v1alpha.ClientsAdminService service. By default, it uses the Connect protocol
// with the binary Protobuf Codec, asks for gzipped responses, and sends uncompressed requests. To
// use the gRPC or gRPC-Web protocols, supply the connect.WithGRPC() or connect.WithGRPCWeb()
// options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewClientsAdminServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) ClientsAdminServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &clientsAdminServiceClient{
		createClient: connect_go.NewClient[v1alpha.CreateClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientsAdminServiceCreateClientProcedure,
			opts...,
		),
		listClients: connect_go.NewClient[v1alpha.ListClientsRequest, v1alpha.ListClientsResponse](
			httpClient,
			baseURL+ClientsAdminServiceListClientsProcedure,
			opts...,
		),
		getClient: connect_go.NewClient[v1alpha.GetClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientsAdminServiceGetClientProcedure,
			opts...,
		),
		updateClient: connect_go.NewClient[v1alpha.UpdateClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientsAdminServiceUpdateClientProcedure,
			opts...,
		),
		deleteClient: connect_go.NewClient[v1alpha.DeleteClientRequest, v1alpha.Client](
			httpClient,
			baseURL+ClientsAdminServiceDeleteClientProcedure,
			opts...,
		),
	}
}

// clientsAdminServiceClient implements ClientsAdminServiceClient.
type clientsAdminServiceClient struct {
	createClient *connect_go.Client[v1alpha.CreateClientRequest, v1alpha.Client]
	listClients  *connect_go.Client[v1alpha.ListClientsRequest, v1alpha.ListClientsResponse]
	getClient    *connect_go.Client[v1alpha.GetClientRequest, v1alpha.Client]
	updateClient *connect_go.Client[v1alpha.UpdateClientRequest, v1alpha.Client]
	deleteClient *connect_go.Client[v1alpha.DeleteClientRequest, v1alpha.Client]
}

// CreateClient calls blocky.authz.admin.v1alpha.ClientsAdminService.CreateClient.
func (c *clientsAdminServiceClient) CreateClient(ctx context.Context, req *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.createClient.CallUnary(ctx, req)
}

// ListClients calls blocky.authz.admin.v1alpha.ClientsAdminService.ListClients.
func (c *clientsAdminServiceClient) ListClients(ctx context.Context, req *connect_go.Request[v1alpha.ListClientsRequest]) (*connect_go.Response[v1alpha.ListClientsResponse], error) {
	return c.listClients.CallUnary(ctx, req)
}

// GetClient calls blocky.authz.admin.v1alpha.ClientsAdminService.GetClient.
func (c *clientsAdminServiceClient) GetClient(ctx context.Context, req *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.getClient.CallUnary(ctx, req)
}

// UpdateClient calls blocky.authz.admin.v1alpha.ClientsAdminService.UpdateClient.
func (c *clientsAdminServiceClient) UpdateClient(ctx context.Context, req *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.updateClient.CallUnary(ctx, req)
}

// DeleteClient calls blocky.authz.admin.v1alpha.ClientsAdminService.DeleteClient.
func (c *clientsAdminServiceClient) DeleteClient(ctx context.Context, req *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return c.deleteClient.CallUnary(ctx, req)
}

// ClientsAdminServiceHandler is an implementation of the
// blocky.authz.admin.v1alpha.ClientsAdminService service.
type ClientsAdminServiceHandler interface {
	// Creates a new authorization client with the specified name,
	// and returns the new client.
	// A newly created client will have a secret generated.
	CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Lists authorization clients matching the specified filter.
	ListClients(context.Context, *connect_go.Request[v1alpha.ListClientsRequest]) (*connect_go.Response[v1alpha.ListClientsResponse], error)
	// Gets an authorization client by its identifier.
	GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Updates an authorization client, and returns the updated client.
	UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error)
	// Deletes an authorization client.
	DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[v1alpha.Client], error)
}

// NewClientsAdminServiceHandler builds an HTTP handler from the service implementation. It returns
// the path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewClientsAdminServiceHandler(svc ClientsAdminServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	clientsAdminServiceCreateClientHandler := connect_go.NewUnaryHandler(
		ClientsAdminServiceCreateClientProcedure,
		svc.CreateClient,
		opts...,
	)
	clientsAdminServiceListClientsHandler := connect_go.NewUnaryHandler(
		ClientsAdminServiceListClientsProcedure,
		svc.ListClients,
		opts...,
	)
	clientsAdminServiceGetClientHandler := connect_go.NewUnaryHandler(
		ClientsAdminServiceGetClientProcedure,
		svc.GetClient,
		opts...,
	)
	clientsAdminServiceUpdateClientHandler := connect_go.NewUnaryHandler(
		ClientsAdminServiceUpdateClientProcedure,
		svc.UpdateClient,
		opts...,
	)
	clientsAdminServiceDeleteClientHandler := connect_go.NewUnaryHandler(
		ClientsAdminServiceDeleteClientProcedure,
		svc.DeleteClient,
		opts...,
	)
	return "/blocky.authz.admin.v1alpha.ClientsAdminService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case ClientsAdminServiceCreateClientProcedure:
			clientsAdminServiceCreateClientHandler.ServeHTTP(w, r)
		case ClientsAdminServiceListClientsProcedure:
			clientsAdminServiceListClientsHandler.ServeHTTP(w, r)
		case ClientsAdminServiceGetClientProcedure:
			clientsAdminServiceGetClientHandler.ServeHTTP(w, r)
		case ClientsAdminServiceUpdateClientProcedure:
			clientsAdminServiceUpdateClientHandler.ServeHTTP(w, r)
		case ClientsAdminServiceDeleteClientProcedure:
			clientsAdminServiceDeleteClientHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedClientsAdminServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedClientsAdminServiceHandler struct{}

func (UnimplementedClientsAdminServiceHandler) CreateClient(context.Context, *connect_go.Request[v1alpha.CreateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientsAdminService.CreateClient is not implemented"))
}

func (UnimplementedClientsAdminServiceHandler) ListClients(context.Context, *connect_go.Request[v1alpha.ListClientsRequest]) (*connect_go.Response[v1alpha.ListClientsResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientsAdminService.ListClients is not implemented"))
}

func (UnimplementedClientsAdminServiceHandler) GetClient(context.Context, *connect_go.Request[v1alpha.GetClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientsAdminService.GetClient is not implemented"))
}

func (UnimplementedClientsAdminServiceHandler) UpdateClient(context.Context, *connect_go.Request[v1alpha.UpdateClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientsAdminService.UpdateClient is not implemented"))
}

func (UnimplementedClientsAdminServiceHandler) DeleteClient(context.Context, *connect_go.Request[v1alpha.DeleteClientRequest]) (*connect_go.Response[v1alpha.Client], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.admin.v1alpha.ClientsAdminService.DeleteClient is not implemented"))
}