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
// Source: blocky/authz/v1alpha/keys.proto

package authzv1alphaconnect

import (
	context "context"
	errors "errors"
	v1alpha "github.com/blockysource/go-genproto/blocky/authz/v1alpha"
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
	// KeysServiceName is the fully-qualified name of the KeysService service.
	KeysServiceName = "blocky.authz.v1alpha.KeysService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// KeysServiceGetPublicKeysProcedure is the fully-qualified name of the KeysService's GetPublicKeys
	// RPC.
	KeysServiceGetPublicKeysProcedure = "/blocky.authz.v1alpha.KeysService/GetPublicKeys"
)

// KeysServiceClient is a client for the blocky.authz.v1alpha.KeysService service.
type KeysServiceClient interface {
	// Returns the public keys used to verify tokens and signatures.
	// The keys are returned in the JWK format as defined in RFC 7517.
	// The order of the keys determines the order in which they are used.
	GetPublicKeys(context.Context, *connect_go.Request[v1alpha.GetPublicKeysRequest]) (*connect_go.Response[v1alpha.GetPublicKeysResponse], error)
}

// NewKeysServiceClient constructs a client for the blocky.authz.v1alpha.KeysService service. By
// default, it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped responses,
// and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the
// connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewKeysServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) KeysServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &keysServiceClient{
		getPublicKeys: connect_go.NewClient[v1alpha.GetPublicKeysRequest, v1alpha.GetPublicKeysResponse](
			httpClient,
			baseURL+KeysServiceGetPublicKeysProcedure,
			opts...,
		),
	}
}

// keysServiceClient implements KeysServiceClient.
type keysServiceClient struct {
	getPublicKeys *connect_go.Client[v1alpha.GetPublicKeysRequest, v1alpha.GetPublicKeysResponse]
}

// GetPublicKeys calls blocky.authz.v1alpha.KeysService.GetPublicKeys.
func (c *keysServiceClient) GetPublicKeys(ctx context.Context, req *connect_go.Request[v1alpha.GetPublicKeysRequest]) (*connect_go.Response[v1alpha.GetPublicKeysResponse], error) {
	return c.getPublicKeys.CallUnary(ctx, req)
}

// KeysServiceHandler is an implementation of the blocky.authz.v1alpha.KeysService service.
type KeysServiceHandler interface {
	// Returns the public keys used to verify tokens and signatures.
	// The keys are returned in the JWK format as defined in RFC 7517.
	// The order of the keys determines the order in which they are used.
	GetPublicKeys(context.Context, *connect_go.Request[v1alpha.GetPublicKeysRequest]) (*connect_go.Response[v1alpha.GetPublicKeysResponse], error)
}

// NewKeysServiceHandler builds an HTTP handler from the service implementation. It returns the path
// on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewKeysServiceHandler(svc KeysServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	keysServiceGetPublicKeysHandler := connect_go.NewUnaryHandler(
		KeysServiceGetPublicKeysProcedure,
		svc.GetPublicKeys,
		opts...,
	)
	return "/blocky.authz.v1alpha.KeysService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case KeysServiceGetPublicKeysProcedure:
			keysServiceGetPublicKeysHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedKeysServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedKeysServiceHandler struct{}

func (UnimplementedKeysServiceHandler) GetPublicKeys(context.Context, *connect_go.Request[v1alpha.GetPublicKeysRequest]) (*connect_go.Response[v1alpha.GetPublicKeysResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.v1alpha.KeysService.GetPublicKeys is not implemented"))
}
