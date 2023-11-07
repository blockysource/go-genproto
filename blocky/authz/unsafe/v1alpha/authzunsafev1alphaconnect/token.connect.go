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
// Source: blocky/authz/unsafe/v1alpha/token.proto

package authzunsafev1alphaconnect

import (
	context "context"
	errors "errors"
	v1alpha "github.com/blockysource/go-genproto/blocky/authz/unsafe/v1alpha"
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
	// TokensServiceName is the fully-qualified name of the TokensService service.
	TokensServiceName = "blocky.authz.unsafe.v1alpha.TokensService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// TokensServiceIssueIDTokenProcedure is the fully-qualified name of the TokensService's
	// IssueIDToken RPC.
	TokensServiceIssueIDTokenProcedure = "/blocky.authz.unsafe.v1alpha.TokensService/IssueIDToken"
	// TokensServiceIssueTokenProcedure is the fully-qualified name of the TokensService's IssueToken
	// RPC.
	TokensServiceIssueTokenProcedure = "/blocky.authz.unsafe.v1alpha.TokensService/IssueToken"
	// TokensServiceRefreshTokenProcedure is the fully-qualified name of the TokensService's
	// RefreshToken RPC.
	TokensServiceRefreshTokenProcedure = "/blocky.authz.unsafe.v1alpha.TokensService/RefreshToken"
	// TokensServiceRevokeRefreshTokenProcedure is the fully-qualified name of the TokensService's
	// RevokeRefreshToken RPC.
	TokensServiceRevokeRefreshTokenProcedure = "/blocky.authz.unsafe.v1alpha.TokensService/RevokeRefreshToken"
	// TokensServiceIntrospectTokenProcedure is the fully-qualified name of the TokensService's
	// IntrospectToken RPC.
	TokensServiceIntrospectTokenProcedure = "/blocky.authz.unsafe.v1alpha.TokensService/IntrospectToken"
)

// TokensServiceClient is a client for the blocky.authz.unsafe.v1alpha.TokensService service.
type TokensServiceClient interface {
	// IssueIDToken issues a new ID token for the input subject.
	IssueIDToken(context.Context, *connect_go.Request[v1alpha.IssueIDTokenRequest]) (*connect_go.Response[v1alpha.IssueIDTokenResponse], error)
	// Issues a new authorization token for the input subject.
	IssueToken(context.Context, *connect_go.Request[v1alpha.IssueTokenRequest]) (*connect_go.Response[v1alpha.IssueTokenResponse], error)
	// Creates a new access, refresh token pair on top of the input refresh token.
	// The input refresh token needs to be non-expired, non-revoked and active.
	// Resulting tokens will share the claims provided during the [IssueTokenRequest].
	RefreshToken(context.Context, *connect_go.Request[v1alpha.RefreshTokenRequest]) (*connect_go.Response[v1alpha.RefreshTokenResponse], error)
	// Revokes the input refresh token.
	// Revoked refresh tokens will not be able to be used to issue new tokens.
	// This makes the refresh token invalid.
	RevokeRefreshToken(context.Context, *connect_go.Request[v1alpha.RevokeRefreshTokenRequest]) (*connect_go.Response[emptypb.Empty], error)
	// Checks if the input token is valid, and if so, returns the claims of the token.
	// If the token is invalid, the response will contain an error.
	IntrospectToken(context.Context, *connect_go.Request[v1alpha.IntrospectTokenRequest]) (*connect_go.Response[v1alpha.IntrospectTokenResponse], error)
}

// NewTokensServiceClient constructs a client for the blocky.authz.unsafe.v1alpha.TokensService
// service. By default, it uses the Connect protocol with the binary Protobuf Codec, asks for
// gzipped responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply
// the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewTokensServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) TokensServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &tokensServiceClient{
		issueIDToken: connect_go.NewClient[v1alpha.IssueIDTokenRequest, v1alpha.IssueIDTokenResponse](
			httpClient,
			baseURL+TokensServiceIssueIDTokenProcedure,
			opts...,
		),
		issueToken: connect_go.NewClient[v1alpha.IssueTokenRequest, v1alpha.IssueTokenResponse](
			httpClient,
			baseURL+TokensServiceIssueTokenProcedure,
			opts...,
		),
		refreshToken: connect_go.NewClient[v1alpha.RefreshTokenRequest, v1alpha.RefreshTokenResponse](
			httpClient,
			baseURL+TokensServiceRefreshTokenProcedure,
			opts...,
		),
		revokeRefreshToken: connect_go.NewClient[v1alpha.RevokeRefreshTokenRequest, emptypb.Empty](
			httpClient,
			baseURL+TokensServiceRevokeRefreshTokenProcedure,
			opts...,
		),
		introspectToken: connect_go.NewClient[v1alpha.IntrospectTokenRequest, v1alpha.IntrospectTokenResponse](
			httpClient,
			baseURL+TokensServiceIntrospectTokenProcedure,
			opts...,
		),
	}
}

// tokensServiceClient implements TokensServiceClient.
type tokensServiceClient struct {
	issueIDToken       *connect_go.Client[v1alpha.IssueIDTokenRequest, v1alpha.IssueIDTokenResponse]
	issueToken         *connect_go.Client[v1alpha.IssueTokenRequest, v1alpha.IssueTokenResponse]
	refreshToken       *connect_go.Client[v1alpha.RefreshTokenRequest, v1alpha.RefreshTokenResponse]
	revokeRefreshToken *connect_go.Client[v1alpha.RevokeRefreshTokenRequest, emptypb.Empty]
	introspectToken    *connect_go.Client[v1alpha.IntrospectTokenRequest, v1alpha.IntrospectTokenResponse]
}

// IssueIDToken calls blocky.authz.unsafe.v1alpha.TokensService.IssueIDToken.
func (c *tokensServiceClient) IssueIDToken(ctx context.Context, req *connect_go.Request[v1alpha.IssueIDTokenRequest]) (*connect_go.Response[v1alpha.IssueIDTokenResponse], error) {
	return c.issueIDToken.CallUnary(ctx, req)
}

// IssueToken calls blocky.authz.unsafe.v1alpha.TokensService.IssueToken.
func (c *tokensServiceClient) IssueToken(ctx context.Context, req *connect_go.Request[v1alpha.IssueTokenRequest]) (*connect_go.Response[v1alpha.IssueTokenResponse], error) {
	return c.issueToken.CallUnary(ctx, req)
}

// RefreshToken calls blocky.authz.unsafe.v1alpha.TokensService.RefreshToken.
func (c *tokensServiceClient) RefreshToken(ctx context.Context, req *connect_go.Request[v1alpha.RefreshTokenRequest]) (*connect_go.Response[v1alpha.RefreshTokenResponse], error) {
	return c.refreshToken.CallUnary(ctx, req)
}

// RevokeRefreshToken calls blocky.authz.unsafe.v1alpha.TokensService.RevokeRefreshToken.
func (c *tokensServiceClient) RevokeRefreshToken(ctx context.Context, req *connect_go.Request[v1alpha.RevokeRefreshTokenRequest]) (*connect_go.Response[emptypb.Empty], error) {
	return c.revokeRefreshToken.CallUnary(ctx, req)
}

// IntrospectToken calls blocky.authz.unsafe.v1alpha.TokensService.IntrospectToken.
func (c *tokensServiceClient) IntrospectToken(ctx context.Context, req *connect_go.Request[v1alpha.IntrospectTokenRequest]) (*connect_go.Response[v1alpha.IntrospectTokenResponse], error) {
	return c.introspectToken.CallUnary(ctx, req)
}

// TokensServiceHandler is an implementation of the blocky.authz.unsafe.v1alpha.TokensService
// service.
type TokensServiceHandler interface {
	// IssueIDToken issues a new ID token for the input subject.
	IssueIDToken(context.Context, *connect_go.Request[v1alpha.IssueIDTokenRequest]) (*connect_go.Response[v1alpha.IssueIDTokenResponse], error)
	// Issues a new authorization token for the input subject.
	IssueToken(context.Context, *connect_go.Request[v1alpha.IssueTokenRequest]) (*connect_go.Response[v1alpha.IssueTokenResponse], error)
	// Creates a new access, refresh token pair on top of the input refresh token.
	// The input refresh token needs to be non-expired, non-revoked and active.
	// Resulting tokens will share the claims provided during the [IssueTokenRequest].
	RefreshToken(context.Context, *connect_go.Request[v1alpha.RefreshTokenRequest]) (*connect_go.Response[v1alpha.RefreshTokenResponse], error)
	// Revokes the input refresh token.
	// Revoked refresh tokens will not be able to be used to issue new tokens.
	// This makes the refresh token invalid.
	RevokeRefreshToken(context.Context, *connect_go.Request[v1alpha.RevokeRefreshTokenRequest]) (*connect_go.Response[emptypb.Empty], error)
	// Checks if the input token is valid, and if so, returns the claims of the token.
	// If the token is invalid, the response will contain an error.
	IntrospectToken(context.Context, *connect_go.Request[v1alpha.IntrospectTokenRequest]) (*connect_go.Response[v1alpha.IntrospectTokenResponse], error)
}

// NewTokensServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewTokensServiceHandler(svc TokensServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	tokensServiceIssueIDTokenHandler := connect_go.NewUnaryHandler(
		TokensServiceIssueIDTokenProcedure,
		svc.IssueIDToken,
		opts...,
	)
	tokensServiceIssueTokenHandler := connect_go.NewUnaryHandler(
		TokensServiceIssueTokenProcedure,
		svc.IssueToken,
		opts...,
	)
	tokensServiceRefreshTokenHandler := connect_go.NewUnaryHandler(
		TokensServiceRefreshTokenProcedure,
		svc.RefreshToken,
		opts...,
	)
	tokensServiceRevokeRefreshTokenHandler := connect_go.NewUnaryHandler(
		TokensServiceRevokeRefreshTokenProcedure,
		svc.RevokeRefreshToken,
		opts...,
	)
	tokensServiceIntrospectTokenHandler := connect_go.NewUnaryHandler(
		TokensServiceIntrospectTokenProcedure,
		svc.IntrospectToken,
		opts...,
	)
	return "/blocky.authz.unsafe.v1alpha.TokensService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case TokensServiceIssueIDTokenProcedure:
			tokensServiceIssueIDTokenHandler.ServeHTTP(w, r)
		case TokensServiceIssueTokenProcedure:
			tokensServiceIssueTokenHandler.ServeHTTP(w, r)
		case TokensServiceRefreshTokenProcedure:
			tokensServiceRefreshTokenHandler.ServeHTTP(w, r)
		case TokensServiceRevokeRefreshTokenProcedure:
			tokensServiceRevokeRefreshTokenHandler.ServeHTTP(w, r)
		case TokensServiceIntrospectTokenProcedure:
			tokensServiceIntrospectTokenHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedTokensServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedTokensServiceHandler struct{}

func (UnimplementedTokensServiceHandler) IssueIDToken(context.Context, *connect_go.Request[v1alpha.IssueIDTokenRequest]) (*connect_go.Response[v1alpha.IssueIDTokenResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.unsafe.v1alpha.TokensService.IssueIDToken is not implemented"))
}

func (UnimplementedTokensServiceHandler) IssueToken(context.Context, *connect_go.Request[v1alpha.IssueTokenRequest]) (*connect_go.Response[v1alpha.IssueTokenResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.unsafe.v1alpha.TokensService.IssueToken is not implemented"))
}

func (UnimplementedTokensServiceHandler) RefreshToken(context.Context, *connect_go.Request[v1alpha.RefreshTokenRequest]) (*connect_go.Response[v1alpha.RefreshTokenResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.unsafe.v1alpha.TokensService.RefreshToken is not implemented"))
}

func (UnimplementedTokensServiceHandler) RevokeRefreshToken(context.Context, *connect_go.Request[v1alpha.RevokeRefreshTokenRequest]) (*connect_go.Response[emptypb.Empty], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.unsafe.v1alpha.TokensService.RevokeRefreshToken is not implemented"))
}

func (UnimplementedTokensServiceHandler) IntrospectToken(context.Context, *connect_go.Request[v1alpha.IntrospectTokenRequest]) (*connect_go.Response[v1alpha.IntrospectTokenResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("blocky.authz.unsafe.v1alpha.TokensService.IntrospectToken is not implemented"))
}