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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: blocky/authz/unsafe/v1alpha/token.proto

package authzunsafev1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	TokensService_IssueIDToken_FullMethodName       = "/blocky.authz.unsafe.v1alpha.TokensService/IssueIDToken"
	TokensService_IssueToken_FullMethodName         = "/blocky.authz.unsafe.v1alpha.TokensService/IssueToken"
	TokensService_RefreshToken_FullMethodName       = "/blocky.authz.unsafe.v1alpha.TokensService/RefreshToken"
	TokensService_RevokeRefreshToken_FullMethodName = "/blocky.authz.unsafe.v1alpha.TokensService/RevokeRefreshToken"
	TokensService_IntrospectToken_FullMethodName    = "/blocky.authz.unsafe.v1alpha.TokensService/IntrospectToken"
)

// TokensServiceClient is the client API for TokensService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TokensServiceClient interface {
	// IssueIDToken issues a new ID token for the input subject.
	IssueIDToken(ctx context.Context, in *IssueIDTokenRequest, opts ...grpc.CallOption) (*IssueIDTokenResponse, error)
	// Issues a new authorization token for the input subject.
	IssueToken(ctx context.Context, in *IssueTokenRequest, opts ...grpc.CallOption) (*IssueTokenResponse, error)
	// Creates a new access, refresh token pair on top of the input refresh token.
	// The input refresh token needs to be non-expired, non-revoked and active.
	// Resulting tokens will share the claims provided during the [IssueTokenRequest].
	RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error)
	// Revokes the input refresh token.
	// Revoked refresh tokens will not be able to be used to issue new tokens.
	// This makes the refresh token invalid.
	RevokeRefreshToken(ctx context.Context, in *RevokeRefreshTokenRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// Checks if the input token is valid, and if so, returns the claims of the token.
	// If the token is invalid, the response will contain an error.
	IntrospectToken(ctx context.Context, in *IntrospectTokenRequest, opts ...grpc.CallOption) (*IntrospectTokenResponse, error)
}

type tokensServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTokensServiceClient(cc grpc.ClientConnInterface) TokensServiceClient {
	return &tokensServiceClient{cc}
}

func (c *tokensServiceClient) IssueIDToken(ctx context.Context, in *IssueIDTokenRequest, opts ...grpc.CallOption) (*IssueIDTokenResponse, error) {
	out := new(IssueIDTokenResponse)
	err := c.cc.Invoke(ctx, TokensService_IssueIDToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensServiceClient) IssueToken(ctx context.Context, in *IssueTokenRequest, opts ...grpc.CallOption) (*IssueTokenResponse, error) {
	out := new(IssueTokenResponse)
	err := c.cc.Invoke(ctx, TokensService_IssueToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensServiceClient) RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error) {
	out := new(RefreshTokenResponse)
	err := c.cc.Invoke(ctx, TokensService_RefreshToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensServiceClient) RevokeRefreshToken(ctx context.Context, in *RevokeRefreshTokenRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, TokensService_RevokeRefreshToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensServiceClient) IntrospectToken(ctx context.Context, in *IntrospectTokenRequest, opts ...grpc.CallOption) (*IntrospectTokenResponse, error) {
	out := new(IntrospectTokenResponse)
	err := c.cc.Invoke(ctx, TokensService_IntrospectToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TokensServiceServer is the server API for TokensService service.
// All implementations must embed UnimplementedTokensServiceServer
// for forward compatibility
type TokensServiceServer interface {
	// IssueIDToken issues a new ID token for the input subject.
	IssueIDToken(context.Context, *IssueIDTokenRequest) (*IssueIDTokenResponse, error)
	// Issues a new authorization token for the input subject.
	IssueToken(context.Context, *IssueTokenRequest) (*IssueTokenResponse, error)
	// Creates a new access, refresh token pair on top of the input refresh token.
	// The input refresh token needs to be non-expired, non-revoked and active.
	// Resulting tokens will share the claims provided during the [IssueTokenRequest].
	RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error)
	// Revokes the input refresh token.
	// Revoked refresh tokens will not be able to be used to issue new tokens.
	// This makes the refresh token invalid.
	RevokeRefreshToken(context.Context, *RevokeRefreshTokenRequest) (*emptypb.Empty, error)
	// Checks if the input token is valid, and if so, returns the claims of the token.
	// If the token is invalid, the response will contain an error.
	IntrospectToken(context.Context, *IntrospectTokenRequest) (*IntrospectTokenResponse, error)
	mustEmbedUnimplementedTokensServiceServer()
}

// UnimplementedTokensServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTokensServiceServer struct {
}

func (UnimplementedTokensServiceServer) IssueIDToken(context.Context, *IssueIDTokenRequest) (*IssueIDTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IssueIDToken not implemented")
}
func (UnimplementedTokensServiceServer) IssueToken(context.Context, *IssueTokenRequest) (*IssueTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IssueToken not implemented")
}
func (UnimplementedTokensServiceServer) RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedTokensServiceServer) RevokeRefreshToken(context.Context, *RevokeRefreshTokenRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeRefreshToken not implemented")
}
func (UnimplementedTokensServiceServer) IntrospectToken(context.Context, *IntrospectTokenRequest) (*IntrospectTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IntrospectToken not implemented")
}
func (UnimplementedTokensServiceServer) mustEmbedUnimplementedTokensServiceServer() {}

// UnsafeTokensServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TokensServiceServer will
// result in compilation errors.
type UnsafeTokensServiceServer interface {
	mustEmbedUnimplementedTokensServiceServer()
}

func RegisterTokensServiceServer(s grpc.ServiceRegistrar, srv TokensServiceServer) {
	s.RegisterService(&TokensService_ServiceDesc, srv)
}

func _TokensService_IssueIDToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueIDTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServiceServer).IssueIDToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TokensService_IssueIDToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServiceServer).IssueIDToken(ctx, req.(*IssueIDTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokensService_IssueToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServiceServer).IssueToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TokensService_IssueToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServiceServer).IssueToken(ctx, req.(*IssueTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokensService_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServiceServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TokensService_RefreshToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServiceServer).RefreshToken(ctx, req.(*RefreshTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokensService_RevokeRefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeRefreshTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServiceServer).RevokeRefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TokensService_RevokeRefreshToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServiceServer).RevokeRefreshToken(ctx, req.(*RevokeRefreshTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokensService_IntrospectToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IntrospectTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServiceServer).IntrospectToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TokensService_IntrospectToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServiceServer).IntrospectToken(ctx, req.(*IntrospectTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TokensService_ServiceDesc is the grpc.ServiceDesc for TokensService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TokensService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.unsafe.v1alpha.TokensService",
	HandlerType: (*TokensServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IssueIDToken",
			Handler:    _TokensService_IssueIDToken_Handler,
		},
		{
			MethodName: "IssueToken",
			Handler:    _TokensService_IssueToken_Handler,
		},
		{
			MethodName: "RefreshToken",
			Handler:    _TokensService_RefreshToken_Handler,
		},
		{
			MethodName: "RevokeRefreshToken",
			Handler:    _TokensService_RevokeRefreshToken_Handler,
		},
		{
			MethodName: "IntrospectToken",
			Handler:    _TokensService_IntrospectToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/unsafe/v1alpha/token.proto",
}