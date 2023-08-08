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
// source: blocky/authz/secure/v1alpha/signatures.proto

package authzsecurev1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SignaturesService_SignClaims_FullMethodName          = "/blocky.authz.secure.v1alpha.SignaturesService/SignClaims"
	SignaturesService_IntrospectSignature_FullMethodName = "/blocky.authz.secure.v1alpha.SignaturesService/IntrospectSignature"
)

// SignaturesServiceClient is the client API for SignaturesService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SignaturesServiceClient interface {
	// Signs the input payload and returns a signed string token.
	// The result is a Json Web Signature (JWS) as defined in RFC 7515.
	SignClaims(ctx context.Context, in *SignClaimsRequest, opts ...grpc.CallOption) (*SignClaimsResponse, error)
	// Introspects the signature and returns the claims.
	// Once the signature is verified, the claims are returned as a Struct.
	IntrospectSignature(ctx context.Context, in *IntrospectSignatureRequest, opts ...grpc.CallOption) (*IntrospectSignatureResponse, error)
}

type signaturesServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSignaturesServiceClient(cc grpc.ClientConnInterface) SignaturesServiceClient {
	return &signaturesServiceClient{cc}
}

func (c *signaturesServiceClient) SignClaims(ctx context.Context, in *SignClaimsRequest, opts ...grpc.CallOption) (*SignClaimsResponse, error) {
	out := new(SignClaimsResponse)
	err := c.cc.Invoke(ctx, SignaturesService_SignClaims_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *signaturesServiceClient) IntrospectSignature(ctx context.Context, in *IntrospectSignatureRequest, opts ...grpc.CallOption) (*IntrospectSignatureResponse, error) {
	out := new(IntrospectSignatureResponse)
	err := c.cc.Invoke(ctx, SignaturesService_IntrospectSignature_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignaturesServiceServer is the server API for SignaturesService service.
// All implementations must embed UnimplementedSignaturesServiceServer
// for forward compatibility
type SignaturesServiceServer interface {
	// Signs the input payload and returns a signed string token.
	// The result is a Json Web Signature (JWS) as defined in RFC 7515.
	SignClaims(context.Context, *SignClaimsRequest) (*SignClaimsResponse, error)
	// Introspects the signature and returns the claims.
	// Once the signature is verified, the claims are returned as a Struct.
	IntrospectSignature(context.Context, *IntrospectSignatureRequest) (*IntrospectSignatureResponse, error)
	mustEmbedUnimplementedSignaturesServiceServer()
}

// UnimplementedSignaturesServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSignaturesServiceServer struct {
}

func (UnimplementedSignaturesServiceServer) SignClaims(context.Context, *SignClaimsRequest) (*SignClaimsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignClaims not implemented")
}
func (UnimplementedSignaturesServiceServer) IntrospectSignature(context.Context, *IntrospectSignatureRequest) (*IntrospectSignatureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IntrospectSignature not implemented")
}
func (UnimplementedSignaturesServiceServer) mustEmbedUnimplementedSignaturesServiceServer() {}

// UnsafeSignaturesServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SignaturesServiceServer will
// result in compilation errors.
type UnsafeSignaturesServiceServer interface {
	mustEmbedUnimplementedSignaturesServiceServer()
}

func RegisterSignaturesServiceServer(s grpc.ServiceRegistrar, srv SignaturesServiceServer) {
	s.RegisterService(&SignaturesService_ServiceDesc, srv)
}

func _SignaturesService_SignClaims_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignClaimsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignaturesServiceServer).SignClaims(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SignaturesService_SignClaims_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignaturesServiceServer).SignClaims(ctx, req.(*SignClaimsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SignaturesService_IntrospectSignature_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IntrospectSignatureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignaturesServiceServer).IntrospectSignature(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SignaturesService_IntrospectSignature_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignaturesServiceServer).IntrospectSignature(ctx, req.(*IntrospectSignatureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SignaturesService_ServiceDesc is the grpc.ServiceDesc for SignaturesService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SignaturesService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.secure.v1alpha.SignaturesService",
	HandlerType: (*SignaturesServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignClaims",
			Handler:    _SignaturesService_SignClaims_Handler,
		},
		{
			MethodName: "IntrospectSignature",
			Handler:    _SignaturesService_IntrospectSignature_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/secure/v1alpha/signatures.proto",
}