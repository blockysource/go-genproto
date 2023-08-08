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
// source: blocky/authz/v1alpha/keys.proto

package authzv1alpha

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
	KeysService_GetPublicKeys_FullMethodName = "/blocky.authz.v1alpha.KeysService/GetPublicKeys"
)

// KeysServiceClient is the client API for KeysService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KeysServiceClient interface {
	// Returns the public keys used to verify tokens and signatures.
	// The keys are returned in the JWK format as defined in RFC 7517.
	// The order of the keys determines the order in which they are used.
	GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest, opts ...grpc.CallOption) (*GetPublicKeysResponse, error)
}

type keysServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeysServiceClient(cc grpc.ClientConnInterface) KeysServiceClient {
	return &keysServiceClient{cc}
}

func (c *keysServiceClient) GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest, opts ...grpc.CallOption) (*GetPublicKeysResponse, error) {
	out := new(GetPublicKeysResponse)
	err := c.cc.Invoke(ctx, KeysService_GetPublicKeys_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeysServiceServer is the server API for KeysService service.
// All implementations must embed UnimplementedKeysServiceServer
// for forward compatibility
type KeysServiceServer interface {
	// Returns the public keys used to verify tokens and signatures.
	// The keys are returned in the JWK format as defined in RFC 7517.
	// The order of the keys determines the order in which they are used.
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	mustEmbedUnimplementedKeysServiceServer()
}

// UnimplementedKeysServiceServer must be embedded to have forward compatible implementations.
type UnimplementedKeysServiceServer struct {
}

func (UnimplementedKeysServiceServer) GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPublicKeys not implemented")
}
func (UnimplementedKeysServiceServer) mustEmbedUnimplementedKeysServiceServer() {}

// UnsafeKeysServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeysServiceServer will
// result in compilation errors.
type UnsafeKeysServiceServer interface {
	mustEmbedUnimplementedKeysServiceServer()
}

func RegisterKeysServiceServer(s grpc.ServiceRegistrar, srv KeysServiceServer) {
	s.RegisterService(&KeysService_ServiceDesc, srv)
}

func _KeysService_GetPublicKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPublicKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeysServiceServer).GetPublicKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeysService_GetPublicKeys_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeysServiceServer).GetPublicKeys(ctx, req.(*GetPublicKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KeysService_ServiceDesc is the grpc.ServiceDesc for KeysService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeysService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.v1alpha.KeysService",
	HandlerType: (*KeysServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPublicKeys",
			Handler:    _KeysService_GetPublicKeys_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/v1alpha/keys.proto",
}
