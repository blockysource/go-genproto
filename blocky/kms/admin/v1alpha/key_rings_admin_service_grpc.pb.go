// Copyright 2024 The Blocky Authors
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
// source: blocky/kms/admin/v1alpha/key_rings_admin_service.proto

package kmsadminpb

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
	KeyRingsAdminService_CreateKeyRing_FullMethodName = "/blocky.kms.admin.v1alpha.KeyRingsAdminService/CreateKeyRing"
	KeyRingsAdminService_ListKeyRings_FullMethodName  = "/blocky.kms.admin.v1alpha.KeyRingsAdminService/ListKeyRings"
	KeyRingsAdminService_GetKeyRing_FullMethodName    = "/blocky.kms.admin.v1alpha.KeyRingsAdminService/GetKeyRing"
	KeyRingsAdminService_UpdateKeyRing_FullMethodName = "/blocky.kms.admin.v1alpha.KeyRingsAdminService/UpdateKeyRing"
	KeyRingsAdminService_DeleteKeyRing_FullMethodName = "/blocky.kms.admin.v1alpha.KeyRingsAdminService/DeleteKeyRing"
)

// KeyRingsAdminServiceClient is the client API for KeyRingsAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KeyRingsAdminServiceClient interface {
	// Create a new key ring.
	CreateKeyRing(ctx context.Context, in *CreateKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error)
	// List key rings.
	ListKeyRings(ctx context.Context, in *ListKeyRingsRequest, opts ...grpc.CallOption) (*ListKeyRingsResponse, error)
	// Get key ring.
	GetKeyRing(ctx context.Context, in *GetKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error)
	// Update key ring.
	UpdateKeyRing(ctx context.Context, in *UpdateKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error)
	// Delete key ring.
	DeleteKeyRing(ctx context.Context, in *DeleteKeyRingRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type keyRingsAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyRingsAdminServiceClient(cc grpc.ClientConnInterface) KeyRingsAdminServiceClient {
	return &keyRingsAdminServiceClient{cc}
}

func (c *keyRingsAdminServiceClient) CreateKeyRing(ctx context.Context, in *CreateKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error) {
	out := new(KeyRing)
	err := c.cc.Invoke(ctx, KeyRingsAdminService_CreateKeyRing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyRingsAdminServiceClient) ListKeyRings(ctx context.Context, in *ListKeyRingsRequest, opts ...grpc.CallOption) (*ListKeyRingsResponse, error) {
	out := new(ListKeyRingsResponse)
	err := c.cc.Invoke(ctx, KeyRingsAdminService_ListKeyRings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyRingsAdminServiceClient) GetKeyRing(ctx context.Context, in *GetKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error) {
	out := new(KeyRing)
	err := c.cc.Invoke(ctx, KeyRingsAdminService_GetKeyRing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyRingsAdminServiceClient) UpdateKeyRing(ctx context.Context, in *UpdateKeyRingRequest, opts ...grpc.CallOption) (*KeyRing, error) {
	out := new(KeyRing)
	err := c.cc.Invoke(ctx, KeyRingsAdminService_UpdateKeyRing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyRingsAdminServiceClient) DeleteKeyRing(ctx context.Context, in *DeleteKeyRingRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, KeyRingsAdminService_DeleteKeyRing_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyRingsAdminServiceServer is the server API for KeyRingsAdminService service.
// All implementations must embed UnimplementedKeyRingsAdminServiceServer
// for forward compatibility
type KeyRingsAdminServiceServer interface {
	// Create a new key ring.
	CreateKeyRing(context.Context, *CreateKeyRingRequest) (*KeyRing, error)
	// List key rings.
	ListKeyRings(context.Context, *ListKeyRingsRequest) (*ListKeyRingsResponse, error)
	// Get key ring.
	GetKeyRing(context.Context, *GetKeyRingRequest) (*KeyRing, error)
	// Update key ring.
	UpdateKeyRing(context.Context, *UpdateKeyRingRequest) (*KeyRing, error)
	// Delete key ring.
	DeleteKeyRing(context.Context, *DeleteKeyRingRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedKeyRingsAdminServiceServer()
}

// UnimplementedKeyRingsAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedKeyRingsAdminServiceServer struct {
}

func (UnimplementedKeyRingsAdminServiceServer) CreateKeyRing(context.Context, *CreateKeyRingRequest) (*KeyRing, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKeyRing not implemented")
}
func (UnimplementedKeyRingsAdminServiceServer) ListKeyRings(context.Context, *ListKeyRingsRequest) (*ListKeyRingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListKeyRings not implemented")
}
func (UnimplementedKeyRingsAdminServiceServer) GetKeyRing(context.Context, *GetKeyRingRequest) (*KeyRing, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKeyRing not implemented")
}
func (UnimplementedKeyRingsAdminServiceServer) UpdateKeyRing(context.Context, *UpdateKeyRingRequest) (*KeyRing, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateKeyRing not implemented")
}
func (UnimplementedKeyRingsAdminServiceServer) DeleteKeyRing(context.Context, *DeleteKeyRingRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteKeyRing not implemented")
}
func (UnimplementedKeyRingsAdminServiceServer) mustEmbedUnimplementedKeyRingsAdminServiceServer() {}

// UnsafeKeyRingsAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeyRingsAdminServiceServer will
// result in compilation errors.
type UnsafeKeyRingsAdminServiceServer interface {
	mustEmbedUnimplementedKeyRingsAdminServiceServer()
}

func RegisterKeyRingsAdminServiceServer(s grpc.ServiceRegistrar, srv KeyRingsAdminServiceServer) {
	s.RegisterService(&KeyRingsAdminService_ServiceDesc, srv)
}

func _KeyRingsAdminService_CreateKeyRing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyRingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyRingsAdminServiceServer).CreateKeyRing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyRingsAdminService_CreateKeyRing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyRingsAdminServiceServer).CreateKeyRing(ctx, req.(*CreateKeyRingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyRingsAdminService_ListKeyRings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListKeyRingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyRingsAdminServiceServer).ListKeyRings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyRingsAdminService_ListKeyRings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyRingsAdminServiceServer).ListKeyRings(ctx, req.(*ListKeyRingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyRingsAdminService_GetKeyRing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyRingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyRingsAdminServiceServer).GetKeyRing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyRingsAdminService_GetKeyRing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyRingsAdminServiceServer).GetKeyRing(ctx, req.(*GetKeyRingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyRingsAdminService_UpdateKeyRing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateKeyRingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyRingsAdminServiceServer).UpdateKeyRing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyRingsAdminService_UpdateKeyRing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyRingsAdminServiceServer).UpdateKeyRing(ctx, req.(*UpdateKeyRingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyRingsAdminService_DeleteKeyRing_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteKeyRingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyRingsAdminServiceServer).DeleteKeyRing(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyRingsAdminService_DeleteKeyRing_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyRingsAdminServiceServer).DeleteKeyRing(ctx, req.(*DeleteKeyRingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KeyRingsAdminService_ServiceDesc is the grpc.ServiceDesc for KeyRingsAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeyRingsAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.kms.admin.v1alpha.KeyRingsAdminService",
	HandlerType: (*KeyRingsAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKeyRing",
			Handler:    _KeyRingsAdminService_CreateKeyRing_Handler,
		},
		{
			MethodName: "ListKeyRings",
			Handler:    _KeyRingsAdminService_ListKeyRings_Handler,
		},
		{
			MethodName: "GetKeyRing",
			Handler:    _KeyRingsAdminService_GetKeyRing_Handler,
		},
		{
			MethodName: "UpdateKeyRing",
			Handler:    _KeyRingsAdminService_UpdateKeyRing_Handler,
		},
		{
			MethodName: "DeleteKeyRing",
			Handler:    _KeyRingsAdminService_DeleteKeyRing_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/kms/admin/v1alpha/key_rings_admin_service.proto",
}
