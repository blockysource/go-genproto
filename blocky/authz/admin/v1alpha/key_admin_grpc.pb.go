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
// source: blocky/authz/admin/v1alpha/key_admin.proto

package authzadminv1alpha

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
	KeyAdminService_CreateKeyCore_FullMethodName   = "/blocky.authz.admin.v1alpha.KeyAdminService/CreateKeyCore"
	KeyAdminService_GetKeyCore_FullMethodName      = "/blocky.authz.admin.v1alpha.KeyAdminService/GetKeyCore"
	KeyAdminService_ListKeyCores_FullMethodName    = "/blocky.authz.admin.v1alpha.KeyAdminService/ListKeyCores"
	KeyAdminService_ListKeyCoreKeys_FullMethodName = "/blocky.authz.admin.v1alpha.KeyAdminService/ListKeyCoreKeys"
	KeyAdminService_UpdateKeyCore_FullMethodName   = "/blocky.authz.admin.v1alpha.KeyAdminService/UpdateKeyCore"
	KeyAdminService_RotateKey_FullMethodName       = "/blocky.authz.admin.v1alpha.KeyAdminService/RotateKey"
	KeyAdminService_GetKey_FullMethodName          = "/blocky.authz.admin.v1alpha.KeyAdminService/GetKey"
	KeyAdminService_ListKeys_FullMethodName        = "/blocky.authz.admin.v1alpha.KeyAdminService/ListKeys"
	KeyAdminService_RevokeKey_FullMethodName       = "/blocky.authz.admin.v1alpha.KeyAdminService/RevokeKey"
)

// KeyAdminServiceClient is the client API for KeyAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type KeyAdminServiceClient interface {
	// CreateKeyCore creates a new authorization key.
	// New key is neither active nor used in a set.
	CreateKeyCore(ctx context.Context, in *CreateKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error)
	// GetKeyCore returns the specified authorization key.
	GetKeyCore(ctx context.Context, in *GetKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error)
	// ListKeyCores lists authorization keys that matches given request.
	ListKeyCores(ctx context.Context, in *ListKeyCoresRequest, opts ...grpc.CallOption) (*ListKeyCoresResponse, error)
	// ListKeyCoreKeys lists authorization keys that matches given request.
	ListKeyCoreKeys(ctx context.Context, in *ListKeyCoreKeysRequest, opts ...grpc.CallOption) (*ListKeyCoreKeysResponse, error)
	// UpdateKeyCore updates the specified authorization key.
	UpdateKeyCore(ctx context.Context, in *UpdateKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error)
	// Creates a new key revision and rotates the key.
	RotateKey(ctx context.Context, in *RotateKeyRequest, opts ...grpc.CallOption) (*Key, error)
	// GetKey returns the specified key revision.
	GetKey(ctx context.Context, in *GetKeyRequest, opts ...grpc.CallOption) (*Key, error)
	// ListKeys lists authorization keys that matches given request.
	ListKeys(ctx context.Context, in *ListKeysRequest, opts ...grpc.CallOption) (*ListKeysResponse, error)
	// RevokeKey revokes an authorization key revision.
	// Once revoked the key revision is no longer valid for signing and verification.
	// If revoked key was the only active signing key, the system will not accept
	// any new requests until a new key is created and activated.
	RevokeKey(ctx context.Context, in *RevokeKeyRequest, opts ...grpc.CallOption) (*Key, error)
}

type keyAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyAdminServiceClient(cc grpc.ClientConnInterface) KeyAdminServiceClient {
	return &keyAdminServiceClient{cc}
}

func (c *keyAdminServiceClient) CreateKeyCore(ctx context.Context, in *CreateKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error) {
	out := new(KeyCore)
	err := c.cc.Invoke(ctx, KeyAdminService_CreateKeyCore_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) GetKeyCore(ctx context.Context, in *GetKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error) {
	out := new(KeyCore)
	err := c.cc.Invoke(ctx, KeyAdminService_GetKeyCore_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) ListKeyCores(ctx context.Context, in *ListKeyCoresRequest, opts ...grpc.CallOption) (*ListKeyCoresResponse, error) {
	out := new(ListKeyCoresResponse)
	err := c.cc.Invoke(ctx, KeyAdminService_ListKeyCores_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) ListKeyCoreKeys(ctx context.Context, in *ListKeyCoreKeysRequest, opts ...grpc.CallOption) (*ListKeyCoreKeysResponse, error) {
	out := new(ListKeyCoreKeysResponse)
	err := c.cc.Invoke(ctx, KeyAdminService_ListKeyCoreKeys_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) UpdateKeyCore(ctx context.Context, in *UpdateKeyCoreRequest, opts ...grpc.CallOption) (*KeyCore, error) {
	out := new(KeyCore)
	err := c.cc.Invoke(ctx, KeyAdminService_UpdateKeyCore_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) RotateKey(ctx context.Context, in *RotateKeyRequest, opts ...grpc.CallOption) (*Key, error) {
	out := new(Key)
	err := c.cc.Invoke(ctx, KeyAdminService_RotateKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) GetKey(ctx context.Context, in *GetKeyRequest, opts ...grpc.CallOption) (*Key, error) {
	out := new(Key)
	err := c.cc.Invoke(ctx, KeyAdminService_GetKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) ListKeys(ctx context.Context, in *ListKeysRequest, opts ...grpc.CallOption) (*ListKeysResponse, error) {
	out := new(ListKeysResponse)
	err := c.cc.Invoke(ctx, KeyAdminService_ListKeys_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyAdminServiceClient) RevokeKey(ctx context.Context, in *RevokeKeyRequest, opts ...grpc.CallOption) (*Key, error) {
	out := new(Key)
	err := c.cc.Invoke(ctx, KeyAdminService_RevokeKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyAdminServiceServer is the server API for KeyAdminService service.
// All implementations must embed UnimplementedKeyAdminServiceServer
// for forward compatibility
type KeyAdminServiceServer interface {
	// CreateKeyCore creates a new authorization key.
	// New key is neither active nor used in a set.
	CreateKeyCore(context.Context, *CreateKeyCoreRequest) (*KeyCore, error)
	// GetKeyCore returns the specified authorization key.
	GetKeyCore(context.Context, *GetKeyCoreRequest) (*KeyCore, error)
	// ListKeyCores lists authorization keys that matches given request.
	ListKeyCores(context.Context, *ListKeyCoresRequest) (*ListKeyCoresResponse, error)
	// ListKeyCoreKeys lists authorization keys that matches given request.
	ListKeyCoreKeys(context.Context, *ListKeyCoreKeysRequest) (*ListKeyCoreKeysResponse, error)
	// UpdateKeyCore updates the specified authorization key.
	UpdateKeyCore(context.Context, *UpdateKeyCoreRequest) (*KeyCore, error)
	// Creates a new key revision and rotates the key.
	RotateKey(context.Context, *RotateKeyRequest) (*Key, error)
	// GetKey returns the specified key revision.
	GetKey(context.Context, *GetKeyRequest) (*Key, error)
	// ListKeys lists authorization keys that matches given request.
	ListKeys(context.Context, *ListKeysRequest) (*ListKeysResponse, error)
	// RevokeKey revokes an authorization key revision.
	// Once revoked the key revision is no longer valid for signing and verification.
	// If revoked key was the only active signing key, the system will not accept
	// any new requests until a new key is created and activated.
	RevokeKey(context.Context, *RevokeKeyRequest) (*Key, error)
	mustEmbedUnimplementedKeyAdminServiceServer()
}

// UnimplementedKeyAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedKeyAdminServiceServer struct {
}

func (UnimplementedKeyAdminServiceServer) CreateKeyCore(context.Context, *CreateKeyCoreRequest) (*KeyCore, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKeyCore not implemented")
}
func (UnimplementedKeyAdminServiceServer) GetKeyCore(context.Context, *GetKeyCoreRequest) (*KeyCore, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKeyCore not implemented")
}
func (UnimplementedKeyAdminServiceServer) ListKeyCores(context.Context, *ListKeyCoresRequest) (*ListKeyCoresResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListKeyCores not implemented")
}
func (UnimplementedKeyAdminServiceServer) ListKeyCoreKeys(context.Context, *ListKeyCoreKeysRequest) (*ListKeyCoreKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListKeyCoreKeys not implemented")
}
func (UnimplementedKeyAdminServiceServer) UpdateKeyCore(context.Context, *UpdateKeyCoreRequest) (*KeyCore, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateKeyCore not implemented")
}
func (UnimplementedKeyAdminServiceServer) RotateKey(context.Context, *RotateKeyRequest) (*Key, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RotateKey not implemented")
}
func (UnimplementedKeyAdminServiceServer) GetKey(context.Context, *GetKeyRequest) (*Key, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKey not implemented")
}
func (UnimplementedKeyAdminServiceServer) ListKeys(context.Context, *ListKeysRequest) (*ListKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListKeys not implemented")
}
func (UnimplementedKeyAdminServiceServer) RevokeKey(context.Context, *RevokeKeyRequest) (*Key, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeKey not implemented")
}
func (UnimplementedKeyAdminServiceServer) mustEmbedUnimplementedKeyAdminServiceServer() {}

// UnsafeKeyAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to KeyAdminServiceServer will
// result in compilation errors.
type UnsafeKeyAdminServiceServer interface {
	mustEmbedUnimplementedKeyAdminServiceServer()
}

func RegisterKeyAdminServiceServer(s grpc.ServiceRegistrar, srv KeyAdminServiceServer) {
	s.RegisterService(&KeyAdminService_ServiceDesc, srv)
}

func _KeyAdminService_CreateKeyCore_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyCoreRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).CreateKeyCore(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_CreateKeyCore_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).CreateKeyCore(ctx, req.(*CreateKeyCoreRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_GetKeyCore_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyCoreRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).GetKeyCore(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_GetKeyCore_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).GetKeyCore(ctx, req.(*GetKeyCoreRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_ListKeyCores_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListKeyCoresRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).ListKeyCores(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_ListKeyCores_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).ListKeyCores(ctx, req.(*ListKeyCoresRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_ListKeyCoreKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListKeyCoreKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).ListKeyCoreKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_ListKeyCoreKeys_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).ListKeyCoreKeys(ctx, req.(*ListKeyCoreKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_UpdateKeyCore_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateKeyCoreRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).UpdateKeyCore(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_UpdateKeyCore_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).UpdateKeyCore(ctx, req.(*UpdateKeyCoreRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_RotateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RotateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).RotateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_RotateKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).RotateKey(ctx, req.(*RotateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_GetKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).GetKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_GetKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).GetKey(ctx, req.(*GetKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_ListKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).ListKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_ListKeys_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).ListKeys(ctx, req.(*ListKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyAdminService_RevokeKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyAdminServiceServer).RevokeKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: KeyAdminService_RevokeKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyAdminServiceServer).RevokeKey(ctx, req.(*RevokeKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// KeyAdminService_ServiceDesc is the grpc.ServiceDesc for KeyAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var KeyAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.admin.v1alpha.KeyAdminService",
	HandlerType: (*KeyAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateKeyCore",
			Handler:    _KeyAdminService_CreateKeyCore_Handler,
		},
		{
			MethodName: "GetKeyCore",
			Handler:    _KeyAdminService_GetKeyCore_Handler,
		},
		{
			MethodName: "ListKeyCores",
			Handler:    _KeyAdminService_ListKeyCores_Handler,
		},
		{
			MethodName: "ListKeyCoreKeys",
			Handler:    _KeyAdminService_ListKeyCoreKeys_Handler,
		},
		{
			MethodName: "UpdateKeyCore",
			Handler:    _KeyAdminService_UpdateKeyCore_Handler,
		},
		{
			MethodName: "RotateKey",
			Handler:    _KeyAdminService_RotateKey_Handler,
		},
		{
			MethodName: "GetKey",
			Handler:    _KeyAdminService_GetKey_Handler,
		},
		{
			MethodName: "ListKeys",
			Handler:    _KeyAdminService_ListKeys_Handler,
		},
		{
			MethodName: "RevokeKey",
			Handler:    _KeyAdminService_RevokeKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/admin/v1alpha/key_admin.proto",
}
