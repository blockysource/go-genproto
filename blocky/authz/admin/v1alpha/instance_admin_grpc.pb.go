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
// source: blocky/authz/admin/v1alpha/instance_admin.proto

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
	InstanceAdminService_UpdateInstance_FullMethodName = "/blocky.authz.admin.v1alpha.InstanceAdminService/UpdateInstance"
	InstanceAdminService_GetInstance_FullMethodName    = "/blocky.authz.admin.v1alpha.InstanceAdminService/GetInstance"
)

// InstanceAdminServiceClient is the client API for InstanceAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type InstanceAdminServiceClient interface {
	// Patch an existing instance of an Authorization service.
	UpdateInstance(ctx context.Context, in *UpdateInstanceRequest, opts ...grpc.CallOption) (*Instance, error)
	// Gets the details of an instance of an Authorization service.
	GetInstance(ctx context.Context, in *GetInstanceRequest, opts ...grpc.CallOption) (*Instance, error)
}

type instanceAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewInstanceAdminServiceClient(cc grpc.ClientConnInterface) InstanceAdminServiceClient {
	return &instanceAdminServiceClient{cc}
}

func (c *instanceAdminServiceClient) UpdateInstance(ctx context.Context, in *UpdateInstanceRequest, opts ...grpc.CallOption) (*Instance, error) {
	out := new(Instance)
	err := c.cc.Invoke(ctx, InstanceAdminService_UpdateInstance_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *instanceAdminServiceClient) GetInstance(ctx context.Context, in *GetInstanceRequest, opts ...grpc.CallOption) (*Instance, error) {
	out := new(Instance)
	err := c.cc.Invoke(ctx, InstanceAdminService_GetInstance_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InstanceAdminServiceServer is the server API for InstanceAdminService service.
// All implementations must embed UnimplementedInstanceAdminServiceServer
// for forward compatibility
type InstanceAdminServiceServer interface {
	// Patch an existing instance of an Authorization service.
	UpdateInstance(context.Context, *UpdateInstanceRequest) (*Instance, error)
	// Gets the details of an instance of an Authorization service.
	GetInstance(context.Context, *GetInstanceRequest) (*Instance, error)
	mustEmbedUnimplementedInstanceAdminServiceServer()
}

// UnimplementedInstanceAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedInstanceAdminServiceServer struct {
}

func (UnimplementedInstanceAdminServiceServer) UpdateInstance(context.Context, *UpdateInstanceRequest) (*Instance, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateInstance not implemented")
}
func (UnimplementedInstanceAdminServiceServer) GetInstance(context.Context, *GetInstanceRequest) (*Instance, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInstance not implemented")
}
func (UnimplementedInstanceAdminServiceServer) mustEmbedUnimplementedInstanceAdminServiceServer() {}

// UnsafeInstanceAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to InstanceAdminServiceServer will
// result in compilation errors.
type UnsafeInstanceAdminServiceServer interface {
	mustEmbedUnimplementedInstanceAdminServiceServer()
}

func RegisterInstanceAdminServiceServer(s grpc.ServiceRegistrar, srv InstanceAdminServiceServer) {
	s.RegisterService(&InstanceAdminService_ServiceDesc, srv)
}

func _InstanceAdminService_UpdateInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateInstanceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InstanceAdminServiceServer).UpdateInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InstanceAdminService_UpdateInstance_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InstanceAdminServiceServer).UpdateInstance(ctx, req.(*UpdateInstanceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _InstanceAdminService_GetInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetInstanceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InstanceAdminServiceServer).GetInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InstanceAdminService_GetInstance_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InstanceAdminServiceServer).GetInstance(ctx, req.(*GetInstanceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// InstanceAdminService_ServiceDesc is the grpc.ServiceDesc for InstanceAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var InstanceAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.admin.v1alpha.InstanceAdminService",
	HandlerType: (*InstanceAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UpdateInstance",
			Handler:    _InstanceAdminService_UpdateInstance_Handler,
		},
		{
			MethodName: "GetInstance",
			Handler:    _InstanceAdminService_GetInstance_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/admin/v1alpha/instance_admin.proto",
}
