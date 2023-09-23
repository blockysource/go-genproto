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
// source: blocky/authz/admin/v1alpha/resource_admin.proto

package authzadminv1alpha

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
	ResourceAdminService_CreateResourceManager_FullMethodName    = "/blocky.authz.admin.v1alpha.ResourceAdminService/CreateResourceManager"
	ResourceAdminService_GetResourceManager_FullMethodName       = "/blocky.authz.admin.v1alpha.ResourceAdminService/GetResourceManager"
	ResourceAdminService_ListResourceManagers_FullMethodName     = "/blocky.authz.admin.v1alpha.ResourceAdminService/ListResourceManagers"
	ResourceAdminService_UpdateResourceManager_FullMethodName    = "/blocky.authz.admin.v1alpha.ResourceAdminService/UpdateResourceManager"
	ResourceAdminService_DeleteResourceManager_FullMethodName    = "/blocky.authz.admin.v1alpha.ResourceAdminService/DeleteResourceManager"
	ResourceAdminService_AliasResourceManager_FullMethodName     = "/blocky.authz.admin.v1alpha.ResourceAdminService/AliasResourceManager"
	ResourceAdminService_CreateResourcePermission_FullMethodName = "/blocky.authz.admin.v1alpha.ResourceAdminService/CreateResourcePermission"
	ResourceAdminService_ListResourcePermission_FullMethodName   = "/blocky.authz.admin.v1alpha.ResourceAdminService/ListResourcePermission"
	ResourceAdminService_GetResourcePermission_FullMethodName    = "/blocky.authz.admin.v1alpha.ResourceAdminService/GetResourcePermission"
	ResourceAdminService_UpdateResourcePermission_FullMethodName = "/blocky.authz.admin.v1alpha.ResourceAdminService/UpdateResourcePermission"
	ResourceAdminService_DeleteResourcePermission_FullMethodName = "/blocky.authz.admin.v1alpha.ResourceAdminService/DeleteResourcePermission"
	ResourceAdminService_AliasResourcePermission_FullMethodName  = "/blocky.authz.admin.v1alpha.ResourceAdminService/AliasResourcePermission"
)

// ResourceAdminServiceClient is the client API for ResourceAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ResourceAdminServiceClient interface {
	// Creates a new resource manager within given project.
	CreateResourceManager(ctx context.Context, in *CreateResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error)
	// Gets a resource manager.
	GetResourceManager(ctx context.Context, in *GetResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error)
	// Gets a list of resource managers.
	ListResourceManagers(ctx context.Context, in *ListResourceManagersRequest, opts ...grpc.CallOption) (*ListResourceManagersResponse, error)
	// Updates an existing resource manager with new information.
	UpdateResourceManager(ctx context.Context, in *UpdateResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error)
	// Deletes a resource manager along with all its dependent permissions.
	DeleteResourceManager(ctx context.Context, in *DeleteResourceRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// Creates an alias for a resource manager.
	// If the alias already exists, the former aliased resource manager
	// will have no alias.
	AliasResourceManager(ctx context.Context, in *AliasResourceRequest, opts ...grpc.CallOption) (*ResourceManager, error)
	// Creates a new authorization resource permission.
	CreateResourcePermission(ctx context.Context, in *CreateResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error)
	// Lists authorization resource permissions that are registered with the service.
	ListResourcePermission(ctx context.Context, in *ListResourcePermissionRequest, opts ...grpc.CallOption) (*ListResourcePermissionResponse, error)
	// Gets an existing resource permission.
	GetResourcePermission(ctx context.Context, in *GetResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error)
	// Updates an existing authorization resource permission with new information.
	UpdateResourcePermission(ctx context.Context, in *UpdateResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error)
	// Deletes an authorization resource permission.
	DeleteResourcePermission(ctx context.Context, in *DeleteResourcePermissionRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// Creates an alias for an authorization resource permission.
	// If the alias already exists, the former aliased resource permission will have
	// no alias.
	AliasResourcePermission(ctx context.Context, in *AliasResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error)
}

type resourceAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewResourceAdminServiceClient(cc grpc.ClientConnInterface) ResourceAdminServiceClient {
	return &resourceAdminServiceClient{cc}
}

func (c *resourceAdminServiceClient) CreateResourceManager(ctx context.Context, in *CreateResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error) {
	out := new(ResourceManager)
	err := c.cc.Invoke(ctx, ResourceAdminService_CreateResourceManager_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) GetResourceManager(ctx context.Context, in *GetResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error) {
	out := new(ResourceManager)
	err := c.cc.Invoke(ctx, ResourceAdminService_GetResourceManager_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) ListResourceManagers(ctx context.Context, in *ListResourceManagersRequest, opts ...grpc.CallOption) (*ListResourceManagersResponse, error) {
	out := new(ListResourceManagersResponse)
	err := c.cc.Invoke(ctx, ResourceAdminService_ListResourceManagers_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) UpdateResourceManager(ctx context.Context, in *UpdateResourceManagerRequest, opts ...grpc.CallOption) (*ResourceManager, error) {
	out := new(ResourceManager)
	err := c.cc.Invoke(ctx, ResourceAdminService_UpdateResourceManager_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) DeleteResourceManager(ctx context.Context, in *DeleteResourceRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ResourceAdminService_DeleteResourceManager_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) AliasResourceManager(ctx context.Context, in *AliasResourceRequest, opts ...grpc.CallOption) (*ResourceManager, error) {
	out := new(ResourceManager)
	err := c.cc.Invoke(ctx, ResourceAdminService_AliasResourceManager_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) CreateResourcePermission(ctx context.Context, in *CreateResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error) {
	out := new(ResourcePermission)
	err := c.cc.Invoke(ctx, ResourceAdminService_CreateResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) ListResourcePermission(ctx context.Context, in *ListResourcePermissionRequest, opts ...grpc.CallOption) (*ListResourcePermissionResponse, error) {
	out := new(ListResourcePermissionResponse)
	err := c.cc.Invoke(ctx, ResourceAdminService_ListResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) GetResourcePermission(ctx context.Context, in *GetResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error) {
	out := new(ResourcePermission)
	err := c.cc.Invoke(ctx, ResourceAdminService_GetResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) UpdateResourcePermission(ctx context.Context, in *UpdateResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error) {
	out := new(ResourcePermission)
	err := c.cc.Invoke(ctx, ResourceAdminService_UpdateResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) DeleteResourcePermission(ctx context.Context, in *DeleteResourcePermissionRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ResourceAdminService_DeleteResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceAdminServiceClient) AliasResourcePermission(ctx context.Context, in *AliasResourcePermissionRequest, opts ...grpc.CallOption) (*ResourcePermission, error) {
	out := new(ResourcePermission)
	err := c.cc.Invoke(ctx, ResourceAdminService_AliasResourcePermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceAdminServiceServer is the server API for ResourceAdminService service.
// All implementations must embed UnimplementedResourceAdminServiceServer
// for forward compatibility
type ResourceAdminServiceServer interface {
	// Creates a new resource manager within given project.
	CreateResourceManager(context.Context, *CreateResourceManagerRequest) (*ResourceManager, error)
	// Gets a resource manager.
	GetResourceManager(context.Context, *GetResourceManagerRequest) (*ResourceManager, error)
	// Gets a list of resource managers.
	ListResourceManagers(context.Context, *ListResourceManagersRequest) (*ListResourceManagersResponse, error)
	// Updates an existing resource manager with new information.
	UpdateResourceManager(context.Context, *UpdateResourceManagerRequest) (*ResourceManager, error)
	// Deletes a resource manager along with all its dependent permissions.
	DeleteResourceManager(context.Context, *DeleteResourceRequest) (*emptypb.Empty, error)
	// Creates an alias for a resource manager.
	// If the alias already exists, the former aliased resource manager
	// will have no alias.
	AliasResourceManager(context.Context, *AliasResourceRequest) (*ResourceManager, error)
	// Creates a new authorization resource permission.
	CreateResourcePermission(context.Context, *CreateResourcePermissionRequest) (*ResourcePermission, error)
	// Lists authorization resource permissions that are registered with the service.
	ListResourcePermission(context.Context, *ListResourcePermissionRequest) (*ListResourcePermissionResponse, error)
	// Gets an existing resource permission.
	GetResourcePermission(context.Context, *GetResourcePermissionRequest) (*ResourcePermission, error)
	// Updates an existing authorization resource permission with new information.
	UpdateResourcePermission(context.Context, *UpdateResourcePermissionRequest) (*ResourcePermission, error)
	// Deletes an authorization resource permission.
	DeleteResourcePermission(context.Context, *DeleteResourcePermissionRequest) (*emptypb.Empty, error)
	// Creates an alias for an authorization resource permission.
	// If the alias already exists, the former aliased resource permission will have
	// no alias.
	AliasResourcePermission(context.Context, *AliasResourcePermissionRequest) (*ResourcePermission, error)
	mustEmbedUnimplementedResourceAdminServiceServer()
}

// UnimplementedResourceAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedResourceAdminServiceServer struct {
}

func (UnimplementedResourceAdminServiceServer) CreateResourceManager(context.Context, *CreateResourceManagerRequest) (*ResourceManager, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResourceManager not implemented")
}
func (UnimplementedResourceAdminServiceServer) GetResourceManager(context.Context, *GetResourceManagerRequest) (*ResourceManager, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResourceManager not implemented")
}
func (UnimplementedResourceAdminServiceServer) ListResourceManagers(context.Context, *ListResourceManagersRequest) (*ListResourceManagersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourceManagers not implemented")
}
func (UnimplementedResourceAdminServiceServer) UpdateResourceManager(context.Context, *UpdateResourceManagerRequest) (*ResourceManager, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateResourceManager not implemented")
}
func (UnimplementedResourceAdminServiceServer) DeleteResourceManager(context.Context, *DeleteResourceRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteResourceManager not implemented")
}
func (UnimplementedResourceAdminServiceServer) AliasResourceManager(context.Context, *AliasResourceRequest) (*ResourceManager, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AliasResourceManager not implemented")
}
func (UnimplementedResourceAdminServiceServer) CreateResourcePermission(context.Context, *CreateResourcePermissionRequest) (*ResourcePermission, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) ListResourcePermission(context.Context, *ListResourcePermissionRequest) (*ListResourcePermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) GetResourcePermission(context.Context, *GetResourcePermissionRequest) (*ResourcePermission, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) UpdateResourcePermission(context.Context, *UpdateResourcePermissionRequest) (*ResourcePermission, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) DeleteResourcePermission(context.Context, *DeleteResourcePermissionRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) AliasResourcePermission(context.Context, *AliasResourcePermissionRequest) (*ResourcePermission, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AliasResourcePermission not implemented")
}
func (UnimplementedResourceAdminServiceServer) mustEmbedUnimplementedResourceAdminServiceServer() {}

// UnsafeResourceAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ResourceAdminServiceServer will
// result in compilation errors.
type UnsafeResourceAdminServiceServer interface {
	mustEmbedUnimplementedResourceAdminServiceServer()
}

func RegisterResourceAdminServiceServer(s grpc.ServiceRegistrar, srv ResourceAdminServiceServer) {
	s.RegisterService(&ResourceAdminService_ServiceDesc, srv)
}

func _ResourceAdminService_CreateResourceManager_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateResourceManagerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).CreateResourceManager(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_CreateResourceManager_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).CreateResourceManager(ctx, req.(*CreateResourceManagerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_GetResourceManager_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetResourceManagerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).GetResourceManager(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_GetResourceManager_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).GetResourceManager(ctx, req.(*GetResourceManagerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_ListResourceManagers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourceManagersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).ListResourceManagers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_ListResourceManagers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).ListResourceManagers(ctx, req.(*ListResourceManagersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_UpdateResourceManager_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateResourceManagerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).UpdateResourceManager(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_UpdateResourceManager_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).UpdateResourceManager(ctx, req.(*UpdateResourceManagerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_DeleteResourceManager_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).DeleteResourceManager(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_DeleteResourceManager_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).DeleteResourceManager(ctx, req.(*DeleteResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_AliasResourceManager_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AliasResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).AliasResourceManager(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_AliasResourceManager_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).AliasResourceManager(ctx, req.(*AliasResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_CreateResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).CreateResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_CreateResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).CreateResourcePermission(ctx, req.(*CreateResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_ListResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).ListResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_ListResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).ListResourcePermission(ctx, req.(*ListResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_GetResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).GetResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_GetResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).GetResourcePermission(ctx, req.(*GetResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_UpdateResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).UpdateResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_UpdateResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).UpdateResourcePermission(ctx, req.(*UpdateResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_DeleteResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).DeleteResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_DeleteResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).DeleteResourcePermission(ctx, req.(*DeleteResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceAdminService_AliasResourcePermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AliasResourcePermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceAdminServiceServer).AliasResourcePermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceAdminService_AliasResourcePermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceAdminServiceServer).AliasResourcePermission(ctx, req.(*AliasResourcePermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ResourceAdminService_ServiceDesc is the grpc.ServiceDesc for ResourceAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ResourceAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.admin.v1alpha.ResourceAdminService",
	HandlerType: (*ResourceAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateResourceManager",
			Handler:    _ResourceAdminService_CreateResourceManager_Handler,
		},
		{
			MethodName: "GetResourceManager",
			Handler:    _ResourceAdminService_GetResourceManager_Handler,
		},
		{
			MethodName: "ListResourceManagers",
			Handler:    _ResourceAdminService_ListResourceManagers_Handler,
		},
		{
			MethodName: "UpdateResourceManager",
			Handler:    _ResourceAdminService_UpdateResourceManager_Handler,
		},
		{
			MethodName: "DeleteResourceManager",
			Handler:    _ResourceAdminService_DeleteResourceManager_Handler,
		},
		{
			MethodName: "AliasResourceManager",
			Handler:    _ResourceAdminService_AliasResourceManager_Handler,
		},
		{
			MethodName: "CreateResourcePermission",
			Handler:    _ResourceAdminService_CreateResourcePermission_Handler,
		},
		{
			MethodName: "ListResourcePermission",
			Handler:    _ResourceAdminService_ListResourcePermission_Handler,
		},
		{
			MethodName: "GetResourcePermission",
			Handler:    _ResourceAdminService_GetResourcePermission_Handler,
		},
		{
			MethodName: "UpdateResourcePermission",
			Handler:    _ResourceAdminService_UpdateResourcePermission_Handler,
		},
		{
			MethodName: "DeleteResourcePermission",
			Handler:    _ResourceAdminService_DeleteResourcePermission_Handler,
		},
		{
			MethodName: "AliasResourcePermission",
			Handler:    _ResourceAdminService_AliasResourcePermission_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/admin/v1alpha/resource_admin.proto",
}
