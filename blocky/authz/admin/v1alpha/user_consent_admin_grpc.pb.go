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
// source: blocky/authz/admin/v1alpha/user_consent_admin.proto

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
	UserContentAdminService_CreateUserConsent_FullMethodName = "/blocky.authz.admin.v1alpha.UserContentAdminService/CreateUserConsent"
	UserContentAdminService_GetUserConsent_FullMethodName    = "/blocky.authz.admin.v1alpha.UserContentAdminService/GetUserConsent"
	UserContentAdminService_ListUserConsents_FullMethodName  = "/blocky.authz.admin.v1alpha.UserContentAdminService/ListUserConsents"
	UserContentAdminService_UpdateUserConsent_FullMethodName = "/blocky.authz.admin.v1alpha.UserContentAdminService/UpdateUserConsent"
	UserContentAdminService_DeleteUserConsent_FullMethodName = "/blocky.authz.admin.v1alpha.UserContentAdminService/DeleteUserConsent"
)

// UserContentAdminServiceClient is the client API for UserContentAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UserContentAdminServiceClient interface {
	// Creates a new user consent on resource permission for specific client.
	CreateUserConsent(ctx context.Context, in *CreateUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error)
	// Gets the user consent on resource permission.
	GetUserConsent(ctx context.Context, in *GetUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error)
	// ListUserConsents lists all user consents for the given project.
	ListUserConsents(ctx context.Context, in *ListUserConsentsRequest, opts ...grpc.CallOption) (*ListUserConsentsResponse, error)
	// Updates the user consent on resource permission.
	UpdateUserConsent(ctx context.Context, in *UpdateUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error)
	// Deletes the user consent on resource permission.
	// The user consent will be deleted regardless of whether it is being used by
	// any other resources.
	DeleteUserConsent(ctx context.Context, in *DeleteUserConsentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type userContentAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUserContentAdminServiceClient(cc grpc.ClientConnInterface) UserContentAdminServiceClient {
	return &userContentAdminServiceClient{cc}
}

func (c *userContentAdminServiceClient) CreateUserConsent(ctx context.Context, in *CreateUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error) {
	out := new(UserConsent)
	err := c.cc.Invoke(ctx, UserContentAdminService_CreateUserConsent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userContentAdminServiceClient) GetUserConsent(ctx context.Context, in *GetUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error) {
	out := new(UserConsent)
	err := c.cc.Invoke(ctx, UserContentAdminService_GetUserConsent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userContentAdminServiceClient) ListUserConsents(ctx context.Context, in *ListUserConsentsRequest, opts ...grpc.CallOption) (*ListUserConsentsResponse, error) {
	out := new(ListUserConsentsResponse)
	err := c.cc.Invoke(ctx, UserContentAdminService_ListUserConsents_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userContentAdminServiceClient) UpdateUserConsent(ctx context.Context, in *UpdateUserConsentRequest, opts ...grpc.CallOption) (*UserConsent, error) {
	out := new(UserConsent)
	err := c.cc.Invoke(ctx, UserContentAdminService_UpdateUserConsent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userContentAdminServiceClient) DeleteUserConsent(ctx context.Context, in *DeleteUserConsentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, UserContentAdminService_DeleteUserConsent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UserContentAdminServiceServer is the server API for UserContentAdminService service.
// All implementations must embed UnimplementedUserContentAdminServiceServer
// for forward compatibility
type UserContentAdminServiceServer interface {
	// Creates a new user consent on resource permission for specific client.
	CreateUserConsent(context.Context, *CreateUserConsentRequest) (*UserConsent, error)
	// Gets the user consent on resource permission.
	GetUserConsent(context.Context, *GetUserConsentRequest) (*UserConsent, error)
	// ListUserConsents lists all user consents for the given project.
	ListUserConsents(context.Context, *ListUserConsentsRequest) (*ListUserConsentsResponse, error)
	// Updates the user consent on resource permission.
	UpdateUserConsent(context.Context, *UpdateUserConsentRequest) (*UserConsent, error)
	// Deletes the user consent on resource permission.
	// The user consent will be deleted regardless of whether it is being used by
	// any other resources.
	DeleteUserConsent(context.Context, *DeleteUserConsentRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedUserContentAdminServiceServer()
}

// UnimplementedUserContentAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUserContentAdminServiceServer struct {
}

func (UnimplementedUserContentAdminServiceServer) CreateUserConsent(context.Context, *CreateUserConsentRequest) (*UserConsent, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUserConsent not implemented")
}
func (UnimplementedUserContentAdminServiceServer) GetUserConsent(context.Context, *GetUserConsentRequest) (*UserConsent, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserConsent not implemented")
}
func (UnimplementedUserContentAdminServiceServer) ListUserConsents(context.Context, *ListUserConsentsRequest) (*ListUserConsentsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUserConsents not implemented")
}
func (UnimplementedUserContentAdminServiceServer) UpdateUserConsent(context.Context, *UpdateUserConsentRequest) (*UserConsent, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserConsent not implemented")
}
func (UnimplementedUserContentAdminServiceServer) DeleteUserConsent(context.Context, *DeleteUserConsentRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUserConsent not implemented")
}
func (UnimplementedUserContentAdminServiceServer) mustEmbedUnimplementedUserContentAdminServiceServer() {
}

// UnsafeUserContentAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UserContentAdminServiceServer will
// result in compilation errors.
type UnsafeUserContentAdminServiceServer interface {
	mustEmbedUnimplementedUserContentAdminServiceServer()
}

func RegisterUserContentAdminServiceServer(s grpc.ServiceRegistrar, srv UserContentAdminServiceServer) {
	s.RegisterService(&UserContentAdminService_ServiceDesc, srv)
}

func _UserContentAdminService_CreateUserConsent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserConsentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserContentAdminServiceServer).CreateUserConsent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserContentAdminService_CreateUserConsent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserContentAdminServiceServer).CreateUserConsent(ctx, req.(*CreateUserConsentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserContentAdminService_GetUserConsent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserConsentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserContentAdminServiceServer).GetUserConsent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserContentAdminService_GetUserConsent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserContentAdminServiceServer).GetUserConsent(ctx, req.(*GetUserConsentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserContentAdminService_ListUserConsents_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUserConsentsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserContentAdminServiceServer).ListUserConsents(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserContentAdminService_ListUserConsents_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserContentAdminServiceServer).ListUserConsents(ctx, req.(*ListUserConsentsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserContentAdminService_UpdateUserConsent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateUserConsentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserContentAdminServiceServer).UpdateUserConsent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserContentAdminService_UpdateUserConsent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserContentAdminServiceServer).UpdateUserConsent(ctx, req.(*UpdateUserConsentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserContentAdminService_DeleteUserConsent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserConsentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserContentAdminServiceServer).DeleteUserConsent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: UserContentAdminService_DeleteUserConsent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserContentAdminServiceServer).DeleteUserConsent(ctx, req.(*DeleteUserConsentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// UserContentAdminService_ServiceDesc is the grpc.ServiceDesc for UserContentAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UserContentAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.authz.admin.v1alpha.UserContentAdminService",
	HandlerType: (*UserContentAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateUserConsent",
			Handler:    _UserContentAdminService_CreateUserConsent_Handler,
		},
		{
			MethodName: "GetUserConsent",
			Handler:    _UserContentAdminService_GetUserConsent_Handler,
		},
		{
			MethodName: "ListUserConsents",
			Handler:    _UserContentAdminService_ListUserConsents_Handler,
		},
		{
			MethodName: "UpdateUserConsent",
			Handler:    _UserContentAdminService_UpdateUserConsent_Handler,
		},
		{
			MethodName: "DeleteUserConsent",
			Handler:    _UserContentAdminService_DeleteUserConsent_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/authz/admin/v1alpha/user_consent_admin.proto",
}
