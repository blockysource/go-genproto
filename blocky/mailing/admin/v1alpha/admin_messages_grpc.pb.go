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
// source: blocky/mailing/admin/v1alpha/admin_messages.proto

package mailingv1alpha

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
	MessagesAdminService_ListMessages_FullMethodName = "/blocky.mailing.v1alpha.MessagesAdminService/ListMessages"
)

// MessagesAdminServiceClient is the client API for MessagesAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MessagesAdminServiceClient interface {
	// Lists the messages that satisfies provided request.
	ListMessages(ctx context.Context, in *ListMessagesRequest, opts ...grpc.CallOption) (*ListMessagesResponse, error)
}

type messagesAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMessagesAdminServiceClient(cc grpc.ClientConnInterface) MessagesAdminServiceClient {
	return &messagesAdminServiceClient{cc}
}

func (c *messagesAdminServiceClient) ListMessages(ctx context.Context, in *ListMessagesRequest, opts ...grpc.CallOption) (*ListMessagesResponse, error) {
	out := new(ListMessagesResponse)
	err := c.cc.Invoke(ctx, MessagesAdminService_ListMessages_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MessagesAdminServiceServer is the server API for MessagesAdminService service.
// All implementations must embed UnimplementedMessagesAdminServiceServer
// for forward compatibility
type MessagesAdminServiceServer interface {
	// Lists the messages that satisfies provided request.
	ListMessages(context.Context, *ListMessagesRequest) (*ListMessagesResponse, error)
	mustEmbedUnimplementedMessagesAdminServiceServer()
}

// UnimplementedMessagesAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMessagesAdminServiceServer struct {
}

func (UnimplementedMessagesAdminServiceServer) ListMessages(context.Context, *ListMessagesRequest) (*ListMessagesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListMessages not implemented")
}
func (UnimplementedMessagesAdminServiceServer) mustEmbedUnimplementedMessagesAdminServiceServer() {}

// UnsafeMessagesAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MessagesAdminServiceServer will
// result in compilation errors.
type UnsafeMessagesAdminServiceServer interface {
	mustEmbedUnimplementedMessagesAdminServiceServer()
}

func RegisterMessagesAdminServiceServer(s grpc.ServiceRegistrar, srv MessagesAdminServiceServer) {
	s.RegisterService(&MessagesAdminService_ServiceDesc, srv)
}

func _MessagesAdminService_ListMessages_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListMessagesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MessagesAdminServiceServer).ListMessages(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MessagesAdminService_ListMessages_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MessagesAdminServiceServer).ListMessages(ctx, req.(*ListMessagesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MessagesAdminService_ServiceDesc is the grpc.ServiceDesc for MessagesAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MessagesAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.mailing.v1alpha.MessagesAdminService",
	HandlerType: (*MessagesAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListMessages",
			Handler:    _MessagesAdminService_ListMessages_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/mailing/admin/v1alpha/admin_messages.proto",
}