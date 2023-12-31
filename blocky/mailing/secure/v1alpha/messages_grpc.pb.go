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
// source: blocky/mailing/secure/v1alpha/messages.proto

package securev1alpha

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
	MailingService_UploadAttachment_FullMethodName     = "/blocky.mailing.secure.v1alpha.MailingService/UploadAttachment"
	MailingService_SendMessage_FullMethodName          = "/blocky.mailing.secure.v1alpha.MailingService/SendMessage"
	MailingService_SendTemplatedMessage_FullMethodName = "/blocky.mailing.secure.v1alpha.MailingService/SendTemplatedMessage"
)

// MailingServiceClient is the client API for MailingService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MailingServiceClient interface {
	// UploadAttachment uploads an attachment to the mailing service, the attachment will be available for sending.
	// The attachment will be deleted from the mailing service after the specified TTL.
	// In order to properly upload an attachment, the client should send a stream of
	// [UploadAttachmentRequest][blocky.mailing.secure.v1alpha.UploadAttachmentRequest] messages, where the first message
	// should be a [UploadAttachmentHeader][blocky.mailing.secure.v1alpha.UploadAttachmentHeader] message and the subsequent
	// messages should be [UploadAttachmentChunk][blocky.mailing.secure.v1alpha.UploadAttachmentChunk] messages.
	// The client should send the chunks in the same order as they are in the original file.
	// The maximum gRPC message size is 4MB, so the chunk size should be less than that.
	// The best practice is to use the chunks of 16-64KB.
	UploadAttachment(ctx context.Context, opts ...grpc.CallOption) (MailingService_UploadAttachmentClient, error)
	// SendMessage sends a single email message.
	SendMessage(ctx context.Context, in *SendMessageRequest, opts ...grpc.CallOption) (*SendMessageResponse, error)
	// SendTemplatedMessage sends a single email message using a template.
	SendTemplatedMessage(ctx context.Context, in *SendTemplatedMessageRequest, opts ...grpc.CallOption) (*SendTemplatedMessageResponse, error)
}

type mailingServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMailingServiceClient(cc grpc.ClientConnInterface) MailingServiceClient {
	return &mailingServiceClient{cc}
}

func (c *mailingServiceClient) UploadAttachment(ctx context.Context, opts ...grpc.CallOption) (MailingService_UploadAttachmentClient, error) {
	stream, err := c.cc.NewStream(ctx, &MailingService_ServiceDesc.Streams[0], MailingService_UploadAttachment_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &mailingServiceUploadAttachmentClient{stream}
	return x, nil
}

type MailingService_UploadAttachmentClient interface {
	Send(*UploadAttachmentRequest) error
	CloseAndRecv() (*UploadAttachmentResponse, error)
	grpc.ClientStream
}

type mailingServiceUploadAttachmentClient struct {
	grpc.ClientStream
}

func (x *mailingServiceUploadAttachmentClient) Send(m *UploadAttachmentRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *mailingServiceUploadAttachmentClient) CloseAndRecv() (*UploadAttachmentResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(UploadAttachmentResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *mailingServiceClient) SendMessage(ctx context.Context, in *SendMessageRequest, opts ...grpc.CallOption) (*SendMessageResponse, error) {
	out := new(SendMessageResponse)
	err := c.cc.Invoke(ctx, MailingService_SendMessage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mailingServiceClient) SendTemplatedMessage(ctx context.Context, in *SendTemplatedMessageRequest, opts ...grpc.CallOption) (*SendTemplatedMessageResponse, error) {
	out := new(SendTemplatedMessageResponse)
	err := c.cc.Invoke(ctx, MailingService_SendTemplatedMessage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MailingServiceServer is the server API for MailingService service.
// All implementations must embed UnimplementedMailingServiceServer
// for forward compatibility
type MailingServiceServer interface {
	// UploadAttachment uploads an attachment to the mailing service, the attachment will be available for sending.
	// The attachment will be deleted from the mailing service after the specified TTL.
	// In order to properly upload an attachment, the client should send a stream of
	// [UploadAttachmentRequest][blocky.mailing.secure.v1alpha.UploadAttachmentRequest] messages, where the first message
	// should be a [UploadAttachmentHeader][blocky.mailing.secure.v1alpha.UploadAttachmentHeader] message and the subsequent
	// messages should be [UploadAttachmentChunk][blocky.mailing.secure.v1alpha.UploadAttachmentChunk] messages.
	// The client should send the chunks in the same order as they are in the original file.
	// The maximum gRPC message size is 4MB, so the chunk size should be less than that.
	// The best practice is to use the chunks of 16-64KB.
	UploadAttachment(MailingService_UploadAttachmentServer) error
	// SendMessage sends a single email message.
	SendMessage(context.Context, *SendMessageRequest) (*SendMessageResponse, error)
	// SendTemplatedMessage sends a single email message using a template.
	SendTemplatedMessage(context.Context, *SendTemplatedMessageRequest) (*SendTemplatedMessageResponse, error)
	mustEmbedUnimplementedMailingServiceServer()
}

// UnimplementedMailingServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMailingServiceServer struct {
}

func (UnimplementedMailingServiceServer) UploadAttachment(MailingService_UploadAttachmentServer) error {
	return status.Errorf(codes.Unimplemented, "method UploadAttachment not implemented")
}
func (UnimplementedMailingServiceServer) SendMessage(context.Context, *SendMessageRequest) (*SendMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendMessage not implemented")
}
func (UnimplementedMailingServiceServer) SendTemplatedMessage(context.Context, *SendTemplatedMessageRequest) (*SendTemplatedMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendTemplatedMessage not implemented")
}
func (UnimplementedMailingServiceServer) mustEmbedUnimplementedMailingServiceServer() {}

// UnsafeMailingServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MailingServiceServer will
// result in compilation errors.
type UnsafeMailingServiceServer interface {
	mustEmbedUnimplementedMailingServiceServer()
}

func RegisterMailingServiceServer(s grpc.ServiceRegistrar, srv MailingServiceServer) {
	s.RegisterService(&MailingService_ServiceDesc, srv)
}

func _MailingService_UploadAttachment_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(MailingServiceServer).UploadAttachment(&mailingServiceUploadAttachmentServer{stream})
}

type MailingService_UploadAttachmentServer interface {
	SendAndClose(*UploadAttachmentResponse) error
	Recv() (*UploadAttachmentRequest, error)
	grpc.ServerStream
}

type mailingServiceUploadAttachmentServer struct {
	grpc.ServerStream
}

func (x *mailingServiceUploadAttachmentServer) SendAndClose(m *UploadAttachmentResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *mailingServiceUploadAttachmentServer) Recv() (*UploadAttachmentRequest, error) {
	m := new(UploadAttachmentRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _MailingService_SendMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MailingServiceServer).SendMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MailingService_SendMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MailingServiceServer).SendMessage(ctx, req.(*SendMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MailingService_SendTemplatedMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendTemplatedMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MailingServiceServer).SendTemplatedMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MailingService_SendTemplatedMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MailingServiceServer).SendTemplatedMessage(ctx, req.(*SendTemplatedMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MailingService_ServiceDesc is the grpc.ServiceDesc for MailingService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MailingService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.mailing.secure.v1alpha.MailingService",
	HandlerType: (*MailingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendMessage",
			Handler:    _MailingService_SendMessage_Handler,
		},
		{
			MethodName: "SendTemplatedMessage",
			Handler:    _MailingService_SendTemplatedMessage_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "UploadAttachment",
			Handler:       _MailingService_UploadAttachment_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "blocky/mailing/secure/v1alpha/messages.proto",
}
