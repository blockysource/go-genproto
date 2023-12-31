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
// source: blocky/projects/admin/v1alpha/project_admin.proto

package projectsadminv1alpha

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
	ProjectsAdminService_CreateProject_FullMethodName = "/blocky.projects.admin.v1alpha.ProjectsAdminService/CreateProject"
	ProjectsAdminService_GetProject_FullMethodName    = "/blocky.projects.admin.v1alpha.ProjectsAdminService/GetProject"
)

// ProjectsAdminServiceClient is the client API for ProjectsAdminService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ProjectsAdminServiceClient interface {
	// Creates a Project.
	CreateProject(ctx context.Context, in *CreateProjectRequest, opts ...grpc.CallOption) (*Project, error)
	// Gets a Project.
	GetProject(ctx context.Context, in *GetProjectRequest, opts ...grpc.CallOption) (*Project, error)
}

type projectsAdminServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewProjectsAdminServiceClient(cc grpc.ClientConnInterface) ProjectsAdminServiceClient {
	return &projectsAdminServiceClient{cc}
}

func (c *projectsAdminServiceClient) CreateProject(ctx context.Context, in *CreateProjectRequest, opts ...grpc.CallOption) (*Project, error) {
	out := new(Project)
	err := c.cc.Invoke(ctx, ProjectsAdminService_CreateProject_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *projectsAdminServiceClient) GetProject(ctx context.Context, in *GetProjectRequest, opts ...grpc.CallOption) (*Project, error) {
	out := new(Project)
	err := c.cc.Invoke(ctx, ProjectsAdminService_GetProject_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProjectsAdminServiceServer is the server API for ProjectsAdminService service.
// All implementations must embed UnimplementedProjectsAdminServiceServer
// for forward compatibility
type ProjectsAdminServiceServer interface {
	// Creates a Project.
	CreateProject(context.Context, *CreateProjectRequest) (*Project, error)
	// Gets a Project.
	GetProject(context.Context, *GetProjectRequest) (*Project, error)
	mustEmbedUnimplementedProjectsAdminServiceServer()
}

// UnimplementedProjectsAdminServiceServer must be embedded to have forward compatible implementations.
type UnimplementedProjectsAdminServiceServer struct {
}

func (UnimplementedProjectsAdminServiceServer) CreateProject(context.Context, *CreateProjectRequest) (*Project, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateProject not implemented")
}
func (UnimplementedProjectsAdminServiceServer) GetProject(context.Context, *GetProjectRequest) (*Project, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetProject not implemented")
}
func (UnimplementedProjectsAdminServiceServer) mustEmbedUnimplementedProjectsAdminServiceServer() {}

// UnsafeProjectsAdminServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ProjectsAdminServiceServer will
// result in compilation errors.
type UnsafeProjectsAdminServiceServer interface {
	mustEmbedUnimplementedProjectsAdminServiceServer()
}

func RegisterProjectsAdminServiceServer(s grpc.ServiceRegistrar, srv ProjectsAdminServiceServer) {
	s.RegisterService(&ProjectsAdminService_ServiceDesc, srv)
}

func _ProjectsAdminService_CreateProject_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateProjectRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProjectsAdminServiceServer).CreateProject(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ProjectsAdminService_CreateProject_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProjectsAdminServiceServer).CreateProject(ctx, req.(*CreateProjectRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ProjectsAdminService_GetProject_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetProjectRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProjectsAdminServiceServer).GetProject(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ProjectsAdminService_GetProject_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProjectsAdminServiceServer).GetProject(ctx, req.(*GetProjectRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ProjectsAdminService_ServiceDesc is the grpc.ServiceDesc for ProjectsAdminService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ProjectsAdminService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blocky.projects.admin.v1alpha.ProjectsAdminService",
	HandlerType: (*ProjectsAdminServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateProject",
			Handler:    _ProjectsAdminService_CreateProject_Handler,
		},
		{
			MethodName: "GetProject",
			Handler:    _ProjectsAdminService_GetProject_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blocky/projects/admin/v1alpha/project_admin.proto",
}
