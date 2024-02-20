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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: blocky/cloud/resourcemanager/v1alpha/project.proto

package resourcemanagerpb

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The project's lifecycle state.
type Project_State int32

const (
	// The project is in an unspecified state.
	Project_STATE_UNSPECIFIED Project_State = 0
	// The project is active.
	Project_ACTIVE Project_State = 1
	// The project has been marked for deletion by the user
	// (by invoking DeleteProject) or by the system.
	Project_DELETE_REQUESTED Project_State = 2
)

// Enum value maps for Project_State.
var (
	Project_State_name = map[int32]string{
		0: "STATE_UNSPECIFIED",
		1: "ACTIVE",
		2: "DELETE_REQUESTED",
	}
	Project_State_value = map[string]int32{
		"STATE_UNSPECIFIED": 0,
		"ACTIVE":            1,
		"DELETE_REQUESTED":  2,
	}
)

func (x Project_State) Enum() *Project_State {
	p := new(Project_State)
	*p = x
	return p
}

func (x Project_State) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Project_State) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_cloud_resourcemanager_v1alpha_project_proto_enumTypes[0].Descriptor()
}

func (Project_State) Type() protoreflect.EnumType {
	return &file_blocky_cloud_resourcemanager_v1alpha_project_proto_enumTypes[0]
}

func (x Project_State) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Project_State.Descriptor instead.
func (Project_State) EnumDescriptor() ([]byte, []int) {
	return file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescGZIP(), []int{0, 0}
}

// Project represents a cloud project resource.
type Project struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Resource name of the Project
	// The format of the project resource name:
	// `projects/*`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Globally unique server-generated identifier for the key.
	// It could be used as the project identifier in its resource name.
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// The project's current state.
	State Project_State `protobuf:"varint,3,opt,name=state,proto3,enum=blocky.cloud.resourcemanager.v1alpha.Project_State" json:"state,omitempty"`
	// The display name of the project.
	DisplayName string `protobuf:"bytes,4,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Time when the key was created.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// The time when the project was last modified.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// The time when the project was marked for deletion.
	DeleteTime *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=delete_time,json=deleteTime,proto3" json:"delete_time,omitempty"`
	// An optional parent resource name of the project.
	Parent string `protobuf:"bytes,8,opt,name=parent,proto3" json:"parent,omitempty"`
}

func (x *Project) Reset() {
	*x = Project{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Project) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Project) ProtoMessage() {}

func (x *Project) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Project.ProtoReflect.Descriptor instead.
func (*Project) Descriptor() ([]byte, []int) {
	return file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescGZIP(), []int{0}
}

func (x *Project) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Project) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *Project) GetState() Project_State {
	if x != nil {
		return x.State
	}
	return Project_STATE_UNSPECIFIED
}

func (x *Project) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *Project) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Project) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *Project) GetDeleteTime() *timestamppb.Timestamp {
	if x != nil {
		return x.DeleteTime
	}
	return nil
}

func (x *Project) GetParent() string {
	if x != nil {
		return x.Parent
	}
	return ""
}

// ProjectCreatedEvent is published
type ProjectCreatedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The project that was created.
	Project *Project `protobuf:"bytes,1,opt,name=project,proto3" json:"project,omitempty"`
}

func (x *ProjectCreatedEvent) Reset() {
	*x = ProjectCreatedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProjectCreatedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProjectCreatedEvent) ProtoMessage() {}

func (x *ProjectCreatedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProjectCreatedEvent.ProtoReflect.Descriptor instead.
func (*ProjectCreatedEvent) Descriptor() ([]byte, []int) {
	return file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescGZIP(), []int{1}
}

func (x *ProjectCreatedEvent) GetProject() *Project {
	if x != nil {
		return x.Project
	}
	return nil
}

var File_blocky_cloud_resourcemanager_v1alpha_project_proto protoreflect.FileDescriptor

var file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDesc = []byte{
	0x0a, 0x32, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x24, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x72, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68,
	0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd8, 0x04, 0x0a, 0x07, 0x50, 0x72, 0x6f, 0x6a,
	0x65, 0x63, 0x74, 0x12, 0x47, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x33, 0xe0, 0x41, 0x08, 0xfa, 0x41, 0x2d, 0x0a, 0x2b, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x50,
	0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x03,
	0x75, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x06, 0xe0, 0x41, 0x03, 0xe0, 0x41,
	0x05, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x4e, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x33, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x63,
	0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x50, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x26, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
	0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41,
	0x07, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x40,
	0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42,
	0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x40, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x06, 0x70, 0x61, 0x72, 0x65, 0x6e,
	0x74, 0x22, 0x40, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x15, 0x0a, 0x11, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x43, 0x54, 0x49, 0x56, 0x45, 0x10, 0x01, 0x12, 0x14, 0x0a,
	0x10, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x45, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x45,
	0x44, 0x10, 0x02, 0x3a, 0x4d, 0xea, 0x41, 0x4a, 0x0a, 0x2b, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x50, 0x72,
	0x6f, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x12, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f,
	0x7b, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x7d, 0x1a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52,
	0x01, 0x01, 0x22, 0x5e, 0x0a, 0x13, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x47, 0x0a, 0x07, 0x70, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x42, 0xc7, 0x02, 0x0a, 0x28, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42,
	0x0c, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a,
	0x5a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x42, 0x43,
	0x52, 0xaa, 0x02, 0x24, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x43, 0x6c, 0x6f, 0x75, 0x64,
	0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca, 0x02, 0x24, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x5c, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x5c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xe2,
	0x02, 0x30, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x5c, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x5c, 0x56,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x27, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x43, 0x6c, 0x6f,
	0x75, 0x64, 0x3a, 0x3a, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x6d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x72, 0x3a, 0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescOnce sync.Once
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescData = file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDesc
)

func file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescGZIP() []byte {
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescOnce.Do(func() {
		file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescData)
	})
	return file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDescData
}

var file_blocky_cloud_resourcemanager_v1alpha_project_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_blocky_cloud_resourcemanager_v1alpha_project_proto_goTypes = []interface{}{
	(Project_State)(0),            // 0: blocky.cloud.resourcemanager.v1alpha.Project.State
	(*Project)(nil),               // 1: blocky.cloud.resourcemanager.v1alpha.Project
	(*ProjectCreatedEvent)(nil),   // 2: blocky.cloud.resourcemanager.v1alpha.ProjectCreatedEvent
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_blocky_cloud_resourcemanager_v1alpha_project_proto_depIdxs = []int32{
	0, // 0: blocky.cloud.resourcemanager.v1alpha.Project.state:type_name -> blocky.cloud.resourcemanager.v1alpha.Project.State
	3, // 1: blocky.cloud.resourcemanager.v1alpha.Project.create_time:type_name -> google.protobuf.Timestamp
	3, // 2: blocky.cloud.resourcemanager.v1alpha.Project.update_time:type_name -> google.protobuf.Timestamp
	3, // 3: blocky.cloud.resourcemanager.v1alpha.Project.delete_time:type_name -> google.protobuf.Timestamp
	1, // 4: blocky.cloud.resourcemanager.v1alpha.ProjectCreatedEvent.project:type_name -> blocky.cloud.resourcemanager.v1alpha.Project
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_blocky_cloud_resourcemanager_v1alpha_project_proto_init() }
func file_blocky_cloud_resourcemanager_v1alpha_project_proto_init() {
	if File_blocky_cloud_resourcemanager_v1alpha_project_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Project); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProjectCreatedEvent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_cloud_resourcemanager_v1alpha_project_proto_goTypes,
		DependencyIndexes: file_blocky_cloud_resourcemanager_v1alpha_project_proto_depIdxs,
		EnumInfos:         file_blocky_cloud_resourcemanager_v1alpha_project_proto_enumTypes,
		MessageInfos:      file_blocky_cloud_resourcemanager_v1alpha_project_proto_msgTypes,
	}.Build()
	File_blocky_cloud_resourcemanager_v1alpha_project_proto = out.File
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_rawDesc = nil
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_goTypes = nil
	file_blocky_cloud_resourcemanager_v1alpha_project_proto_depIdxs = nil
}