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
// source: blocky/authz/admin/v1alpha/resource.proto

package authzadminv1alpha

import (
	signalgpb "github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
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

// A resource manager describes a valid any service that provides some resources
// and is expected to be secured by the Authorization Server.
// The resource service identified by its resource manager is also an
// audience of the authorization tokens.
// Each resource manager may manage access to its resources using different
// permission scopes.
// A resource manager may also specify which signing algorithms it supports,
// and which signing algorithms are required for the access tokens.
type ResourceManager struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Is a unique identifier of the resource manager.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Is a system-assigned unique identifier for this resource manager.
	// The format of this identifier is a UUID.s
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// Is a unique human-readable name of the resource manager.
	// If defined it may be used as an alias for the resource manager identifier.
	// I.e.:  projects/{project}/resourceManagers/my-resource-manager
	// The alias is mutable by custom AliasResourceManager RPC.
	Alias string `protobuf:"bytes,3,opt,name=alias,proto3" json:"alias,omitempty"`
	// Is a human-readable name of the resource manager.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// Is a human-readable name of the resource manager.
	DisplayName string `protobuf:"bytes,5,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Is a token audience name for this resource manager.
	// The audience name is used by the token issuer to identify the resource manager.
	// If not defined, the audience name is the same as the resource manager name.
	Audience string `protobuf:"bytes,6,opt,name=audience,proto3" json:"audience,omitempty"`
	// URIs associated with this resource manager.
	Uris []string `protobuf:"bytes,7,rep,name=uris,proto3" json:"uris,omitempty"`
	// Is a human-readable description of the resource manager.
	Description string `protobuf:"bytes,8,opt,name=description,proto3" json:"description,omitempty"`
	// Supported signing algorithms for this resource manager.
	// If not defined, all signing algorithms are supported.
	SigningAlgorithms []signalgpb.SigningAlgorithm `protobuf:"varint,9,rep,packed,name=signing_algorithms,json=signingAlgorithms,proto3,enum=blocky.authz.type.SigningAlgorithm" json:"signing_algorithms,omitempty"`
}

func (x *ResourceManager) Reset() {
	*x = ResourceManager{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceManager) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceManager) ProtoMessage() {}

func (x *ResourceManager) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceManager.ProtoReflect.Descriptor instead.
func (*ResourceManager) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_resource_proto_rawDescGZIP(), []int{0}
}

func (x *ResourceManager) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ResourceManager) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *ResourceManager) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *ResourceManager) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *ResourceManager) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *ResourceManager) GetAudience() string {
	if x != nil {
		return x.Audience
	}
	return ""
}

func (x *ResourceManager) GetUris() []string {
	if x != nil {
		return x.Uris
	}
	return nil
}

func (x *ResourceManager) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *ResourceManager) GetSigningAlgorithms() []signalgpb.SigningAlgorithm {
	if x != nil {
		return x.SigningAlgorithms
	}
	return nil
}

// Determines a set of access permissions for a particular resource, identified
type ResourcePermission struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The resource permission identifier and resource name.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Server-generated unique identifier for the scope.
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// The authorization scope string that is used in the OAuth 2.0 access and refresh tokens.
	// It is used as OAuth 2.0 scope parameter.
	// The scope must be unique within the whole project.
	Scope string `protobuf:"bytes,3,opt,name=scope,proto3" json:"scope,omitempty"`
	// The human-readable alias of resource permission identifier.
	// It needs to be unique in the parent resource manager.
	// As a good practice the alias might correspond to the scope,
	// which guarantees uniqueness of the scope within the project.
	Alias string `protobuf:"bytes,4,opt,name=alias,proto3" json:"alias,omitempty"`
	// The date of creation of the resource permission.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// The date of the last modification of the resource permission.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// The human-readable display name of the resource permission.
	DisplayName string `protobuf:"bytes,7,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// The human-readable description of the resource permission.
	Description string `protobuf:"bytes,8,opt,name=description,proto3" json:"description,omitempty"`
	// Etag of the resource permission.
	Etag string `protobuf:"bytes,9,opt,name=etag,proto3" json:"etag,omitempty"`
}

func (x *ResourcePermission) Reset() {
	*x = ResourcePermission{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourcePermission) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourcePermission) ProtoMessage() {}

func (x *ResourcePermission) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourcePermission.ProtoReflect.Descriptor instead.
func (*ResourcePermission) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_resource_proto_rawDescGZIP(), []int{1}
}

func (x *ResourcePermission) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ResourcePermission) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *ResourcePermission) GetScope() string {
	if x != nil {
		return x.Scope
	}
	return ""
}

func (x *ResourcePermission) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *ResourcePermission) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *ResourcePermission) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *ResourcePermission) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *ResourcePermission) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *ResourcePermission) GetEtag() string {
	if x != nil {
		return x.Etag
	}
	return ""
}

var File_blocky_authz_admin_v1alpha_resource_proto protoreflect.FileDescriptor

var file_blocky_authz_admin_v1alpha_resource_proto_rawDesc = []byte{
	0x0a, 0x29, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x29, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f,
	0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x69,
	0x6e, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66,
	0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x87, 0x04, 0x0a, 0x0f, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x72, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x03, 0xe0, 0x41, 0x08, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x15, 0x0a, 0x03,
	0x75, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x03,
	0x75, 0x69, 0x64, 0x12, 0x19, 0x0a, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x40,
	0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42,
	0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x26, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x0b, 0x64, 0x69, 0x73,
	0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x08, 0x61, 0x75, 0x64, 0x69,
	0x65, 0x6e, 0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x08, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x17, 0x0a, 0x04, 0x75, 0x72, 0x69,
	0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x04, 0x75, 0x72,
	0x69, 0x73, 0x12, 0x25, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x57, 0x0a, 0x12, 0x73, 0x69, 0x67,
	0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x18,
	0x09, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e,
	0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52,
	0x11, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x73, 0x3a, 0x84, 0x01, 0xea, 0x41, 0x80, 0x01, 0x0a, 0x24, 0x61, 0x75, 0x74, 0x68, 0x7a,
	0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12,
	0x35, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x7b, 0x70, 0x72, 0x6f, 0x6a, 0x65,
	0x63, 0x74, 0x7d, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x72, 0x73, 0x2f, 0x7b, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61,
	0x6e, 0x61, 0x67, 0x65, 0x72, 0x7d, 0x2a, 0x10, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x73, 0x32, 0x0f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x22, 0x8d, 0x04, 0x0a, 0x12, 0x52, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03,
	0xe0, 0x41, 0x08, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x75, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x03, 0x75, 0x69, 0x64,
	0x12, 0x19, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42,
	0x03, 0xe0, 0x41, 0x05, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x05, 0x61,
	0x6c, 0x69, 0x61, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0c, 0x64, 0x69,
	0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x03, 0xe0, 0x41, 0x07, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x65, 0x74, 0x61,
	0x67, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x65, 0x74, 0x61, 0x67, 0x3a, 0xa9, 0x01,
	0xea, 0x41, 0xa5, 0x01, 0x0a, 0x1a, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x53, 0x63, 0x6f, 0x70, 0x65,
	0x12, 0x5e, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x7b, 0x70, 0x72, 0x6f, 0x6a,
	0x65, 0x63, 0x74, 0x7d, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x72, 0x73, 0x2f, 0x7b, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x7d, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x7b, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x7d,
	0x2a, 0x13, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x32, 0x12, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50,
	0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x42, 0x8c, 0x02, 0x0a, 0x1e, 0x63, 0x6f,
	0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x0d, 0x52, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x50, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f,
	0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x75,
	0x74, 0x68, 0x7a, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xa2,
	0x02, 0x03, 0x42, 0x41, 0x41, 0xaa, 0x02, 0x1a, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x41,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0xca, 0x02, 0x1a, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68,
	0x7a, 0x5c, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xe2,
	0x02, 0x26, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x41,
	0x64, 0x6d, 0x69, 0x6e, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1d, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x3a, 0x3a, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x3a, 0x3a, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x3a,
	0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_authz_admin_v1alpha_resource_proto_rawDescOnce sync.Once
	file_blocky_authz_admin_v1alpha_resource_proto_rawDescData = file_blocky_authz_admin_v1alpha_resource_proto_rawDesc
)

func file_blocky_authz_admin_v1alpha_resource_proto_rawDescGZIP() []byte {
	file_blocky_authz_admin_v1alpha_resource_proto_rawDescOnce.Do(func() {
		file_blocky_authz_admin_v1alpha_resource_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_authz_admin_v1alpha_resource_proto_rawDescData)
	})
	return file_blocky_authz_admin_v1alpha_resource_proto_rawDescData
}

var file_blocky_authz_admin_v1alpha_resource_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_blocky_authz_admin_v1alpha_resource_proto_goTypes = []interface{}{
	(*ResourceManager)(nil),         // 0: blocky.authz.admin.v1alpha.ResourceManager
	(*ResourcePermission)(nil),      // 1: blocky.authz.admin.v1alpha.ResourcePermission
	(*timestamppb.Timestamp)(nil),   // 2: google.protobuf.Timestamp
	(signalgpb.SigningAlgorithm)(0), // 3: blocky.authz.type.SigningAlgorithm
}
var file_blocky_authz_admin_v1alpha_resource_proto_depIdxs = []int32{
	2, // 0: blocky.authz.admin.v1alpha.ResourceManager.create_time:type_name -> google.protobuf.Timestamp
	3, // 1: blocky.authz.admin.v1alpha.ResourceManager.signing_algorithms:type_name -> blocky.authz.type.SigningAlgorithm
	2, // 2: blocky.authz.admin.v1alpha.ResourcePermission.create_time:type_name -> google.protobuf.Timestamp
	2, // 3: blocky.authz.admin.v1alpha.ResourcePermission.update_time:type_name -> google.protobuf.Timestamp
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_blocky_authz_admin_v1alpha_resource_proto_init() }
func file_blocky_authz_admin_v1alpha_resource_proto_init() {
	if File_blocky_authz_admin_v1alpha_resource_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceManager); i {
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
		file_blocky_authz_admin_v1alpha_resource_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourcePermission); i {
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
			RawDescriptor: file_blocky_authz_admin_v1alpha_resource_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_authz_admin_v1alpha_resource_proto_goTypes,
		DependencyIndexes: file_blocky_authz_admin_v1alpha_resource_proto_depIdxs,
		MessageInfos:      file_blocky_authz_admin_v1alpha_resource_proto_msgTypes,
	}.Build()
	File_blocky_authz_admin_v1alpha_resource_proto = out.File
	file_blocky_authz_admin_v1alpha_resource_proto_rawDesc = nil
	file_blocky_authz_admin_v1alpha_resource_proto_goTypes = nil
	file_blocky_authz_admin_v1alpha_resource_proto_depIdxs = nil
}
