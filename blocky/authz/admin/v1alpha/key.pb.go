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
// source: blocky/authz/admin/v1alpha/key.proto

package authzadminv1alpha

import (
	signalgpb "github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
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

// KeyCore is a representation of an authorization key core definition.
// It contains information about the key, such as algorithm, name,
// creation time, as well as information about its activation and rotation.
//
// The core is used to derive authorization key used for signing and verification.
// Once the key is being rotated, a new key derives actual parameters from the core.
// This may change the new key properties like priority.
//
// Once a new key is derived from the core in addition to its own name,
// it is also assigned an alias 'latest' which is used to refer to the latest key.
// The full path of the latest key core derivation is:
// 'projects/{project}/keyCores/{key_core}/keys/latest'
type KeyCore struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name of the key core.
	// Format: 'projects/{project}/keyCores/{key_core}'
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The unique server-generated UUID identifier for the key revision.
	// It could be used as the key revision identifier in its resource name.
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// Algorithm used for signing and verification.
	Algorithm signalgpb.SigningAlgorithm `protobuf:"varint,3,opt,name=algorithm,proto3,enum=blocky.authz.type.SigningAlgorithm" json:"algorithm,omitempty"`
	// The display name of the key core.
	DisplayName string `protobuf:"bytes,4,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Time when the key core was created.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// Time when the key core was updated.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// Time when the key core was last rotated.
	LastRotatedTime *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=last_rotated_time,json=lastRotatedTime,proto3" json:"last_rotated_time,omitempty"`
	// Rotation interval of the key derived from this core.
	// If not provided, the key core will not be rotated automatically.
	RotationInterval *durationpb.Duration `protobuf:"bytes,8,opt,name=rotation_interval,json=rotationInterval,proto3" json:"rotation_interval,omitempty"`
	// Priority of the key core.
	// The higher the priority, the more likely the key will be used for signing.
	// If not provided, the key will be assigned the default priority 0.
	// The keys in the JWK set are sorted by priority in descending order.
	Priority int32 `protobuf:"varint,9,opt,name=priority,proto3" json:"priority,omitempty"`
	// Is the number of keys derived from this core.
	DerivedKeysCount int32 `protobuf:"varint,10,opt,name=derived_keys_count,json=derivedKeysCount,proto3" json:"derived_keys_count,omitempty"`
}

func (x *KeyCore) Reset() {
	*x = KeyCore{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_key_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyCore) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyCore) ProtoMessage() {}

func (x *KeyCore) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_key_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyCore.ProtoReflect.Descriptor instead.
func (*KeyCore) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_key_proto_rawDescGZIP(), []int{0}
}

func (x *KeyCore) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KeyCore) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *KeyCore) GetAlgorithm() signalgpb.SigningAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return signalgpb.SigningAlgorithm(0)
}

func (x *KeyCore) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *KeyCore) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *KeyCore) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *KeyCore) GetLastRotatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.LastRotatedTime
	}
	return nil
}

func (x *KeyCore) GetRotationInterval() *durationpb.Duration {
	if x != nil {
		return x.RotationInterval
	}
	return nil
}

func (x *KeyCore) GetPriority() int32 {
	if x != nil {
		return x.Priority
	}
	return 0
}

func (x *KeyCore) GetDerivedKeysCount() int32 {
	if x != nil {
		return x.DerivedKeysCount
	}
	return 0
}

// Key is a representation of an authorization key used by the service.
// It is derived from the key core and is directly used for signing and verification
// of the authorization tokens.
// The
// Only the most recent key revision could be used to sign the tokens,
// However all, non-revoked key revisions could be used for verification.
type Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The resource name of the key revision.
	// Format: `projects/{project}/keys/{key}`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Is a unique key revision identifier assigned by the server.
	// It is directly used as the 'kid' parameter in the JWK set.
	// I.e.: 'projects/{project}/keys/key_id'
	KeyId string `protobuf:"bytes,2,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// The creation time of the key revision.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// The key revision number for the parent.
	// All the key revisions rotated from the same parent key have the same revision number.
	RevisionNumber int32 `protobuf:"varint,4,opt,name=revision_number,json=revisionNumber,proto3" json:"revision_number,omitempty"`
	// Revocation time of the key.
	// If the key was revoked, it is no longer used for signing and verification.
	// It is not included in the public JWK set.
	// Once rotated, a new key is no longer marked as revoked.
	// Remains null if the key was not revoked.
	RevokeTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=revoke_time,json=revokeTime,proto3" json:"revoke_time,omitempty"`
	// Core from which the key was derived.
	Core string `protobuf:"bytes,6,opt,name=core,proto3" json:"core,omitempty"`
}

func (x *Key) Reset() {
	*x = Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_admin_v1alpha_key_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Key) ProtoMessage() {}

func (x *Key) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_admin_v1alpha_key_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Key.ProtoReflect.Descriptor instead.
func (*Key) Descriptor() ([]byte, []int) {
	return file_blocky_authz_admin_v1alpha_key_proto_rawDescGZIP(), []int{1}
}

func (x *Key) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Key) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *Key) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Key) GetRevisionNumber() int32 {
	if x != nil {
		return x.RevisionNumber
	}
	return 0
}

func (x *Key) GetRevokeTime() *timestamppb.Timestamp {
	if x != nil {
		return x.RevokeTime
	}
	return nil
}

func (x *Key) GetCore() string {
	if x != nil {
		return x.Core
	}
	return ""
}

var File_blocky_authz_admin_v1alpha_key_proto protoreflect.FileDescriptor

var file_blocky_authz_admin_v1alpha_key_proto_rawDesc = []byte{
	0x0a, 0x24, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x6b, 0x65, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x1a, 0x29, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a,
	0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x6c,
	0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f,
	0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xff, 0x04, 0x0a, 0x07, 0x4b,
	0x65, 0x79, 0x43, 0x6f, 0x72, 0x65, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x08, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x18, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x06, 0xe0, 0x41,
	0x03, 0xe0, 0x41, 0x05, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x49, 0x0a, 0x09, 0x61, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x42, 0x06, 0xe0, 0x41, 0x02, 0xe0, 0x41, 0x05, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x12, 0x26, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x07, 0x52,
	0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0,
	0x41, 0x03, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x40,
	0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42,
	0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x4b, 0x0a, 0x11, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0f, 0x6c, 0x61,
	0x73, 0x74, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a,
	0x11, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x10, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x12, 0x1f, 0x0a, 0x08, 0x70, 0x72,
	0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x42, 0x03, 0xe0, 0x41,
	0x07, 0x52, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x31, 0x0a, 0x12, 0x64,
	0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x05, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x10, 0x64, 0x65,
	0x72, 0x69, 0x76, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x73, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x5c,
	0xea, 0x41, 0x59, 0x0a, 0x1c, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x72,
	0x65, 0x12, 0x26, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x7b, 0x70, 0x72, 0x6f,
	0x6a, 0x65, 0x63, 0x74, 0x7d, 0x2f, 0x6b, 0x65, 0x79, 0x43, 0x6f, 0x72, 0x65, 0x73, 0x2f, 0x7b,
	0x6b, 0x65, 0x79, 0x5f, 0x63, 0x6f, 0x72, 0x65, 0x7d, 0x2a, 0x08, 0x6b, 0x65, 0x79, 0x43, 0x6f,
	0x72, 0x65, 0x73, 0x32, 0x07, 0x6b, 0x65, 0x79, 0x43, 0x6f, 0x72, 0x65, 0x22, 0xe4, 0x02, 0x0a,
	0x03, 0x4b, 0x65, 0x79, 0x12, 0x17, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x08, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a,
	0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0,
	0x41, 0x03, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x2c, 0x0a, 0x0f, 0x72,
	0x65, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x05, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0e, 0x72, 0x65, 0x76, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x40, 0x0a, 0x0b, 0x72, 0x65, 0x76,
	0x6f, 0x6b, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x0a, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x04, 0x63,
	0x6f, 0x72, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x42, 0x24, 0xe0, 0x41, 0x03, 0xfa, 0x41,
	0x1e, 0x0a, 0x1c, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61,
	0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x72, 0x65, 0x52,
	0x04, 0x63, 0x6f, 0x72, 0x65, 0x3a, 0x3c, 0xea, 0x41, 0x39, 0x0a, 0x18, 0x61, 0x75, 0x74, 0x68,
	0x7a, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x2f, 0x7b,
	0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x7d, 0x2f, 0x6b, 0x65, 0x79, 0x73, 0x2f, 0x7b, 0x6b,
	0x65, 0x79, 0x7d, 0x42, 0x87, 0x02, 0x0a, 0x1e, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x08, 0x4b, 0x65, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x50, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67,
	0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x3b, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0xa2, 0x02, 0x03, 0x42, 0x41, 0x41, 0xaa, 0x02, 0x1a, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2e,
	0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca, 0x02, 0x1a, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x5c, 0x56, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0xe2, 0x02, 0x26, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75,
	0x74, 0x68, 0x7a, 0x5c, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1d,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x3a, 0x3a, 0x41,
	0x64, 0x6d, 0x69, 0x6e, 0x3a, 0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_authz_admin_v1alpha_key_proto_rawDescOnce sync.Once
	file_blocky_authz_admin_v1alpha_key_proto_rawDescData = file_blocky_authz_admin_v1alpha_key_proto_rawDesc
)

func file_blocky_authz_admin_v1alpha_key_proto_rawDescGZIP() []byte {
	file_blocky_authz_admin_v1alpha_key_proto_rawDescOnce.Do(func() {
		file_blocky_authz_admin_v1alpha_key_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_authz_admin_v1alpha_key_proto_rawDescData)
	})
	return file_blocky_authz_admin_v1alpha_key_proto_rawDescData
}

var file_blocky_authz_admin_v1alpha_key_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_blocky_authz_admin_v1alpha_key_proto_goTypes = []interface{}{
	(*KeyCore)(nil),                 // 0: blocky.authz.admin.v1alpha.KeyCore
	(*Key)(nil),                     // 1: blocky.authz.admin.v1alpha.Key
	(signalgpb.SigningAlgorithm)(0), // 2: blocky.authz.type.SigningAlgorithm
	(*timestamppb.Timestamp)(nil),   // 3: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),     // 4: google.protobuf.Duration
}
var file_blocky_authz_admin_v1alpha_key_proto_depIdxs = []int32{
	2, // 0: blocky.authz.admin.v1alpha.KeyCore.algorithm:type_name -> blocky.authz.type.SigningAlgorithm
	3, // 1: blocky.authz.admin.v1alpha.KeyCore.create_time:type_name -> google.protobuf.Timestamp
	3, // 2: blocky.authz.admin.v1alpha.KeyCore.update_time:type_name -> google.protobuf.Timestamp
	3, // 3: blocky.authz.admin.v1alpha.KeyCore.last_rotated_time:type_name -> google.protobuf.Timestamp
	4, // 4: blocky.authz.admin.v1alpha.KeyCore.rotation_interval:type_name -> google.protobuf.Duration
	3, // 5: blocky.authz.admin.v1alpha.Key.create_time:type_name -> google.protobuf.Timestamp
	3, // 6: blocky.authz.admin.v1alpha.Key.revoke_time:type_name -> google.protobuf.Timestamp
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_blocky_authz_admin_v1alpha_key_proto_init() }
func file_blocky_authz_admin_v1alpha_key_proto_init() {
	if File_blocky_authz_admin_v1alpha_key_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_authz_admin_v1alpha_key_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyCore); i {
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
		file_blocky_authz_admin_v1alpha_key_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Key); i {
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
			RawDescriptor: file_blocky_authz_admin_v1alpha_key_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_authz_admin_v1alpha_key_proto_goTypes,
		DependencyIndexes: file_blocky_authz_admin_v1alpha_key_proto_depIdxs,
		MessageInfos:      file_blocky_authz_admin_v1alpha_key_proto_msgTypes,
	}.Build()
	File_blocky_authz_admin_v1alpha_key_proto = out.File
	file_blocky_authz_admin_v1alpha_key_proto_rawDesc = nil
	file_blocky_authz_admin_v1alpha_key_proto_goTypes = nil
	file_blocky_authz_admin_v1alpha_key_proto_depIdxs = nil
}
