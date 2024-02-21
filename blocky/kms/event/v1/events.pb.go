// Copyright 2024 The Blocky Authors
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
// source: blocky/kms/event/v1/events.proto

package kmseventpb

import (
	crypto "github.com/blockysource/go-genproto/blocky/type/crypto"
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

// Key represents a cryptographic key.
type Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Resource name of the Key.
	// The format of the key resource name:
	// `keys{key}`
	// `projects/{project}/keys/{key}`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The unique server-generated UUID identifier for the key.
	// It could be used as the key identifier in its resource name.
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// The aliases that can be used to refer to the key.
	// The full path of the alias is:
	// 'keys/{key_alias}'
	Aliases []string `protobuf:"bytes,3,rep,name=aliases,proto3" json:"aliases,omitempty"`
	// The key algorithm type
	AlgorithmType crypto.KeyAlgorithmType `protobuf:"varint,4,opt,name=algorithm_type,json=algorithmType,proto3,enum=blocky.type.crypto.KeyAlgorithmType" json:"algorithm_type,omitempty"`
	// The parameters used to generate the key material.
	AlgorithmParameters *crypto.KeyAlgorithmParameters `protobuf:"bytes,5,opt,name=algorithm_parameters,json=algorithmParameters,proto3" json:"algorithm_parameters,omitempty"`
	// Supported signing algorithms of the key.
	SigningAlgorithms []crypto.SignatureAlgorithm `protobuf:"varint,6,rep,packed,name=signing_algorithms,json=signingAlgorithms,proto3,enum=blocky.type.crypto.SignatureAlgorithm" json:"signing_algorithms,omitempty"`
	// Supported encryption algorithms of the key.
	EncryptionAlgorithms []crypto.EncryptionAlgorithm `protobuf:"varint,7,rep,packed,name=encryption_algorithms,json=encryptionAlgorithms,proto3,enum=blocky.type.crypto.EncryptionAlgorithm" json:"encryption_algorithms,omitempty"`
	// The display name of the key.
	DisplayName string `protobuf:"bytes,8,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// Time when the key was created.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,9,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// Time when the key was updated.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,10,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// Time when the key was last rotated.
	LastRotatedTime *timestamppb.Timestamp `protobuf:"bytes,11,opt,name=last_rotated_time,json=lastRotatedTime,proto3" json:"last_rotated_time,omitempty"`
	// Rotation interval of the material derived from this key.
	// If not provided, the key will not be rotated automatically.
	RotationInterval *durationpb.Duration `protobuf:"bytes,12,opt,name=rotation_interval,json=rotationInterval,proto3" json:"rotation_interval,omitempty"`
	// Determines if a key is protected against accidental deletion.
	// If not provided, the key will not be protected.
	DestroyProtection bool `protobuf:"varint,13,opt,name=destroy_protection,json=destroyProtection,proto3" json:"destroy_protection,omitempty"`
}

func (x *Key) Reset() {
	*x = Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Key) ProtoMessage() {}

func (x *Key) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[0]
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
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{0}
}

func (x *Key) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Key) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *Key) GetAliases() []string {
	if x != nil {
		return x.Aliases
	}
	return nil
}

func (x *Key) GetAlgorithmType() crypto.KeyAlgorithmType {
	if x != nil {
		return x.AlgorithmType
	}
	return crypto.KeyAlgorithmType(0)
}

func (x *Key) GetAlgorithmParameters() *crypto.KeyAlgorithmParameters {
	if x != nil {
		return x.AlgorithmParameters
	}
	return nil
}

func (x *Key) GetSigningAlgorithms() []crypto.SignatureAlgorithm {
	if x != nil {
		return x.SigningAlgorithms
	}
	return nil
}

func (x *Key) GetEncryptionAlgorithms() []crypto.EncryptionAlgorithm {
	if x != nil {
		return x.EncryptionAlgorithms
	}
	return nil
}

func (x *Key) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *Key) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Key) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *Key) GetLastRotatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.LastRotatedTime
	}
	return nil
}

func (x *Key) GetRotationInterval() *durationpb.Duration {
	if x != nil {
		return x.RotationInterval
	}
	return nil
}

func (x *Key) GetDestroyProtection() bool {
	if x != nil {
		return x.DestroyProtection
	}
	return false
}

// Is a cryptographic key material directly used for the cryptographic operations.
// The parameters of the material are derived from the key.
type KeyMaterial struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The resource name of the key material.
	// The format of the key material resource name:
	// `keys/{key}/materials/{material}`
	// `projects/{project}/keys/{key}/materials/{material}`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The creation time of the key material.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// The public content of the key material.
	PublicKey *crypto.KeyMaterial `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *KeyMaterial) Reset() {
	*x = KeyMaterial{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyMaterial) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMaterial) ProtoMessage() {}

func (x *KeyMaterial) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyMaterial.ProtoReflect.Descriptor instead.
func (*KeyMaterial) Descriptor() ([]byte, []int) {
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{1}
}

func (x *KeyMaterial) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KeyMaterial) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *KeyMaterial) GetPublicKey() *crypto.KeyMaterial {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// An event message that is published when a key is created.
type KeyCreated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The key that was created.
	Key *Key `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *KeyCreated) Reset() {
	*x = KeyCreated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyCreated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyCreated) ProtoMessage() {}

func (x *KeyCreated) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyCreated.ProtoReflect.Descriptor instead.
func (*KeyCreated) Descriptor() ([]byte, []int) {
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{2}
}

func (x *KeyCreated) GetKey() *Key {
	if x != nil {
		return x.Key
	}
	return nil
}

// An event message that is published when a key is updated.
type KeyUpdated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The key that was updated.
	Key *Key `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *KeyUpdated) Reset() {
	*x = KeyUpdated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyUpdated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyUpdated) ProtoMessage() {}

func (x *KeyUpdated) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyUpdated.ProtoReflect.Descriptor instead.
func (*KeyUpdated) Descriptor() ([]byte, []int) {
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{3}
}

func (x *KeyUpdated) GetKey() *Key {
	if x != nil {
		return x.Key
	}
	return nil
}

// An event message that is published when a key is deleted.
type KeyDeleted struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the key resource that is deleted.
	// The format of the key resource name:
	// `keys/{key}`
	// `projects/{project}/keys/{key}`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *KeyDeleted) Reset() {
	*x = KeyDeleted{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyDeleted) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyDeleted) ProtoMessage() {}

func (x *KeyDeleted) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyDeleted.ProtoReflect.Descriptor instead.
func (*KeyDeleted) Descriptor() ([]byte, []int) {
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{4}
}

func (x *KeyDeleted) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// An event message that is published when a key material is created.
type KeyMaterialCreated struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The key material that was created.
	KeyMaterial *KeyMaterial `protobuf:"bytes,1,opt,name=key_material,json=keyMaterial,proto3" json:"key_material,omitempty"`
}

func (x *KeyMaterialCreated) Reset() {
	*x = KeyMaterialCreated{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_event_v1_events_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyMaterialCreated) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMaterialCreated) ProtoMessage() {}

func (x *KeyMaterialCreated) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_event_v1_events_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyMaterialCreated.ProtoReflect.Descriptor instead.
func (*KeyMaterialCreated) Descriptor() ([]byte, []int) {
	return file_blocky_kms_event_v1_events_proto_rawDescGZIP(), []int{5}
}

func (x *KeyMaterialCreated) GetKeyMaterial() *KeyMaterial {
	if x != nil {
		return x.KeyMaterial
	}
	return nil
}

var File_blocky_kms_event_v1_events_proto protoreflect.FileDescriptor

var file_blocky_kms_event_v1_events_proto_rawDesc = []byte{
	0x0a, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x65, 0x76, 0x65,
	0x6e, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x13, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x65,
	0x76, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x22, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x61, 0x6c, 0x67, 0x6f,
	0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x25, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f,
	0x6b, 0x65, 0x79, 0x5f, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66,
	0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xe7, 0x06, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x32, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xe0, 0x41, 0x08, 0xfa, 0x41, 0x18, 0x0a, 0x16, 0x6b,
	0x6d, 0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x03, 0x75,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x06, 0xe0, 0x41, 0x03, 0xe0, 0x41, 0x05,
	0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x1d, 0x0a, 0x07, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x07, 0x61, 0x6c, 0x69,
	0x61, 0x73, 0x65, 0x73, 0x12, 0x53, 0x0a, 0x0e, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x24, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2e, 0x4b, 0x65, 0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x54, 0x79,
	0x70, 0x65, 0x42, 0x06, 0xe0, 0x41, 0x02, 0xe0, 0x41, 0x05, 0x52, 0x0d, 0x61, 0x6c, 0x67, 0x6f,
	0x72, 0x69, 0x74, 0x68, 0x6d, 0x54, 0x79, 0x70, 0x65, 0x12, 0x65, 0x0a, 0x14, 0x61, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72,
	0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x4b, 0x65, 0x79,
	0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74,
	0x65, 0x72, 0x73, 0x42, 0x06, 0xe0, 0x41, 0x02, 0xe0, 0x41, 0x05, 0x52, 0x13, 0x61, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73,
	0x12, 0x5a, 0x0a, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f,
	0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x26, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x69,
	0x6e, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x12, 0x61, 0x0a, 0x15,
	0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x27, 0x2e, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x14, 0x65, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x73, 0x12,
	0x26, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x07, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70,
	0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52,
	0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x11, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0f, 0x6c, 0x61, 0x73, 0x74, 0x52, 0x6f, 0x74,
	0x61, 0x74, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x11, 0x72, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x03,
	0xe0, 0x41, 0x01, 0x52, 0x10, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x74,
	0x65, 0x72, 0x76, 0x61, 0x6c, 0x12, 0x32, 0x0a, 0x12, 0x64, 0x65, 0x73, 0x74, 0x72, 0x6f, 0x79,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x08, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x11, 0x64, 0x65, 0x73, 0x74, 0x72, 0x6f, 0x79, 0x50,
	0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0xd0, 0x01, 0x0a, 0x0b, 0x4b, 0x65,
	0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x12, 0x3a, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x26, 0xe0, 0x41, 0x08, 0xfa, 0x41, 0x20, 0x0a,
	0x1e, 0x6b, 0x6d, 0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x43, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x2e, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x42, 0x03, 0xe0, 0x41,
	0x02, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x3d, 0x0a, 0x0a,
	0x4b, 0x65, 0x79, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12, 0x2f, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4b, 0x65,
	0x79, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x22, 0x3d, 0x0a, 0x0a, 0x4b,
	0x65, 0x79, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x2f, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e,
	0x6b, 0x6d, 0x73, 0x2e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4b, 0x65, 0x79,
	0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x22, 0x40, 0x0a, 0x0a, 0x4b, 0x65,
	0x79, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x12, 0x32, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xe0, 0x41, 0x08, 0xfa, 0x41, 0x18, 0x0a, 0x16,
	0x6b, 0x6d, 0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x5e, 0x0a, 0x12,
	0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x64, 0x12, 0x48, 0x0a, 0x0c, 0x6b, 0x65, 0x79, 0x5f, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69,
	0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x4b,
	0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52,
	0x0b, 0x6b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x42, 0xd9, 0x01, 0x0a,
	0x17, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x42, 0x0b, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2f, 0x76, 0x31,
	0x3b, 0x6b, 0x6d, 0x73, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x42, 0x4b,
	0x45, 0xaa, 0x02, 0x13, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x4b, 0x6d, 0x73, 0x2e, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x13, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x1f,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea,
	0x02, 0x16, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x4b, 0x6d, 0x73, 0x3a, 0x3a, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_kms_event_v1_events_proto_rawDescOnce sync.Once
	file_blocky_kms_event_v1_events_proto_rawDescData = file_blocky_kms_event_v1_events_proto_rawDesc
)

func file_blocky_kms_event_v1_events_proto_rawDescGZIP() []byte {
	file_blocky_kms_event_v1_events_proto_rawDescOnce.Do(func() {
		file_blocky_kms_event_v1_events_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_kms_event_v1_events_proto_rawDescData)
	})
	return file_blocky_kms_event_v1_events_proto_rawDescData
}

var file_blocky_kms_event_v1_events_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_blocky_kms_event_v1_events_proto_goTypes = []interface{}{
	(*Key)(nil),                           // 0: blocky.kms.event.v1.Key
	(*KeyMaterial)(nil),                   // 1: blocky.kms.event.v1.KeyMaterial
	(*KeyCreated)(nil),                    // 2: blocky.kms.event.v1.KeyCreated
	(*KeyUpdated)(nil),                    // 3: blocky.kms.event.v1.KeyUpdated
	(*KeyDeleted)(nil),                    // 4: blocky.kms.event.v1.KeyDeleted
	(*KeyMaterialCreated)(nil),            // 5: blocky.kms.event.v1.KeyMaterialCreated
	(crypto.KeyAlgorithmType)(0),          // 6: blocky.type.crypto.KeyAlgorithmType
	(*crypto.KeyAlgorithmParameters)(nil), // 7: blocky.type.crypto.KeyAlgorithmParameters
	(crypto.SignatureAlgorithm)(0),        // 8: blocky.type.crypto.SignatureAlgorithm
	(crypto.EncryptionAlgorithm)(0),       // 9: blocky.type.crypto.EncryptionAlgorithm
	(*timestamppb.Timestamp)(nil),         // 10: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),           // 11: google.protobuf.Duration
	(*crypto.KeyMaterial)(nil),            // 12: blocky.type.crypto.KeyMaterial
}
var file_blocky_kms_event_v1_events_proto_depIdxs = []int32{
	6,  // 0: blocky.kms.event.v1.Key.algorithm_type:type_name -> blocky.type.crypto.KeyAlgorithmType
	7,  // 1: blocky.kms.event.v1.Key.algorithm_parameters:type_name -> blocky.type.crypto.KeyAlgorithmParameters
	8,  // 2: blocky.kms.event.v1.Key.signing_algorithms:type_name -> blocky.type.crypto.SignatureAlgorithm
	9,  // 3: blocky.kms.event.v1.Key.encryption_algorithms:type_name -> blocky.type.crypto.EncryptionAlgorithm
	10, // 4: blocky.kms.event.v1.Key.create_time:type_name -> google.protobuf.Timestamp
	10, // 5: blocky.kms.event.v1.Key.update_time:type_name -> google.protobuf.Timestamp
	10, // 6: blocky.kms.event.v1.Key.last_rotated_time:type_name -> google.protobuf.Timestamp
	11, // 7: blocky.kms.event.v1.Key.rotation_interval:type_name -> google.protobuf.Duration
	10, // 8: blocky.kms.event.v1.KeyMaterial.create_time:type_name -> google.protobuf.Timestamp
	12, // 9: blocky.kms.event.v1.KeyMaterial.public_key:type_name -> blocky.type.crypto.KeyMaterial
	0,  // 10: blocky.kms.event.v1.KeyCreated.key:type_name -> blocky.kms.event.v1.Key
	0,  // 11: blocky.kms.event.v1.KeyUpdated.key:type_name -> blocky.kms.event.v1.Key
	1,  // 12: blocky.kms.event.v1.KeyMaterialCreated.key_material:type_name -> blocky.kms.event.v1.KeyMaterial
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_blocky_kms_event_v1_events_proto_init() }
func file_blocky_kms_event_v1_events_proto_init() {
	if File_blocky_kms_event_v1_events_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_kms_event_v1_events_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_blocky_kms_event_v1_events_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyMaterial); i {
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
		file_blocky_kms_event_v1_events_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyCreated); i {
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
		file_blocky_kms_event_v1_events_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyUpdated); i {
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
		file_blocky_kms_event_v1_events_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyDeleted); i {
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
		file_blocky_kms_event_v1_events_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyMaterialCreated); i {
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
			RawDescriptor: file_blocky_kms_event_v1_events_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_kms_event_v1_events_proto_goTypes,
		DependencyIndexes: file_blocky_kms_event_v1_events_proto_depIdxs,
		MessageInfos:      file_blocky_kms_event_v1_events_proto_msgTypes,
	}.Build()
	File_blocky_kms_event_v1_events_proto = out.File
	file_blocky_kms_event_v1_events_proto_rawDesc = nil
	file_blocky_kms_event_v1_events_proto_goTypes = nil
	file_blocky_kms_event_v1_events_proto_depIdxs = nil
}
