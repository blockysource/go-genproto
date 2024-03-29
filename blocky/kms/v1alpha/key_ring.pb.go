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
// source: blocky/kms/v1alpha/key_ring.proto

package kmspb

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

// Is a ring of cryptographic keys, that can be combined and used for multiple purposes.
type KeyRing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The resource name of the key ring.
	// Key ring names have the form `projects/*/keyRings/*`.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The unique id of the key ring.
	Uid string `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	// The display name of the key ring.
	DisplayName string `protobuf:"bytes,3,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
	// The aliases of the key ring.
	Aliases []string `protobuf:"bytes,4,rep,name=aliases,proto3" json:"aliases,omitempty"`
	// Creation time of the key ring.
	CreateTime *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	// Update time of the key ring.
	UpdateTime *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty"`
	// The resource names of the keys in this key ring.
	Keys []string `protobuf:"bytes,7,rep,name=keys,proto3" json:"keys,omitempty"`
	// Delete protection of the key ring.
	// When the delete protection is set to true, the key ring cannot be deleted,
	// and no keys in the key ring can be deleted either.
	DeleteProtection bool `protobuf:"varint,8,opt,name=delete_protection,json=deleteProtection,proto3" json:"delete_protection,omitempty"`
	// ETag of the key ring.
	Etag string `protobuf:"bytes,9,opt,name=etag,proto3" json:"etag,omitempty"`
}

func (x *KeyRing) Reset() {
	*x = KeyRing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_v1alpha_key_ring_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyRing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyRing) ProtoMessage() {}

func (x *KeyRing) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_v1alpha_key_ring_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyRing.ProtoReflect.Descriptor instead.
func (*KeyRing) Descriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_key_ring_proto_rawDescGZIP(), []int{0}
}

func (x *KeyRing) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KeyRing) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *KeyRing) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

func (x *KeyRing) GetAliases() []string {
	if x != nil {
		return x.Aliases
	}
	return nil
}

func (x *KeyRing) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *KeyRing) GetUpdateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *KeyRing) GetKeys() []string {
	if x != nil {
		return x.Keys
	}
	return nil
}

func (x *KeyRing) GetDeleteProtection() bool {
	if x != nil {
		return x.DeleteProtection
	}
	return false
}

func (x *KeyRing) GetEtag() string {
	if x != nil {
		return x.Etag
	}
	return ""
}

var File_blocky_kms_v1alpha_key_ring_proto protoreflect.FileDescriptor

var file_blocky_kms_v1alpha_key_ring_proto_rawDesc = []byte{
	0x0a, 0x21, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2f, 0x6b, 0x65, 0x79, 0x5f, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x12, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69,
	0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa2, 0x03, 0x0a, 0x07, 0x4b, 0x65, 0x79, 0x52, 0x69, 0x6e, 0x67,
	0x12, 0x36, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x22,
	0xe0, 0x41, 0x02, 0xfa, 0x41, 0x1c, 0x0a, 0x1a, 0x6b, 0x6d, 0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x52, 0x69,
	0x6e, 0x67, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12,
	0x26, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x07, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70,
	0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x07, 0x61, 0x6c, 0x69, 0x61, 0x73,
	0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x07, 0x61,
	0x6c, 0x69, 0x61, 0x73, 0x65, 0x73, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x03, 0xe0, 0x41, 0x03, 0x52, 0x0a,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x32, 0x0a, 0x04, 0x6b, 0x65,
	0x79, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x42, 0x1e, 0xe0, 0x41, 0x01, 0xfa, 0x41, 0x18,
	0x0a, 0x16, 0x6b, 0x6d, 0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x65, 0x79, 0x52, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x12, 0x30,
	0x0a, 0x11, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x10,
	0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x17, 0x0a, 0x04, 0x65, 0x74, 0x61, 0x67, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03,
	0xe0, 0x41, 0x03, 0x52, 0x04, 0x65, 0x74, 0x61, 0x67, 0x42, 0xce, 0x01, 0x0a, 0x16, 0x63, 0x6f,
	0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x42, 0x0c, 0x4b, 0x65, 0x79, 0x52, 0x69, 0x6e, 0x67, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f,
	0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x6b, 0x6d, 0x73,
	0x70, 0x62, 0xa2, 0x02, 0x03, 0x42, 0x4b, 0x58, 0xaa, 0x02, 0x12, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x4b, 0x6d, 0x73, 0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca, 0x02, 0x12,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0xe2, 0x02, 0x1e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c,
	0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0xea, 0x02, 0x14, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x4b, 0x6d,
	0x73, 0x3a, 0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_blocky_kms_v1alpha_key_ring_proto_rawDescOnce sync.Once
	file_blocky_kms_v1alpha_key_ring_proto_rawDescData = file_blocky_kms_v1alpha_key_ring_proto_rawDesc
)

func file_blocky_kms_v1alpha_key_ring_proto_rawDescGZIP() []byte {
	file_blocky_kms_v1alpha_key_ring_proto_rawDescOnce.Do(func() {
		file_blocky_kms_v1alpha_key_ring_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_kms_v1alpha_key_ring_proto_rawDescData)
	})
	return file_blocky_kms_v1alpha_key_ring_proto_rawDescData
}

var file_blocky_kms_v1alpha_key_ring_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_blocky_kms_v1alpha_key_ring_proto_goTypes = []interface{}{
	(*KeyRing)(nil),               // 0: blocky.kms.v1alpha.KeyRing
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_blocky_kms_v1alpha_key_ring_proto_depIdxs = []int32{
	1, // 0: blocky.kms.v1alpha.KeyRing.create_time:type_name -> google.protobuf.Timestamp
	1, // 1: blocky.kms.v1alpha.KeyRing.update_time:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_blocky_kms_v1alpha_key_ring_proto_init() }
func file_blocky_kms_v1alpha_key_ring_proto_init() {
	if File_blocky_kms_v1alpha_key_ring_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_kms_v1alpha_key_ring_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyRing); i {
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
			RawDescriptor: file_blocky_kms_v1alpha_key_ring_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_kms_v1alpha_key_ring_proto_goTypes,
		DependencyIndexes: file_blocky_kms_v1alpha_key_ring_proto_depIdxs,
		MessageInfos:      file_blocky_kms_v1alpha_key_ring_proto_msgTypes,
	}.Build()
	File_blocky_kms_v1alpha_key_ring_proto = out.File
	file_blocky_kms_v1alpha_key_ring_proto_rawDesc = nil
	file_blocky_kms_v1alpha_key_ring_proto_goTypes = nil
	file_blocky_kms_v1alpha_key_ring_proto_depIdxs = nil
}
