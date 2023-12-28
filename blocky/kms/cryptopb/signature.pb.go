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
// source: blocky/kms/crypto/signature.proto

package cryptopb

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// SignedContent is a message that represents a Protobuf Web Signature.
// The resultant signature is in two steps:
// 1. The Signature message with only the header and content fields are serialized and signed using the key.
// 2. The resultant signature is appended to the Signature message.
type SignedContent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Header is the header of the signature.
	Header *SignedContent_Header `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	// Content is the content that was signed.
	Content []byte `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
	// Signature is the signature of the content.
	Signature []byte `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *SignedContent) Reset() {
	*x = SignedContent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_crypto_signature_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedContent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedContent) ProtoMessage() {}

func (x *SignedContent) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_crypto_signature_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedContent.ProtoReflect.Descriptor instead.
func (*SignedContent) Descriptor() ([]byte, []int) {
	return file_blocky_kms_crypto_signature_proto_rawDescGZIP(), []int{0}
}

func (x *SignedContent) GetHeader() *SignedContent_Header {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *SignedContent) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *SignedContent) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

type SignedContent_Header struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Algorithm is the algorithm used to sign the content.
	Algorithm SignatureAlgorithm `protobuf:"varint,1,opt,name=algorithm,json=alg,proto3,enum=blocky.kms.crypto.SignatureAlgorithm" json:"algorithm,omitempty"`
	// Key material resource is the material of the key used to sign the content.
	// This is not a full resource name, but just a key identifier.
	KeyMaterial string `protobuf:"bytes,2,opt,name=key_material,json=kid,proto3" json:"key_material,omitempty"`
	// Metadata is the metadata of the signature.
	Metadata map[string]string `protobuf:"bytes,3,rep,name=metadata,json=meta,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SignedContent_Header) Reset() {
	*x = SignedContent_Header{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_kms_crypto_signature_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignedContent_Header) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignedContent_Header) ProtoMessage() {}

func (x *SignedContent_Header) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_kms_crypto_signature_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignedContent_Header.ProtoReflect.Descriptor instead.
func (*SignedContent_Header) Descriptor() ([]byte, []int) {
	return file_blocky_kms_crypto_signature_proto_rawDescGZIP(), []int{0, 0}
}

func (x *SignedContent_Header) GetAlgorithm() SignatureAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return SignatureAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED
}

func (x *SignedContent_Header) GetKeyMaterial() string {
	if x != nil {
		return x.KeyMaterial
	}
	return ""
}

func (x *SignedContent_Header) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_blocky_kms_crypto_signature_proto protoreflect.FileDescriptor

var file_blocky_kms_crypto_signature_proto_rawDesc = []byte{
	0x0a, 0x21, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x6f, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x11, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x1a, 0x21, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b,
	0x6d, 0x73, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69,
	0x74, 0x68, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61,
	0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xba, 0x03, 0x0a, 0x0d, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
	0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x44, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1d, 0x0a,
	0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03,
	0xe0, 0x41, 0x02, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x12, 0x21, 0x0a, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x42,
	0x03, 0xe0, 0x41, 0x02, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x1a,
	0xa0, 0x02, 0x0a, 0x06, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x42, 0x0a, 0x09, 0x61, 0x6c,
	0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x25, 0x2e,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x03, 0x61, 0x6c, 0x67, 0x12, 0x41,
	0x0a, 0x0c, 0x6b, 0x65, 0x79, 0x5f, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x26, 0xe0, 0x41, 0x02, 0xfa, 0x41, 0x20, 0x0a, 0x1e, 0x6b, 0x6d,
	0x73, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x52, 0x03, 0x6b, 0x69,
	0x64, 0x12, 0x52, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73,
	0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x2e, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52,
	0x04, 0x6d, 0x65, 0x74, 0x61, 0x1a, 0x3b, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x42, 0xcf, 0x01, 0x0a, 0x15, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x42, 0x0e, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x40,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x70, 0x62, 0x3b, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x70, 0x62,
	0xa2, 0x02, 0x03, 0x42, 0x4b, 0x43, 0xaa, 0x02, 0x11, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e,
	0x4b, 0x6d, 0x73, 0x2e, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0xca, 0x02, 0x11, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0xe2, 0x02,
	0x1d, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x43, 0x72, 0x79, 0x70,
	0x74, 0x6f, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02,
	0x13, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x4b, 0x6d, 0x73, 0x3a, 0x3a, 0x43, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_kms_crypto_signature_proto_rawDescOnce sync.Once
	file_blocky_kms_crypto_signature_proto_rawDescData = file_blocky_kms_crypto_signature_proto_rawDesc
)

func file_blocky_kms_crypto_signature_proto_rawDescGZIP() []byte {
	file_blocky_kms_crypto_signature_proto_rawDescOnce.Do(func() {
		file_blocky_kms_crypto_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_kms_crypto_signature_proto_rawDescData)
	})
	return file_blocky_kms_crypto_signature_proto_rawDescData
}

var file_blocky_kms_crypto_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_blocky_kms_crypto_signature_proto_goTypes = []interface{}{
	(*SignedContent)(nil),        // 0: blocky.kms.crypto.SignedContent
	(*SignedContent_Header)(nil), // 1: blocky.kms.crypto.SignedContent.Header
	nil,                          // 2: blocky.kms.crypto.SignedContent.Header.MetadataEntry
	(SignatureAlgorithm)(0),      // 3: blocky.kms.crypto.SignatureAlgorithm
}
var file_blocky_kms_crypto_signature_proto_depIdxs = []int32{
	1, // 0: blocky.kms.crypto.SignedContent.header:type_name -> blocky.kms.crypto.SignedContent.Header
	3, // 1: blocky.kms.crypto.SignedContent.Header.algorithm:type_name -> blocky.kms.crypto.SignatureAlgorithm
	2, // 2: blocky.kms.crypto.SignedContent.Header.metadata:type_name -> blocky.kms.crypto.SignedContent.Header.MetadataEntry
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_blocky_kms_crypto_signature_proto_init() }
func file_blocky_kms_crypto_signature_proto_init() {
	if File_blocky_kms_crypto_signature_proto != nil {
		return
	}
	file_blocky_kms_crypto_algorithm_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_blocky_kms_crypto_signature_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedContent); i {
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
		file_blocky_kms_crypto_signature_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignedContent_Header); i {
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
			RawDescriptor: file_blocky_kms_crypto_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_kms_crypto_signature_proto_goTypes,
		DependencyIndexes: file_blocky_kms_crypto_signature_proto_depIdxs,
		MessageInfos:      file_blocky_kms_crypto_signature_proto_msgTypes,
	}.Build()
	File_blocky_kms_crypto_signature_proto = out.File
	file_blocky_kms_crypto_signature_proto_rawDesc = nil
	file_blocky_kms_crypto_signature_proto_goTypes = nil
	file_blocky_kms_crypto_signature_proto_depIdxs = nil
}
