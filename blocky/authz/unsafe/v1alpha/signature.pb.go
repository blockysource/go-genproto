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
// source: blocky/authz/unsafe/v1alpha/signature.proto

package authzunsafev1alpha

import (
	signalgpb "github.com/blockysource/go-genproto/blocky/authz/type/signalgpb"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Request message for
// [SignaturesService.SignClaims][blocky.authz.unsafe.v1alpha.SignaturesService.SignClaims].
type SignClaimsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The claims to sign.
	Claims *structpb.Struct `protobuf:"bytes,1,opt,name=claims,proto3" json:"claims,omitempty"`
	// Optional signature type to use.
	// If not specified a signature is generated using the default key
	// and the default signing algorithm.
	// The signature type may be used to override the default key and algorithm.
	// This field relates to the signature type id in the
	// [SignatureType][blocky.authz.unsafe.v1alpha.SignatureType] message.
	SignatureTypeId string `protobuf:"bytes,2,opt,name=signature_type_id,json=signatureTypeId,proto3" json:"signature_type_id,omitempty"`
	// Optional key id to use.
	// If not specified the default key id is used.
	// This field relates to the field:
	// [Key][blocky.authz.unsafe.v1alpha.Key.key_id].
	KeyId string `protobuf:"bytes,3,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// Optional signing algorithm to use.
	// If not specified the default signing algorithm is used.
	// If no matching algorithm is found, an error is returned.
	SigningAlgorithm signalgpb.SigningAlgorithm `protobuf:"varint,4,opt,name=signing_algorithm,json=signingAlgorithm,proto3,enum=blocky.authz.type.SigningAlgorithm" json:"signing_algorithm,omitempty"`
}

func (x *SignClaimsRequest) Reset() {
	*x = SignClaimsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignClaimsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignClaimsRequest) ProtoMessage() {}

func (x *SignClaimsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignClaimsRequest.ProtoReflect.Descriptor instead.
func (*SignClaimsRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescGZIP(), []int{0}
}

func (x *SignClaimsRequest) GetClaims() *structpb.Struct {
	if x != nil {
		return x.Claims
	}
	return nil
}

func (x *SignClaimsRequest) GetSignatureTypeId() string {
	if x != nil {
		return x.SignatureTypeId
	}
	return ""
}

func (x *SignClaimsRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *SignClaimsRequest) GetSigningAlgorithm() signalgpb.SigningAlgorithm {
	if x != nil {
		return x.SigningAlgorithm
	}
	return signalgpb.SigningAlgorithm(0)
}

// Response message for
// [SignaturesService.SignClaims][blocky.authz.unsafe.v1alpha.SignaturesService.SignClaims].
type SignClaimsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The compacted JWS token as defined in RFC 7515.
	Token string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *SignClaimsResponse) Reset() {
	*x = SignClaimsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignClaimsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignClaimsResponse) ProtoMessage() {}

func (x *SignClaimsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignClaimsResponse.ProtoReflect.Descriptor instead.
func (*SignClaimsResponse) Descriptor() ([]byte, []int) {
	return file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescGZIP(), []int{1}
}

func (x *SignClaimsResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

// Request message for
// [SignaturesService.IntrospectSignature][blocky.authz.unsafe.v1alpha.SignaturesService.IntrospectSignature].
type IntrospectSignatureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required signature to introspect.
	Signature string `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *IntrospectSignatureRequest) Reset() {
	*x = IntrospectSignatureRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IntrospectSignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntrospectSignatureRequest) ProtoMessage() {}

func (x *IntrospectSignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntrospectSignatureRequest.ProtoReflect.Descriptor instead.
func (*IntrospectSignatureRequest) Descriptor() ([]byte, []int) {
	return file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescGZIP(), []int{2}
}

func (x *IntrospectSignatureRequest) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

// Response message for
// [SignaturesService.IntrospectSignature][blocky.authz.unsafe.v1alpha.SignaturesService.IntrospectSignature].
type IntrospectSignatureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The claims returned by the introspection.
	Claims *structpb.Struct `protobuf:"bytes,1,opt,name=claims,proto3" json:"claims,omitempty"`
}

func (x *IntrospectSignatureResponse) Reset() {
	*x = IntrospectSignatureResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IntrospectSignatureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntrospectSignatureResponse) ProtoMessage() {}

func (x *IntrospectSignatureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntrospectSignatureResponse.ProtoReflect.Descriptor instead.
func (*IntrospectSignatureResponse) Descriptor() ([]byte, []int) {
	return file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescGZIP(), []int{3}
}

func (x *IntrospectSignatureResponse) GetClaims() *structpb.Struct {
	if x != nil {
		return x.Claims
	}
	return nil
}

var File_blocky_authz_unsafe_v1alpha_signature_proto protoreflect.FileDescriptor

var file_blocky_authz_unsafe_v1alpha_signature_proto_rawDesc = []byte{
	0x0a, 0x2b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x75,
	0x6e, 0x73, 0x61, 0x66, 0x65, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1b, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e, 0x73, 0x61,
	0x66, 0x65, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x29, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x73, 0x69,
	0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xed, 0x01, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x6c, 0x61,
	0x69, 0x6d, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x06, 0x63, 0x6c,
	0x61, 0x69, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x75, 0x63, 0x74, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x73,
	0x12, 0x2f, 0x0a, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x01,
	0x52, 0x0f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x54, 0x79, 0x70, 0x65, 0x49,
	0x64, 0x12, 0x1a, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x55, 0x0a,
	0x11, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74,
	0x68, 0x6d, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x53, 0x69, 0x67,
	0x6e, 0x69, 0x6e, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x42, 0x03, 0xe0,
	0x41, 0x01, 0x52, 0x10, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x41, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x22, 0x2a, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x6c, 0x61, 0x69,
	0x6d, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x22, 0x3f, 0x0a, 0x1a, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x21,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x22, 0x4e, 0x0a, 0x1b, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2f, 0x0a, 0x06, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x06, 0x63, 0x6c, 0x61, 0x69, 0x6d,
	0x73, 0x32, 0x8d, 0x02, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x6d, 0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x43,
	0x6c, 0x61, 0x69, 0x6d, 0x73, 0x12, 0x2e, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2f, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x88, 0x01, 0x0a, 0x13, 0x49, 0x6e, 0x74, 0x72, 0x6f,
	0x73, 0x70, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x37,
	0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e,
	0x73, 0x61, 0x66, 0x65, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x49, 0x6e, 0x74,
	0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x38, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74,
	0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x42, 0x94, 0x02, 0x0a, 0x1f, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x0e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x52, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65,
	0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x75, 0x6e,
	0x73, 0x61, 0x66, 0x65, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xa2, 0x02, 0x03, 0x42, 0x41,
	0x55, 0xaa, 0x02, 0x1b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x7a,
	0x2e, 0x55, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca,
	0x02, 0x1b, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x55,
	0x6e, 0x73, 0x61, 0x66, 0x65, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xe2, 0x02, 0x27,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x5c, 0x55, 0x6e, 0x73,
	0x61, 0x66, 0x65, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x1e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79,
	0x3a, 0x3a, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x3a, 0x3a, 0x55, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x3a,
	0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescOnce sync.Once
	file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescData = file_blocky_authz_unsafe_v1alpha_signature_proto_rawDesc
)

func file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescGZIP() []byte {
	file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescOnce.Do(func() {
		file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescData)
	})
	return file_blocky_authz_unsafe_v1alpha_signature_proto_rawDescData
}

var file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_blocky_authz_unsafe_v1alpha_signature_proto_goTypes = []interface{}{
	(*SignClaimsRequest)(nil),           // 0: blocky.authz.unsafe.v1alpha.SignClaimsRequest
	(*SignClaimsResponse)(nil),          // 1: blocky.authz.unsafe.v1alpha.SignClaimsResponse
	(*IntrospectSignatureRequest)(nil),  // 2: blocky.authz.unsafe.v1alpha.IntrospectSignatureRequest
	(*IntrospectSignatureResponse)(nil), // 3: blocky.authz.unsafe.v1alpha.IntrospectSignatureResponse
	(*structpb.Struct)(nil),             // 4: google.protobuf.Struct
	(signalgpb.SigningAlgorithm)(0),     // 5: blocky.authz.type.SigningAlgorithm
}
var file_blocky_authz_unsafe_v1alpha_signature_proto_depIdxs = []int32{
	4, // 0: blocky.authz.unsafe.v1alpha.SignClaimsRequest.claims:type_name -> google.protobuf.Struct
	5, // 1: blocky.authz.unsafe.v1alpha.SignClaimsRequest.signing_algorithm:type_name -> blocky.authz.type.SigningAlgorithm
	4, // 2: blocky.authz.unsafe.v1alpha.IntrospectSignatureResponse.claims:type_name -> google.protobuf.Struct
	0, // 3: blocky.authz.unsafe.v1alpha.SignaturesService.SignClaims:input_type -> blocky.authz.unsafe.v1alpha.SignClaimsRequest
	2, // 4: blocky.authz.unsafe.v1alpha.SignaturesService.IntrospectSignature:input_type -> blocky.authz.unsafe.v1alpha.IntrospectSignatureRequest
	1, // 5: blocky.authz.unsafe.v1alpha.SignaturesService.SignClaims:output_type -> blocky.authz.unsafe.v1alpha.SignClaimsResponse
	3, // 6: blocky.authz.unsafe.v1alpha.SignaturesService.IntrospectSignature:output_type -> blocky.authz.unsafe.v1alpha.IntrospectSignatureResponse
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_blocky_authz_unsafe_v1alpha_signature_proto_init() }
func file_blocky_authz_unsafe_v1alpha_signature_proto_init() {
	if File_blocky_authz_unsafe_v1alpha_signature_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignClaimsRequest); i {
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
		file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignClaimsResponse); i {
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
		file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IntrospectSignatureRequest); i {
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
		file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IntrospectSignatureResponse); i {
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
			RawDescriptor: file_blocky_authz_unsafe_v1alpha_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_blocky_authz_unsafe_v1alpha_signature_proto_goTypes,
		DependencyIndexes: file_blocky_authz_unsafe_v1alpha_signature_proto_depIdxs,
		MessageInfos:      file_blocky_authz_unsafe_v1alpha_signature_proto_msgTypes,
	}.Build()
	File_blocky_authz_unsafe_v1alpha_signature_proto = out.File
	file_blocky_authz_unsafe_v1alpha_signature_proto_rawDesc = nil
	file_blocky_authz_unsafe_v1alpha_signature_proto_goTypes = nil
	file_blocky_authz_unsafe_v1alpha_signature_proto_depIdxs = nil
}
