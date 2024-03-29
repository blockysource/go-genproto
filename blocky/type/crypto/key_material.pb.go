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
// source: blocky/type/crypto/key_material.proto

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

// KeyAlgorithmType is an algorithm used to generate and verify JSON Web Keys (JWK) as defined in RFC 7518.
type KeyAlgorithmType int32

const (
	// Unspecified key type.
	KeyAlgorithmType_KEY_ALGORITHM_TYPE_UNSPECIFIED KeyAlgorithmType = 0
	// KeyType of type Elliptic Curve (EC) key
	KeyAlgorithmType_EC KeyAlgorithmType = 1
	// KeyType of type RSA key
	KeyAlgorithmType_RSA KeyAlgorithmType = 2
	// KeyType of type Octet sequence (used to represent symmetric keys)
	KeyAlgorithmType_OCTET KeyAlgorithmType = 3
	// KeyType of type OKP key.
	KeyAlgorithmType_OKP KeyAlgorithmType = 4
)

// Enum value maps for KeyAlgorithmType.
var (
	KeyAlgorithmType_name = map[int32]string{
		0: "KEY_ALGORITHM_TYPE_UNSPECIFIED",
		1: "EC",
		2: "RSA",
		3: "OCTET",
		4: "OKP",
	}
	KeyAlgorithmType_value = map[string]int32{
		"KEY_ALGORITHM_TYPE_UNSPECIFIED": 0,
		"EC":                             1,
		"RSA":                            2,
		"OCTET":                          3,
		"OKP":                            4,
	}
)

func (x KeyAlgorithmType) Enum() *KeyAlgorithmType {
	p := new(KeyAlgorithmType)
	*p = x
	return p
}

func (x KeyAlgorithmType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyAlgorithmType) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_type_crypto_key_material_proto_enumTypes[0].Descriptor()
}

func (KeyAlgorithmType) Type() protoreflect.EnumType {
	return &file_blocky_type_crypto_key_material_proto_enumTypes[0]
}

func (x KeyAlgorithmType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyAlgorithmType.Descriptor instead.
func (KeyAlgorithmType) EnumDescriptor() ([]byte, []int) {
	return file_blocky_type_crypto_key_material_proto_rawDescGZIP(), []int{0}
}

// Curve defines the curve used to encode the key material content.
type Curve int32

const (
	// Unspecified curve.
	Curve_CURVE_UNSPECIFIED Curve = 0
	// The NIST P-256 elliptic curve.
	Curve_P256 Curve = 1
	// The NIST P-384 elliptic curve.
	Curve_P384 Curve = 2
	// The NIST P-521 elliptic curve.
	Curve_P521 Curve = 3
	// The elliptic curve used by the Edwards-curve Digital Signature Algorithm (EdDSA).
	Curve_ED25519 Curve = 4
)

// Enum value maps for Curve.
var (
	Curve_name = map[int32]string{
		0: "CURVE_UNSPECIFIED",
		1: "P256",
		2: "P384",
		3: "P521",
		4: "ED25519",
	}
	Curve_value = map[string]int32{
		"CURVE_UNSPECIFIED": 0,
		"P256":              1,
		"P384":              2,
		"P521":              3,
		"ED25519":           4,
	}
)

func (x Curve) Enum() *Curve {
	p := new(Curve)
	*p = x
	return p
}

func (x Curve) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Curve) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_type_crypto_key_material_proto_enumTypes[1].Descriptor()
}

func (Curve) Type() protoreflect.EnumType {
	return &file_blocky_type_crypto_key_material_proto_enumTypes[1]
}

func (x Curve) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Curve.Descriptor instead.
func (Curve) EnumDescriptor() ([]byte, []int) {
	return file_blocky_type_crypto_key_material_proto_rawDescGZIP(), []int{1}
}

// The content of the cryptographical key.
type KeyMaterial struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The key material content type.
	Type KeyAlgorithmType `protobuf:"varint,1,opt,name=type,proto3,enum=blocky.type.crypto.KeyAlgorithmType" json:"type,omitempty"`
	// The elliptic curve used to encode the key material content.
	// This field only applies to Elliptic Curve and OKP key types.
	Curve Curve `protobuf:"varint,2,opt,name=curve,proto3,enum=blocky.type.crypto.Curve" json:"curve,omitempty"`
	// The symmetric key material content.
	K []byte `protobuf:"bytes,3,opt,name=k,proto3" json:"k,omitempty"`
	// Elliptic Curve Public X Coordinate parameter.
	// For ED25519 curve, it is the public key.
	X []byte `protobuf:"bytes,4,opt,name=x,proto3" json:"x,omitempty"`
	// Elliptic Curve Public Y Coordinate parameter.
	Y []byte `protobuf:"bytes,5,opt,name=y,proto3" json:"y,omitempty"`
	// RSA modulus parameter
	N []byte `protobuf:"bytes,6,opt,name=n,proto3" json:"n,omitempty"`
	// Exponent parameter used to generate the RSA key.
	E []byte `protobuf:"bytes,7,opt,name=e,proto3" json:"e,omitempty"`
	// Elliptic Curve Private Key parameter.
	// For ED25519 curve, it is the private key.
	D []byte `protobuf:"bytes,8,opt,name=d,proto3" json:"d,omitempty"`
	// First prime factor of the RSA modulus.
	P []byte `protobuf:"bytes,9,opt,name=p,proto3" json:"p,omitempty"`
	// Second prime factor of the RSA modulus.
	Q []byte `protobuf:"bytes,10,opt,name=q,proto3" json:"q,omitempty"`
	// First Factor Chinese Remainder Theorem (CRT) exponent.
	Dp []byte `protobuf:"bytes,11,opt,name=dp,proto3" json:"dp,omitempty"`
	// Second Factor CRT exponent.
	Dq []byte `protobuf:"bytes,12,opt,name=dq,proto3" json:"dq,omitempty"`
	// First CRT coefficient.
	Qi []byte `protobuf:"bytes,13,opt,name=qi,proto3" json:"qi,omitempty"`
}

func (x *KeyMaterial) Reset() {
	*x = KeyMaterial{}
	if protoimpl.UnsafeEnabled {
		mi := &file_blocky_type_crypto_key_material_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyMaterial) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyMaterial) ProtoMessage() {}

func (x *KeyMaterial) ProtoReflect() protoreflect.Message {
	mi := &file_blocky_type_crypto_key_material_proto_msgTypes[0]
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
	return file_blocky_type_crypto_key_material_proto_rawDescGZIP(), []int{0}
}

func (x *KeyMaterial) GetType() KeyAlgorithmType {
	if x != nil {
		return x.Type
	}
	return KeyAlgorithmType_KEY_ALGORITHM_TYPE_UNSPECIFIED
}

func (x *KeyMaterial) GetCurve() Curve {
	if x != nil {
		return x.Curve
	}
	return Curve_CURVE_UNSPECIFIED
}

func (x *KeyMaterial) GetK() []byte {
	if x != nil {
		return x.K
	}
	return nil
}

func (x *KeyMaterial) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *KeyMaterial) GetY() []byte {
	if x != nil {
		return x.Y
	}
	return nil
}

func (x *KeyMaterial) GetN() []byte {
	if x != nil {
		return x.N
	}
	return nil
}

func (x *KeyMaterial) GetE() []byte {
	if x != nil {
		return x.E
	}
	return nil
}

func (x *KeyMaterial) GetD() []byte {
	if x != nil {
		return x.D
	}
	return nil
}

func (x *KeyMaterial) GetP() []byte {
	if x != nil {
		return x.P
	}
	return nil
}

func (x *KeyMaterial) GetQ() []byte {
	if x != nil {
		return x.Q
	}
	return nil
}

func (x *KeyMaterial) GetDp() []byte {
	if x != nil {
		return x.Dp
	}
	return nil
}

func (x *KeyMaterial) GetDq() []byte {
	if x != nil {
		return x.Dq
	}
	return nil
}

func (x *KeyMaterial) GetQi() []byte {
	if x != nil {
		return x.Qi
	}
	return nil
}

var File_blocky_type_crypto_key_material_proto protoreflect.FileDescriptor

var file_blocky_type_crypto_key_material_proto_rawDesc = []byte{
	0x0a, 0x25, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x2f, 0x6b, 0x65, 0x79, 0x5f, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
	0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65,
	0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa2, 0x02, 0x0a,
	0x0b, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x12, 0x3d, 0x0a, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x24, 0x2e, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
	0x4b, 0x65, 0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x54, 0x79, 0x70, 0x65,
	0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x34, 0x0a, 0x05, 0x63,
	0x75, 0x72, 0x76, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
	0x43, 0x75, 0x72, 0x76, 0x65, 0x42, 0x03, 0xe0, 0x41, 0x01, 0x52, 0x05, 0x63, 0x75, 0x72, 0x76,
	0x65, 0x12, 0x0c, 0x0a, 0x01, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x6b, 0x12,
	0x0c, 0x0a, 0x01, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0c, 0x0a,
	0x01, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x6e,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x6e, 0x12, 0x0c, 0x0a, 0x01, 0x65, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x65, 0x12, 0x0c, 0x0a, 0x01, 0x64, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x64, 0x12, 0x0c, 0x0a, 0x01, 0x70, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x70, 0x12, 0x0c, 0x0a, 0x01, 0x71, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01,
	0x71, 0x12, 0x0e, 0x0a, 0x02, 0x64, 0x70, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x64,
	0x70, 0x12, 0x0e, 0x0a, 0x02, 0x64, 0x71, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x64,
	0x71, 0x12, 0x0e, 0x0a, 0x02, 0x71, 0x69, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x71,
	0x69, 0x2a, 0x5b, 0x0a, 0x10, 0x4b, 0x65, 0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x1e, 0x4b, 0x45, 0x59, 0x5f, 0x41, 0x4c, 0x47,
	0x4f, 0x52, 0x49, 0x54, 0x48, 0x4d, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x45, 0x43, 0x10,
	0x01, 0x12, 0x07, 0x0a, 0x03, 0x52, 0x53, 0x41, 0x10, 0x02, 0x12, 0x09, 0x0a, 0x05, 0x4f, 0x43,
	0x54, 0x45, 0x54, 0x10, 0x03, 0x12, 0x07, 0x0a, 0x03, 0x4f, 0x4b, 0x50, 0x10, 0x04, 0x2a, 0x49,
	0x0a, 0x05, 0x43, 0x75, 0x72, 0x76, 0x65, 0x12, 0x15, 0x0a, 0x11, 0x43, 0x55, 0x52, 0x56, 0x45,
	0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x08,
	0x0a, 0x04, 0x50, 0x32, 0x35, 0x36, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x50, 0x33, 0x38, 0x34,
	0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x50, 0x35, 0x32, 0x31, 0x10, 0x03, 0x12, 0x0b, 0x0a, 0x07,
	0x45, 0x44, 0x32, 0x35, 0x35, 0x31, 0x39, 0x10, 0x04, 0x42, 0xd5, 0x01, 0x0a, 0x16, 0x63, 0x6f,
	0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x42, 0x10, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
	0x6c, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x3b, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x42, 0x54, 0x43, 0xaa,
	0x02, 0x12, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x43, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0xca, 0x02, 0x12, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x54, 0x79,
	0x70, 0x65, 0x5c, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0xe2, 0x02, 0x1e, 0x42, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x5c, 0x54, 0x79, 0x70, 0x65, 0x5c, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x5c, 0x47,
	0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x14, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x3a, 0x43, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_blocky_type_crypto_key_material_proto_rawDescOnce sync.Once
	file_blocky_type_crypto_key_material_proto_rawDescData = file_blocky_type_crypto_key_material_proto_rawDesc
)

func file_blocky_type_crypto_key_material_proto_rawDescGZIP() []byte {
	file_blocky_type_crypto_key_material_proto_rawDescOnce.Do(func() {
		file_blocky_type_crypto_key_material_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_type_crypto_key_material_proto_rawDescData)
	})
	return file_blocky_type_crypto_key_material_proto_rawDescData
}

var file_blocky_type_crypto_key_material_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_blocky_type_crypto_key_material_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_blocky_type_crypto_key_material_proto_goTypes = []interface{}{
	(KeyAlgorithmType)(0), // 0: blocky.type.crypto.KeyAlgorithmType
	(Curve)(0),            // 1: blocky.type.crypto.Curve
	(*KeyMaterial)(nil),   // 2: blocky.type.crypto.KeyMaterial
}
var file_blocky_type_crypto_key_material_proto_depIdxs = []int32{
	0, // 0: blocky.type.crypto.KeyMaterial.type:type_name -> blocky.type.crypto.KeyAlgorithmType
	1, // 1: blocky.type.crypto.KeyMaterial.curve:type_name -> blocky.type.crypto.Curve
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_blocky_type_crypto_key_material_proto_init() }
func file_blocky_type_crypto_key_material_proto_init() {
	if File_blocky_type_crypto_key_material_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_blocky_type_crypto_key_material_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_blocky_type_crypto_key_material_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_type_crypto_key_material_proto_goTypes,
		DependencyIndexes: file_blocky_type_crypto_key_material_proto_depIdxs,
		EnumInfos:         file_blocky_type_crypto_key_material_proto_enumTypes,
		MessageInfos:      file_blocky_type_crypto_key_material_proto_msgTypes,
	}.Build()
	File_blocky_type_crypto_key_material_proto = out.File
	file_blocky_type_crypto_key_material_proto_rawDesc = nil
	file_blocky_type_crypto_key_material_proto_goTypes = nil
	file_blocky_type_crypto_key_material_proto_depIdxs = nil
}
