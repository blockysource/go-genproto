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
// source: blocky/kms/v1alpha/algorithm.proto

package kmsv1alpha

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

// KeyUse is an algorithm used to generate and verify JSON Web Keys (JWK) as defined in RFC 7518.
type KeyUse int32

const (
	// Unspecified key use.
	KeyUse_KEY_USE_UNSPECIFIED KeyUse = 0
	// Indicates that the key is used for signing.
	KeyUse_SIGN_VERIFY KeyUse = 1
	// Indicates that the key is used for encryption.
	KeyUse_ENCRYPT_DECRYPT KeyUse = 2
	// Indicates that the key is used for both signing and encryption.
	KeyUse_SIGN_ENCRYPT_DECRYPT KeyUse = 3
)

// Enum value maps for KeyUse.
var (
	KeyUse_name = map[int32]string{
		0: "KEY_USE_UNSPECIFIED",
		1: "SIGN_VERIFY",
		2: "ENCRYPT_DECRYPT",
		3: "SIGN_ENCRYPT_DECRYPT",
	}
	KeyUse_value = map[string]int32{
		"KEY_USE_UNSPECIFIED":  0,
		"SIGN_VERIFY":          1,
		"ENCRYPT_DECRYPT":      2,
		"SIGN_ENCRYPT_DECRYPT": 3,
	}
)

func (x KeyUse) Enum() *KeyUse {
	p := new(KeyUse)
	*p = x
	return p
}

func (x KeyUse) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyUse) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[0].Descriptor()
}

func (KeyUse) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[0]
}

func (x KeyUse) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyUse.Descriptor instead.
func (KeyUse) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{0}
}

// Is the specified RSA key size supported.
type RSAKeySize int32

const (
	RSAKeySize_RSA_KEY_SIZE_UNSPECIFIED RSAKeySize = 0
	// RSA_2048 is the RSA key size of 2048 bits.
	RSAKeySize_RSA_2048 RSAKeySize = 2048
	// RSA_3072 is the RSA key size of 3072 bits.
	RSAKeySize_RSA_3072 RSAKeySize = 3072
	// RSA_4096 is the RSA key size of 4096 bits.
	RSAKeySize_RSA_4096 RSAKeySize = 4096
)

// Enum value maps for RSAKeySize.
var (
	RSAKeySize_name = map[int32]string{
		0:    "RSA_KEY_SIZE_UNSPECIFIED",
		2048: "RSA_2048",
		3072: "RSA_3072",
		4096: "RSA_4096",
	}
	RSAKeySize_value = map[string]int32{
		"RSA_KEY_SIZE_UNSPECIFIED": 0,
		"RSA_2048":                 2048,
		"RSA_3072":                 3072,
		"RSA_4096":                 4096,
	}
)

func (x RSAKeySize) Enum() *RSAKeySize {
	p := new(RSAKeySize)
	*p = x
	return p
}

func (x RSAKeySize) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RSAKeySize) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[1].Descriptor()
}

func (RSAKeySize) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[1]
}

func (x RSAKeySize) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RSAKeySize.Descriptor instead.
func (RSAKeySize) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{1}
}

// EllipticCurve is an algorithm used to generate and verify JSON Web Keys (JWK) as defined in RFC 7518.
type EllipticCurve int32

const (
	// Unspecified elliptic curve.
	EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED EllipticCurve = 0
	// EllipticCurve of type P-256
	EllipticCurve_EC_P256 EllipticCurve = 1
	// EllipticCurve of type P-384
	EllipticCurve_EC_P384 EllipticCurve = 2
	// EllipticCurve of type P-521
	EllipticCurve_EC_P521 EllipticCurve = 3
)

// Enum value maps for EllipticCurve.
var (
	EllipticCurve_name = map[int32]string{
		0: "ELLIPTIC_CURVE_UNSPECIFIED",
		1: "EC_P256",
		2: "EC_P384",
		3: "EC_P521",
	}
	EllipticCurve_value = map[string]int32{
		"ELLIPTIC_CURVE_UNSPECIFIED": 0,
		"EC_P256":                    1,
		"EC_P384":                    2,
		"EC_P521":                    3,
	}
)

func (x EllipticCurve) Enum() *EllipticCurve {
	p := new(EllipticCurve)
	*p = x
	return p
}

func (x EllipticCurve) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EllipticCurve) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[2].Descriptor()
}

func (EllipticCurve) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[2]
}

func (x EllipticCurve) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EllipticCurve.Descriptor instead.
func (EllipticCurve) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{2}
}

// OKPCurve is an algorithm used to generate and verify JSON Web Keys (JWK) as defined in RFC 7518.
type OKPCurve int32

const (
	// Unspecified OKP curve.
	OKPCurve_OKP_CURVE_UNSPECIFIED OKPCurve = 0
	// OKPCurve of type Ed25519
	OKPCurve_OKP_ED25519 OKPCurve = 1
)

// Enum value maps for OKPCurve.
var (
	OKPCurve_name = map[int32]string{
		0: "OKP_CURVE_UNSPECIFIED",
		1: "OKP_ED25519",
	}
	OKPCurve_value = map[string]int32{
		"OKP_CURVE_UNSPECIFIED": 0,
		"OKP_ED25519":           1,
	}
)

func (x OKPCurve) Enum() *OKPCurve {
	p := new(OKPCurve)
	*p = x
	return p
}

func (x OKPCurve) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OKPCurve) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[3].Descriptor()
}

func (OKPCurve) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[3]
}

func (x OKPCurve) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OKPCurve.Descriptor instead.
func (OKPCurve) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{3}
}

type HashAlgorithm int32

const (
	// Unspecified hash algorithm.
	HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED HashAlgorithm = 0
	// HashAlgorithm of type SHA-256
	HashAlgorithm_SHA256 HashAlgorithm = 1
	// HashAlgorithm of type SHA-384
	HashAlgorithm_SHA384 HashAlgorithm = 2
	// HashAlgorithm of type SHA-512
	HashAlgorithm_SHA512 HashAlgorithm = 3
)

// Enum value maps for HashAlgorithm.
var (
	HashAlgorithm_name = map[int32]string{
		0: "HASH_ALGORITHM_UNSPECIFIED",
		1: "SHA256",
		2: "SHA384",
		3: "SHA512",
	}
	HashAlgorithm_value = map[string]int32{
		"HASH_ALGORITHM_UNSPECIFIED": 0,
		"SHA256":                     1,
		"SHA384":                     2,
		"SHA512":                     3,
	}
)

func (x HashAlgorithm) Enum() *HashAlgorithm {
	p := new(HashAlgorithm)
	*p = x
	return p
}

func (x HashAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HashAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[4].Descriptor()
}

func (HashAlgorithm) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[4]
}

func (x HashAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HashAlgorithm.Descriptor instead.
func (HashAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{4}
}

// KeyManagementType is an algorithm used to encrypt and decrypt content.
type KeyManagementAlgorithm int32

const (
	// Unspecified key management type.
	KeyManagementAlgorithm_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED KeyManagementAlgorithm = 0
	// KeyManagementType of type Edwards-curve Digital Signature Algorithm (EdDSA)
	KeyManagementAlgorithm_ED25519 KeyManagementAlgorithm = 1
	// KeyManagementType of type RSA-PKCS1v1.5
	KeyManagementAlgorithm_RSA1_5 KeyManagementAlgorithm = 2
	// KeyManagementType of type RSA-OAEP-SHA1
	KeyManagementAlgorithm_RSA_OAEP KeyManagementAlgorithm = 3
	// KeyManagementType of type RSA-OAEP-SHA256
	KeyManagementAlgorithm_RSA_OAEP_256 KeyManagementAlgorithm = 4
	// KeyManagementType of type AES key wrap (128)
	KeyManagementAlgorithm_A128KW KeyManagementAlgorithm = 5
	// KeyManagementType of type AES key wrap (192)
	KeyManagementAlgorithm_A192KW KeyManagementAlgorithm = 6
	// KeyManagementType of type AES key wrap (256)
	KeyManagementAlgorithm_A256KW KeyManagementAlgorithm = 7
	// KeyManagementType of type Direct encryption
	KeyManagementAlgorithm_DIRECT KeyManagementAlgorithm = 8
	// KeyManagementType of type ECDH-ES
	KeyManagementAlgorithm_ECDH_ES KeyManagementAlgorithm = 9
	// KeyManagementType of type ECDH-ES + AES key wrap (128)
	KeyManagementAlgorithm_ECDH_ES_A128KW KeyManagementAlgorithm = 10
	// KeyManagementType of type ECDH-ES + AES key wrap (192)
	KeyManagementAlgorithm_ECDH_ES_A192KW KeyManagementAlgorithm = 11
	// KeyManagementType of type ECDH-ES + AES key wrap (256)
	KeyManagementAlgorithm_ECDH_ES_A256KW KeyManagementAlgorithm = 12
	// KeyManagementType of type AES-GCM key wrap (128)
	KeyManagementAlgorithm_A128GCMKW KeyManagementAlgorithm = 13
	// KeyManagementType of type AES-GCM key wrap (192)
	KeyManagementAlgorithm_A192GCMKW KeyManagementAlgorithm = 14
	// KeyManagementType of type AES-GCM key wrap (256)
	KeyManagementAlgorithm_A256GCMKW KeyManagementAlgorithm = 15
	// KeyManagementType of type PBES2 + HMAC-SHA256 + AES key wrap (128)
	KeyManagementAlgorithm_PBES2_HS256_A128KW KeyManagementAlgorithm = 16
	// KeyManagementType of type PBES2 + HMAC-SHA384 + AES key wrap (192)
	KeyManagementAlgorithm_PBES2_HS384_A192KW KeyManagementAlgorithm = 17
	// KeyManagementType of type PBES2 + HMAC-SHA512 + AES key wrap (256)
	KeyManagementAlgorithm_PBES2_HS512_A256KW KeyManagementAlgorithm = 18
)

// Enum value maps for KeyManagementAlgorithm.
var (
	KeyManagementAlgorithm_name = map[int32]string{
		0:  "KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED",
		1:  "ED25519",
		2:  "RSA1_5",
		3:  "RSA_OAEP",
		4:  "RSA_OAEP_256",
		5:  "A128KW",
		6:  "A192KW",
		7:  "A256KW",
		8:  "DIRECT",
		9:  "ECDH_ES",
		10: "ECDH_ES_A128KW",
		11: "ECDH_ES_A192KW",
		12: "ECDH_ES_A256KW",
		13: "A128GCMKW",
		14: "A192GCMKW",
		15: "A256GCMKW",
		16: "PBES2_HS256_A128KW",
		17: "PBES2_HS384_A192KW",
		18: "PBES2_HS512_A256KW",
	}
	KeyManagementAlgorithm_value = map[string]int32{
		"KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED": 0,
		"ED25519":                              1,
		"RSA1_5":                               2,
		"RSA_OAEP":                             3,
		"RSA_OAEP_256":                         4,
		"A128KW":                               5,
		"A192KW":                               6,
		"A256KW":                               7,
		"DIRECT":                               8,
		"ECDH_ES":                              9,
		"ECDH_ES_A128KW":                       10,
		"ECDH_ES_A192KW":                       11,
		"ECDH_ES_A256KW":                       12,
		"A128GCMKW":                            13,
		"A192GCMKW":                            14,
		"A256GCMKW":                            15,
		"PBES2_HS256_A128KW":                   16,
		"PBES2_HS384_A192KW":                   17,
		"PBES2_HS512_A256KW":                   18,
	}
)

func (x KeyManagementAlgorithm) Enum() *KeyManagementAlgorithm {
	p := new(KeyManagementAlgorithm)
	*p = x
	return p
}

func (x KeyManagementAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (KeyManagementAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[5].Descriptor()
}

func (KeyManagementAlgorithm) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[5]
}

func (x KeyManagementAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use KeyManagementAlgorithm.Descriptor instead.
func (KeyManagementAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{5}
}

// SignatureAlgorithm is an algorithm used to sign and verify content.
type SignatureAlgorithm int32

const (
	// Unspecified algorithm.
	SignatureAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED SignatureAlgorithm = 0
	// Defines No digital signature
	SignatureAlgorithm_NONE SignatureAlgorithm = 1
	// Defines HMAC SHA-256 signing algorithm.
	SignatureAlgorithm_HS256 SignatureAlgorithm = 2
	// Defines HMAC SHA-384 signing algorithm.
	SignatureAlgorithm_HS384 SignatureAlgorithm = 3
	// Defines HMAC SHA-512 signing algorithm.
	SignatureAlgorithm_HS512 SignatureAlgorithm = 4
	// Defines RSA PKCS1 v1.5 signing algorithm.
	SignatureAlgorithm_RS256 SignatureAlgorithm = 5
	// Defines RSA PSS signing algorithm with SHA-384 hash.
	SignatureAlgorithm_RS384 SignatureAlgorithm = 6
	// Defines RSA PSS signing algorithm with SHA-512 hash.
	SignatureAlgorithm_RS512 SignatureAlgorithm = 7
	// Defines Elliptic Curve signing algorithm with P-256 curve SHA-256 hash.
	SignatureAlgorithm_ES256 SignatureAlgorithm = 8
	// Defines Elliptic Curve signing algorithm with P-384 curve SHA-384 hash.
	SignatureAlgorithm_ES384 SignatureAlgorithm = 9
	// Defines Elliptic Curve signing algorithm with P-521 curve SHA-512 hash.
	SignatureAlgorithm_ES512 SignatureAlgorithm = 10
	// Defines RSASSA-PSS signing algorithm with SHA-256 hash.
	SignatureAlgorithm_PS256 SignatureAlgorithm = 11
	// Defines RSASSA-PSS signing algorithm with SHA-384 hash.
	SignatureAlgorithm_PS384 SignatureAlgorithm = 12
	// Defines RSASSA-PSS signing algorithm with SHA-512 hash.
	SignatureAlgorithm_PS512 SignatureAlgorithm = 13
	// Defines EdDSA - Edwards-Curve Digital Signature Algorithm  (Ed25519) signing algorithm.
	SignatureAlgorithm_EdDSA SignatureAlgorithm = 14
)

// Enum value maps for SignatureAlgorithm.
var (
	SignatureAlgorithm_name = map[int32]string{
		0:  "SIGNING_ALGORITHM_UNSPECIFIED",
		1:  "NONE",
		2:  "HS256",
		3:  "HS384",
		4:  "HS512",
		5:  "RS256",
		6:  "RS384",
		7:  "RS512",
		8:  "ES256",
		9:  "ES384",
		10: "ES512",
		11: "PS256",
		12: "PS384",
		13: "PS512",
		14: "EdDSA",
	}
	SignatureAlgorithm_value = map[string]int32{
		"SIGNING_ALGORITHM_UNSPECIFIED": 0,
		"NONE":                          1,
		"HS256":                         2,
		"HS384":                         3,
		"HS512":                         4,
		"RS256":                         5,
		"RS384":                         6,
		"RS512":                         7,
		"ES256":                         8,
		"ES384":                         9,
		"ES512":                         10,
		"PS256":                         11,
		"PS384":                         12,
		"PS512":                         13,
		"EdDSA":                         14,
	}
)

func (x SignatureAlgorithm) Enum() *SignatureAlgorithm {
	p := new(SignatureAlgorithm)
	*p = x
	return p
}

func (x SignatureAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SignatureAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[6].Descriptor()
}

func (SignatureAlgorithm) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[6]
}

func (x SignatureAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SignatureAlgorithm.Descriptor instead.
func (SignatureAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{6}
}

// EncryptionAlgorithm is an algorithm used to encrypt and decrypt JSON Web Encryption (JWE) as defined in RFC 7518.
type EncryptionAlgorithm int32

const (
	EncryptionAlgorithm_ENCRYPTION_ALGORITHM_UNSPECIFIED EncryptionAlgorithm = 0
	// Defines AES_128_CBC_HMAC_SHA_256 authenticated encryptiosn algorithm.
	EncryptionAlgorithm_A128CBC_HS256 EncryptionAlgorithm = 1
	// Defines AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm.
	EncryptionAlgorithm_A192CBC_HS384 EncryptionAlgorithm = 2
	// Defines AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm.
	EncryptionAlgorithm_A256CBC_HS512 EncryptionAlgorithm = 3
	// Defines AES_128_GCM authenticated encryption algorithm.
	EncryptionAlgorithm_A128GCM EncryptionAlgorithm = 4
	// Defines AES_192_GCM authenticated encryption algorithm.
	EncryptionAlgorithm_A192GCM EncryptionAlgorithm = 5
	// Defines AES_256_GCM authenticated encryption algorithm.
	EncryptionAlgorithm_A256GCM EncryptionAlgorithm = 6
)

// Enum value maps for EncryptionAlgorithm.
var (
	EncryptionAlgorithm_name = map[int32]string{
		0: "ENCRYPTION_ALGORITHM_UNSPECIFIED",
		1: "A128CBC_HS256",
		2: "A192CBC_HS384",
		3: "A256CBC_HS512",
		4: "A128GCM",
		5: "A192GCM",
		6: "A256GCM",
	}
	EncryptionAlgorithm_value = map[string]int32{
		"ENCRYPTION_ALGORITHM_UNSPECIFIED": 0,
		"A128CBC_HS256":                    1,
		"A192CBC_HS384":                    2,
		"A256CBC_HS512":                    3,
		"A128GCM":                          4,
		"A192GCM":                          5,
		"A256GCM":                          6,
	}
)

func (x EncryptionAlgorithm) Enum() *EncryptionAlgorithm {
	p := new(EncryptionAlgorithm)
	*p = x
	return p
}

func (x EncryptionAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncryptionAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_blocky_kms_v1alpha_algorithm_proto_enumTypes[7].Descriptor()
}

func (EncryptionAlgorithm) Type() protoreflect.EnumType {
	return &file_blocky_kms_v1alpha_algorithm_proto_enumTypes[7]
}

func (x EncryptionAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncryptionAlgorithm.Descriptor instead.
func (EncryptionAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP(), []int{7}
}

var File_blocky_kms_v1alpha_algorithm_proto protoreflect.FileDescriptor

var file_blocky_kms_v1alpha_algorithm_proto_rawDesc = []byte{
	0x0a, 0x22, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2f, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2e, 0x6b, 0x6d, 0x73,
	0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76,
	0x69, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x61, 0x0a, 0x06, 0x4b, 0x65, 0x79, 0x55, 0x73, 0x65, 0x12, 0x17,
	0x0a, 0x13, 0x4b, 0x45, 0x59, 0x5f, 0x55, 0x53, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43,
	0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x49, 0x47, 0x4e, 0x5f,
	0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0x10, 0x01, 0x12, 0x13, 0x0a, 0x0f, 0x45, 0x4e, 0x43, 0x52,
	0x59, 0x50, 0x54, 0x5f, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x10, 0x02, 0x12, 0x18, 0x0a,
	0x14, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x5f, 0x44, 0x45,
	0x43, 0x52, 0x59, 0x50, 0x54, 0x10, 0x03, 0x2a, 0x57, 0x0a, 0x0a, 0x52, 0x53, 0x41, 0x4b, 0x65,
	0x79, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1c, 0x0a, 0x18, 0x52, 0x53, 0x41, 0x5f, 0x4b, 0x45, 0x59,
	0x5f, 0x53, 0x49, 0x5a, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45,
	0x44, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x08, 0x52, 0x53, 0x41, 0x5f, 0x32, 0x30, 0x34, 0x38, 0x10,
	0x80, 0x10, 0x12, 0x0d, 0x0a, 0x08, 0x52, 0x53, 0x41, 0x5f, 0x33, 0x30, 0x37, 0x32, 0x10, 0x80,
	0x18, 0x12, 0x0d, 0x0a, 0x08, 0x52, 0x53, 0x41, 0x5f, 0x34, 0x30, 0x39, 0x36, 0x10, 0x80, 0x20,
	0x2a, 0x56, 0x0a, 0x0d, 0x45, 0x6c, 0x6c, 0x69, 0x70, 0x74, 0x69, 0x63, 0x43, 0x75, 0x72, 0x76,
	0x65, 0x12, 0x1e, 0x0a, 0x1a, 0x45, 0x4c, 0x4c, 0x49, 0x50, 0x54, 0x49, 0x43, 0x5f, 0x43, 0x55,
	0x52, 0x56, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x0b, 0x0a, 0x07, 0x45, 0x43, 0x5f, 0x50, 0x32, 0x35, 0x36, 0x10, 0x01, 0x12, 0x0b,
	0x0a, 0x07, 0x45, 0x43, 0x5f, 0x50, 0x33, 0x38, 0x34, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x45,
	0x43, 0x5f, 0x50, 0x35, 0x32, 0x31, 0x10, 0x03, 0x2a, 0x36, 0x0a, 0x08, 0x4f, 0x4b, 0x50, 0x43,
	0x75, 0x72, 0x76, 0x65, 0x12, 0x19, 0x0a, 0x15, 0x4f, 0x4b, 0x50, 0x5f, 0x43, 0x55, 0x52, 0x56,
	0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12,
	0x0f, 0x0a, 0x0b, 0x4f, 0x4b, 0x50, 0x5f, 0x45, 0x44, 0x32, 0x35, 0x35, 0x31, 0x39, 0x10, 0x01,
	0x2a, 0x53, 0x0a, 0x0d, 0x48, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x12, 0x1e, 0x0a, 0x1a, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49,
	0x54, 0x48, 0x4d, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x10, 0x01, 0x12, 0x0a, 0x0a,
	0x06, 0x53, 0x48, 0x41, 0x33, 0x38, 0x34, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48, 0x41,
	0x35, 0x31, 0x32, 0x10, 0x03, 0x2a, 0xe9, 0x02, 0x0a, 0x16, 0x4b, 0x65, 0x79, 0x4d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
	0x12, 0x28, 0x0a, 0x24, 0x4b, 0x45, 0x59, 0x5f, 0x4d, 0x41, 0x4e, 0x41, 0x47, 0x45, 0x4d, 0x45,
	0x4e, 0x54, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54, 0x48, 0x4d, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x45, 0x44,
	0x32, 0x35, 0x35, 0x31, 0x39, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x53, 0x41, 0x31, 0x5f,
	0x35, 0x10, 0x02, 0x12, 0x0c, 0x0a, 0x08, 0x52, 0x53, 0x41, 0x5f, 0x4f, 0x41, 0x45, 0x50, 0x10,
	0x03, 0x12, 0x10, 0x0a, 0x0c, 0x52, 0x53, 0x41, 0x5f, 0x4f, 0x41, 0x45, 0x50, 0x5f, 0x32, 0x35,
	0x36, 0x10, 0x04, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x31, 0x32, 0x38, 0x4b, 0x57, 0x10, 0x05, 0x12,
	0x0a, 0x0a, 0x06, 0x41, 0x31, 0x39, 0x32, 0x4b, 0x57, 0x10, 0x06, 0x12, 0x0a, 0x0a, 0x06, 0x41,
	0x32, 0x35, 0x36, 0x4b, 0x57, 0x10, 0x07, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x49, 0x52, 0x45, 0x43,
	0x54, 0x10, 0x08, 0x12, 0x0b, 0x0a, 0x07, 0x45, 0x43, 0x44, 0x48, 0x5f, 0x45, 0x53, 0x10, 0x09,
	0x12, 0x12, 0x0a, 0x0e, 0x45, 0x43, 0x44, 0x48, 0x5f, 0x45, 0x53, 0x5f, 0x41, 0x31, 0x32, 0x38,
	0x4b, 0x57, 0x10, 0x0a, 0x12, 0x12, 0x0a, 0x0e, 0x45, 0x43, 0x44, 0x48, 0x5f, 0x45, 0x53, 0x5f,
	0x41, 0x31, 0x39, 0x32, 0x4b, 0x57, 0x10, 0x0b, 0x12, 0x12, 0x0a, 0x0e, 0x45, 0x43, 0x44, 0x48,
	0x5f, 0x45, 0x53, 0x5f, 0x41, 0x32, 0x35, 0x36, 0x4b, 0x57, 0x10, 0x0c, 0x12, 0x0d, 0x0a, 0x09,
	0x41, 0x31, 0x32, 0x38, 0x47, 0x43, 0x4d, 0x4b, 0x57, 0x10, 0x0d, 0x12, 0x0d, 0x0a, 0x09, 0x41,
	0x31, 0x39, 0x32, 0x47, 0x43, 0x4d, 0x4b, 0x57, 0x10, 0x0e, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x32,
	0x35, 0x36, 0x47, 0x43, 0x4d, 0x4b, 0x57, 0x10, 0x0f, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x42, 0x45,
	0x53, 0x32, 0x5f, 0x48, 0x53, 0x32, 0x35, 0x36, 0x5f, 0x41, 0x31, 0x32, 0x38, 0x4b, 0x57, 0x10,
	0x10, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x42, 0x45, 0x53, 0x32, 0x5f, 0x48, 0x53, 0x33, 0x38, 0x34,
	0x5f, 0x41, 0x31, 0x39, 0x32, 0x4b, 0x57, 0x10, 0x11, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x42, 0x45,
	0x53, 0x32, 0x5f, 0x48, 0x53, 0x35, 0x31, 0x32, 0x5f, 0x41, 0x32, 0x35, 0x36, 0x4b, 0x57, 0x10,
	0x12, 0x2a, 0xd0, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41,
	0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x21, 0x0a, 0x1d, 0x53, 0x49, 0x47, 0x4e,
	0x49, 0x4e, 0x47, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54, 0x48, 0x4d, 0x5f, 0x55, 0x4e,
	0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x4e,
	0x4f, 0x4e, 0x45, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x48, 0x53, 0x32, 0x35, 0x36, 0x10, 0x02,
	0x12, 0x09, 0x0a, 0x05, 0x48, 0x53, 0x33, 0x38, 0x34, 0x10, 0x03, 0x12, 0x09, 0x0a, 0x05, 0x48,
	0x53, 0x35, 0x31, 0x32, 0x10, 0x04, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x53, 0x32, 0x35, 0x36, 0x10,
	0x05, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x53, 0x33, 0x38, 0x34, 0x10, 0x06, 0x12, 0x09, 0x0a, 0x05,
	0x52, 0x53, 0x35, 0x31, 0x32, 0x10, 0x07, 0x12, 0x09, 0x0a, 0x05, 0x45, 0x53, 0x32, 0x35, 0x36,
	0x10, 0x08, 0x12, 0x09, 0x0a, 0x05, 0x45, 0x53, 0x33, 0x38, 0x34, 0x10, 0x09, 0x12, 0x09, 0x0a,
	0x05, 0x45, 0x53, 0x35, 0x31, 0x32, 0x10, 0x0a, 0x12, 0x09, 0x0a, 0x05, 0x50, 0x53, 0x32, 0x35,
	0x36, 0x10, 0x0b, 0x12, 0x09, 0x0a, 0x05, 0x50, 0x53, 0x33, 0x38, 0x34, 0x10, 0x0c, 0x12, 0x09,
	0x0a, 0x05, 0x50, 0x53, 0x35, 0x31, 0x32, 0x10, 0x0d, 0x12, 0x09, 0x0a, 0x05, 0x45, 0x64, 0x44,
	0x53, 0x41, 0x10, 0x0e, 0x2a, 0x9b, 0x01, 0x0a, 0x13, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x24, 0x0a, 0x20,
	0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52,
	0x49, 0x54, 0x48, 0x4d, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x31, 0x32, 0x38, 0x43, 0x42, 0x43, 0x5f, 0x48, 0x53,
	0x32, 0x35, 0x36, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x31, 0x39, 0x32, 0x43, 0x42, 0x43,
	0x5f, 0x48, 0x53, 0x33, 0x38, 0x34, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x32, 0x35, 0x36,
	0x43, 0x42, 0x43, 0x5f, 0x48, 0x53, 0x35, 0x31, 0x32, 0x10, 0x03, 0x12, 0x0b, 0x0a, 0x07, 0x41,
	0x31, 0x32, 0x38, 0x47, 0x43, 0x4d, 0x10, 0x04, 0x12, 0x0b, 0x0a, 0x07, 0x41, 0x31, 0x39, 0x32,
	0x47, 0x43, 0x4d, 0x10, 0x05, 0x12, 0x0b, 0x0a, 0x07, 0x41, 0x32, 0x35, 0x36, 0x47, 0x43, 0x4d,
	0x10, 0x06, 0x42, 0xd5, 0x01, 0x0a, 0x16, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x0e, 0x41,
	0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a,
	0x41, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x79, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x2f, 0x6b, 0x6d, 0x73, 0x2f,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x6b, 0x6d, 0x73, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0xa2, 0x02, 0x03, 0x42, 0x4b, 0x58, 0xaa, 0x02, 0x12, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x79, 0x2e, 0x4b, 0x6d, 0x73, 0x2e, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0xca, 0x02, 0x12,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c, 0x56, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0xe2, 0x02, 0x1e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x5c, 0x4b, 0x6d, 0x73, 0x5c,
	0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0xea, 0x02, 0x14, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x79, 0x3a, 0x3a, 0x4b, 0x6d,
	0x73, 0x3a, 0x3a, 0x56, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_blocky_kms_v1alpha_algorithm_proto_rawDescOnce sync.Once
	file_blocky_kms_v1alpha_algorithm_proto_rawDescData = file_blocky_kms_v1alpha_algorithm_proto_rawDesc
)

func file_blocky_kms_v1alpha_algorithm_proto_rawDescGZIP() []byte {
	file_blocky_kms_v1alpha_algorithm_proto_rawDescOnce.Do(func() {
		file_blocky_kms_v1alpha_algorithm_proto_rawDescData = protoimpl.X.CompressGZIP(file_blocky_kms_v1alpha_algorithm_proto_rawDescData)
	})
	return file_blocky_kms_v1alpha_algorithm_proto_rawDescData
}

var file_blocky_kms_v1alpha_algorithm_proto_enumTypes = make([]protoimpl.EnumInfo, 8)
var file_blocky_kms_v1alpha_algorithm_proto_goTypes = []interface{}{
	(KeyUse)(0),                 // 0: blocky.kms.v1alpha.KeyUse
	(RSAKeySize)(0),             // 1: blocky.kms.v1alpha.RSAKeySize
	(EllipticCurve)(0),          // 2: blocky.kms.v1alpha.EllipticCurve
	(OKPCurve)(0),               // 3: blocky.kms.v1alpha.OKPCurve
	(HashAlgorithm)(0),          // 4: blocky.kms.v1alpha.HashAlgorithm
	(KeyManagementAlgorithm)(0), // 5: blocky.kms.v1alpha.KeyManagementAlgorithm
	(SignatureAlgorithm)(0),     // 6: blocky.kms.v1alpha.SignatureAlgorithm
	(EncryptionAlgorithm)(0),    // 7: blocky.kms.v1alpha.EncryptionAlgorithm
}
var file_blocky_kms_v1alpha_algorithm_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_blocky_kms_v1alpha_algorithm_proto_init() }
func file_blocky_kms_v1alpha_algorithm_proto_init() {
	if File_blocky_kms_v1alpha_algorithm_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_blocky_kms_v1alpha_algorithm_proto_rawDesc,
			NumEnums:      8,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_blocky_kms_v1alpha_algorithm_proto_goTypes,
		DependencyIndexes: file_blocky_kms_v1alpha_algorithm_proto_depIdxs,
		EnumInfos:         file_blocky_kms_v1alpha_algorithm_proto_enumTypes,
	}.Build()
	File_blocky_kms_v1alpha_algorithm_proto = out.File
	file_blocky_kms_v1alpha_algorithm_proto_rawDesc = nil
	file_blocky_kms_v1alpha_algorithm_proto_goTypes = nil
	file_blocky_kms_v1alpha_algorithm_proto_depIdxs = nil
}
