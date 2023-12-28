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

package cryptopb

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Key is the type that represents a cryptographic key decoded from a KeyMaterialContent.
// Depending on the key type and content it can be:
// - ECDSA: *ecdsa.PrivateKey, *ecdsa.PublicKey
// - RSA: *rsa.PrivateKey, *rsa.PublicKey
// - Octet: SymmetricKey
// - OKP: ed25519.PrivateKey, ed25519.PublicKey
type Key any

var (
	_ crypto.PrivateKey = (SymmetricKey)(nil)
	_ crypto.PublicKey  = (SymmetricKey)(nil)
	_ interface {
		Public() crypto.PublicKey
		Equal(x crypto.PrivateKey) bool
	} = (SymmetricKey)(nil)
)

// SymmetricKey is a type that represents a symmetric key.
type SymmetricKey []byte

// Public returns the public key corresponding to the opaque,
// private key.
func (k SymmetricKey) Public() crypto.PublicKey {
	return k
}

// Equal reports whether k and x have the same value.
func (k SymmetricKey) Equal(x crypto.PrivateKey) bool {
	sk, ok := x.(SymmetricKey)
	if !ok {
		return false
	}

	return bytes.Equal(k, sk)
}

// EncodeKey encodes the key material content.
// The input 'key' can be one of the following types:
// - ECDSA: *ecdsa.PrivateKey, *ecdsa.PublicKey
// - RSA: *rsa.PrivateKey, *rsa.PublicKey
// - Octet: SymmetricKey
// - OKP: ed25519.PrivateKey, ed25519.PublicKey
// The encoded key is stored in the 'out' KeyMaterialContent.
func EncodeKey(key Key, out *KeyMaterialContent) error {
	out.Reset()

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return fromEcPrivateKey(k, out)
	case *ecdsa.PublicKey:
		return fromEcPublicKey(k, out)
	case *rsa.PrivateKey:
		return fromRsaPrivateKey(k, out)
	case *rsa.PublicKey:
		fromRsaPublicKey(k, out)
		return nil
	case SymmetricKey:
		out.Type = KeyAlgorithmType_OCTET
		out.K = make([]byte, len(k))
		copy(out.K, k)
		return nil
	case ed25519.PrivateKey:
		return fromEd25519PrivateKey(k, out)
	case ed25519.PublicKey:
		fromEd25519PublicKey(k, out)
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

func fromEd25519PrivateKey(k ed25519.PrivateKey, kc *KeyMaterialContent) error {
	if len(k) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	fromEd25519PublicKey(ed25519.PublicKey(k[32:]), kc)
	kc.D = k[0:32]
	return nil
}

func fromEd25519PublicKey(k ed25519.PublicKey, kc *KeyMaterialContent) {
	kc.Type = KeyAlgorithmType_OKP
	kc.Curve = Curve_ED25519
	kc.X = k
}

func fromRsaPrivateKey(k *rsa.PrivateKey, kc *KeyMaterialContent) error {
	if len(k.Primes) != 2 {
		return errors.New("unsupported RSA key")
	}
	fromRsaPublicKey(&k.PublicKey, kc)

	kc.D = k.D.Bytes()
	kc.P = k.Primes[0].Bytes()
	kc.Q = k.Primes[1].Bytes()

	if k.Precomputed.Dp != nil {
		kc.Dp = k.Precomputed.Dp.Bytes()
	}
	if k.Precomputed.Dq != nil {
		kc.Dq = k.Precomputed.Dq.Bytes()
	}
	if k.Precomputed.Qinv != nil {
		kc.Qi = k.Precomputed.Qinv.Bytes()
	}

	return nil
}

func fromRsaPublicKey(k *rsa.PublicKey, kc *KeyMaterialContent) {
	kc.Type = KeyAlgorithmType_RSA
	kc.N = k.N.Bytes()
	kc.E = bytesFromInt(uint64(k.E))
}

func fromEcPrivateKey(ec *ecdsa.PrivateKey, raw *KeyMaterialContent) error {
	if err := fromEcPublicKey(&ec.PublicKey, raw); err != nil {
		return err
	}

	if ec.D == nil {
		return errors.New("invalid EC private key")
	}

	raw.D = bytesFromFixedSize(ec.D.Bytes(), dSize(ec.Curve))

	return nil
}

func fromEcPublicKey(pub *ecdsa.PublicKey, raw *KeyMaterialContent) error {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return fmt.Errorf(" invalid EC key or X/Y missing)")
	}

	size := curveSize(pub.Curve)

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	if len(xBytes) > size || len(yBytes) > size {
		return fmt.Errorf("invalid EC key (X/Y too large)")
	}

	raw.Type = KeyAlgorithmType_EC
	switch pub.Curve {
	case elliptic.P256():
		raw.Curve = Curve_P256
	case elliptic.P384():
		raw.Curve = Curve_P384
	case elliptic.P521():
		raw.Curve = Curve_P521
	}
	raw.X = bytesFromFixedSize(xBytes, size)
	raw.Y = bytesFromFixedSize(yBytes, size)
	return nil
}

// Decode decodes the key material content.
// If the content represents a public key, only the public key is returned.
func (x *KeyMaterialContent) Decode() (Key, error) {
	switch x.Type {
	case KeyAlgorithmType_EC:
		return x.decodeEcKey()
	case KeyAlgorithmType_RSA:
		return x.decodeRSAKey()
	case KeyAlgorithmType_OCTET:
		return x.decodeOctetKey()
	case KeyAlgorithmType_OKP:
		return x.decodeOKPKey()
	default:
		return nil, errors.New("invalid key material content")
	}
}

func (x *KeyMaterialContent) decodeEcKey() (Key, error) {
	var curve elliptic.Curve
	switch x.Curve {
	case Curve_P256:
		curve = elliptic.P256()
	case Curve_P384:
		curve = elliptic.P384()
	case Curve_P521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("invalid elliptic curve")
	}

	if x.X == nil || x.Y == nil {
		return nil, errors.New("invalid key material content, missing elliptic curve point")
	}

	if curveSize(curve) != len(x.X) {
		return nil, errors.New("invalid key material content, invalid elliptic curve point")
	}
	if curveSize(curve) != len(x.Y) {
		return nil, errors.New("invalid key material content, invalid elliptic curve point")
	}

	ecX := bytesBigInt(x.X)
	ecY := bytesBigInt(x.Y)

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     ecX,
		Y:     ecY,
	}
	if x.D == nil {
		return &pub, nil
	}
	if dSize(curve) != len(x.D) {
		return nil, errors.New("invalid key material content, invalid elliptic curve point")
	}

	pk := &ecdsa.PrivateKey{
		PublicKey: pub,
		D:         bytesBigInt(x.D),
	}

	return pk, nil
}

func (x *KeyMaterialContent) decodeRSAKey() (Key, error) {
	var missing []string
	switch {
	case x.N == nil:
		missing = append(missing, "N")
	case x.E == nil:
		missing = append(missing, "E")
	case x.P == nil:
		if x.D != nil {
			missing = append(missing, "P")
		}
	case x.Q == nil:
		if x.D != nil {
			missing = append(missing, "Q")
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("invalid RSA key, missing %s value(s)", strings.Join(missing, ", "))
	}

	pub := rsa.PublicKey{
		N: bytesBigInt(x.N),
		E: bytesInt(x.E),
	}

	if x.D == nil {
		return &pub, nil
	}

	rv := &rsa.PrivateKey{
		PublicKey: pub,
		D:         bytesBigInt(x.D),
		Primes: []*big.Int{
			bytesBigInt(x.P),
			bytesBigInt(x.Q),
		},
	}

	if x.Dp != nil {
		rv.Precomputed.Dp = bytesBigInt(x.Dp)
	}
	if x.Dq != nil {
		rv.Precomputed.Dq = bytesBigInt(x.Dq)
	}
	if x.Qi != nil {
		rv.Precomputed.Qinv = bytesBigInt(x.Qi)
	}

	if err := rv.Validate(); err != nil {
		return nil, err
	}
	return rv, nil
}

func (x *KeyMaterialContent) decodeOctetKey() (Key, error) {
	if x.K == nil {
		return nil, errors.New("invalid key material content, missing octet key")
	}
	sym := make([]byte, len(x.K))
	copy(sym, x.K)
	return SymmetricKey(sym), nil
}

func (x *KeyMaterialContent) decodeOKPKey() (Key, error) {
	if x.X == nil {
		return nil, errors.New("invalid Ed25519 public key, missing x value")
	}

	if x.D == nil {
		if len(x.X) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key, invalid x value")
		}
		pk := make([]byte, ed25519.PublicKeySize)
		copy(pk[0:ed25519.PublicKeySize], x.X)

		return ed25519.PublicKey(pk), nil
	}

	pk := make([]byte, ed25519.PrivateKeySize)
	copy(pk[0:32], x.D)
	copy(pk[32:], x.X)
	return ed25519.PrivateKey(pk), nil
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}

func bytesBigInt(in []byte) *big.Int {
	if len(in) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(in)
}

func bytesInt(in []byte) int {
	return int(bytesBigInt(in).Int64())
}

// dSize returns the size in octets for the "d" member of an elliptic curve
// private key.
// The length of this octet string MUST be ceiling(log-base-2(n)/8)
// octets (where n is the order of the curve).
// https://tools.ietf.org/html/rfc7518#section-6.2.2.1
func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / 8
	if bitLen%8 != 0 {
		size++
	}
	return size
}

func bytesFromInt(num uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return bytes.TrimLeft(data, "\x00")
}

func bytesFromFixedSize(data []byte, length int) []byte {
	if len(data) > length {
		panic("invalid call to B64FromFixedSize (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return append(pad, data...)
}
