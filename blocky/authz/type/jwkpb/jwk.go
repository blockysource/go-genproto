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

package jwkpb

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// RsaPrivateKey returns the RSA private key represented by the JWK.
// This function returns the value only if the key type is "RSA", and all required fields are set.
func (m *JWK) RsaPrivateKey() (*rsa.PrivateKey, error) {
	var missing []string
	switch {
	case m.N == nil:
		missing = append(missing, "N")
	case m.E == nil:
		missing = append(missing, "E")
	case m.D == nil:
		missing = append(missing, "D")
	case m.P == nil:
		missing = append(missing, "P")
	case m.Q == nil:
		missing = append(missing, "Q")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("invalid RSA private key, missing %s value(s)", strings.Join(missing, ", "))
	}

	rv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: bytesBigInt(m.N),
			E: bytesInt(m.E),
		},
		D: bytesBigInt(m.D),
		Primes: []*big.Int{
			bytesBigInt(m.P),
			bytesBigInt(m.Q),
		},
	}

	if m.Dp != nil {
		rv.Precomputed.Dp = bytesBigInt(m.Dp)
	}
	if m.Dq != nil {
		rv.Precomputed.Dq = bytesBigInt(m.Dq)
	}
	if m.Qi != nil {
		rv.Precomputed.Qinv = bytesBigInt(m.Qi)
	}

	err := rv.Validate()
	return rv, err
}

// RsaPublicKey returns the RSA public key represented by the JWK.
// This function returns the value only if the key type is "RSA", and all required fields are set.
func (m *JWK) RsaPublicKey() (*rsa.PublicKey, error) {
	var missing []string
	switch {
	case m.N == nil:
		missing = append(missing, "N")
	case m.E == nil:
		missing = append(missing, "E")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("invalid RSA public key, missing %s value(s)", strings.Join(missing, ", "))
	}

	return &rsa.PublicKey{
		N: bytesBigInt(m.N),
		E: bytesInt(m.E),
	}, nil
}

// EcPublicKey returns the ECDSA public key represented by the JWK.
func (m *JWK) EcPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch m.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve '%s'", m.Crv)
	}

	if m.X == nil || m.Y == nil {
		return nil, fmt.Errorf("invalid EC key, missing x/y values")
	}

	// The length of this octet string MUST be the full size of a coordinate for
	// the curve specified in the "crv" parameter.
	// https://tools.ietf.org/html/rfc7518#section-6.2.1.2
	if curveSize(curve) != len(m.X) {
		return nil, fmt.Errorf("invalid EC public key, wrong length for x")
	}

	if curveSize(curve) != len(m.Y) {
		return nil, fmt.Errorf("invalid EC public key, wrong length for y")
	}

	x := bytesBigInt(m.X)
	y := bytesBigInt(m.Y)

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid EC key, X/Y are not on declared curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// IsSymmetric returns true if the key is a symmetric key.
func (m *JWK) IsSymmetric() bool {
	return m.Kty == "oct"
}

// IsPrivate returns true if the key is a private key.
// It returns true either if the value of the JWK is an asymmetric private key, or a symmetric key.
func (m *JWK) IsPrivate() bool {
	return m.D != nil || m.Kty == "oct"
}

// EcPrivateKey returns the ECDSA private key represented by the JWK.
func (m *JWK) EcPrivateKey() (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch m.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve '%s'", m.Crv)
	}

	if m.X == nil || m.Y == nil || m.D == nil {
		return nil, fmt.Errorf("invalid EC private key, missing x/y/d values")
	}

	// The length of this octet string MUST be the full size of a coordinate for
	// the curve specified in the "crv" parameter.
	// https://tools.ietf.org/html/rfc7518#section-6.2.1.2
	if curveSize(curve) != len(m.X) {
		return nil, fmt.Errorf("invalid EC private key, wrong length for x")
	}

	if curveSize(curve) != len(m.Y) {
		return nil, fmt.Errorf("invalid EC private key, wrong length for y")
	}

	// https://tools.ietf.org/html/rfc7518#section-6.2.2.1
	if dSize(curve) != len(m.D) {
		return nil, fmt.Errorf("invalid EC private key, wrong length for d")
	}

	x := bytesBigInt(m.X)
	y := bytesBigInt(m.Y)

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid EC key, X/Y are not on declared curve")
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: bytesBigInt(m.D),
	}, nil
}

// EdPrivateKey returns the Ed25519 private key represented by the JWK.
func (m *JWK) EdPrivateKey() (ed25519.PrivateKey, error) {
	var missing []string
	switch {
	case m.D == nil:
		missing = append(missing, "D")
	case m.X == nil:
		missing = append(missing, "X")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("invalid Ed25519 private key, missing %s value(s)", strings.Join(missing, ", "))
	}

	privateKey := make([]byte, ed25519.PrivateKeySize)
	copy(privateKey[0:32], m.D)
	copy(privateKey[32:], m.X)
	rv := ed25519.PrivateKey(privateKey)
	return rv, nil
}

// EdPublicKey returns the Ed25519 public key represented by the JWK.
func (m *JWK) EdPublicKey() (ed25519.PublicKey, error) {
	if m.X == nil {
		return nil, fmt.Errorf("invalid Ed25519 public key, missing x value")
	}

	if len(m.X) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key, wrong length for x")
	}

	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey[0:32], m.X)
	rv := ed25519.PublicKey(publicKey)

	return rv, nil
}

// SymmetricKey returns the symmetric key represented by the JWK.
func (m *JWK) SymmetricKey() ([]byte, error) {
	if m.K == nil {
		return nil, fmt.Errorf("invalid symmetric key, missing k value")
	}

	return m.K, nil
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

type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

// base64URLDecode is implemented as defined in https://www.rfc-editor.org/rfc/rfc7515.html#appendix-C
func base64URLDecode(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	return base64.RawURLEncoding.DecodeString(value)
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

// rawJSONWebKey represents a public or private key in JWK format, used for parsing/serializing.
type rawJSONWebKey struct {
	Use string      `json:"use,omitempty"`
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	Alg string      `json:"alg,omitempty"`
	K   *byteBuffer `json:"k,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *byteBuffer `json:"d,omitempty"`
	P  *byteBuffer `json:"p,omitempty"`
	Q  *byteBuffer `json:"q,omitempty"`
	Dp *byteBuffer `json:"dp,omitempty"`
	Dq *byteBuffer `json:"dq,omitempty"`
	Qi *byteBuffer `json:"qi,omitempty"`
	// Certificates
	X5c       []string `json:"x5c,omitempty"`
	X5u       string   `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

func (m *JWK) MarshalJSON() ([]byte, error) {
	raw := rawJSONWebKey{
		Use:       m.Use,
		Kty:       m.Kty,
		Kid:       m.Kid,
		Crv:       m.Crv,
		Alg:       m.Alg,
		K:         newBufferFromB64(m.K),
		X:         newBufferFromB64(m.X),
		Y:         newBufferFromB64(m.Y),
		N:         newBufferFromB64(m.N),
		E:         newBufferFromB64(m.E),
		D:         newBufferFromB64(m.D),
		P:         newBufferFromB64(m.P),
		Q:         newBufferFromB64(m.Q),
		Dp:        newBufferFromB64(m.Dp),
		Dq:        newBufferFromB64(m.Dq),
		Qi:        newBufferFromB64(m.Qi),
		X5u:       m.X5U,
		X5tSHA1:   base64RawUrlEncode(m.X5TSha1),
		X5tSHA256: base64RawUrlEncode(m.X5TSha256),
	}

	return json.Marshal(raw)
}

func (m *JWK) UnmarshalJSON(data []byte) error {
	var raw rawJSONWebKey
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	m.Use = raw.Use
	m.Kty = raw.Kty
	m.Kid = raw.Kid
	m.Crv = raw.Crv
	m.Alg = raw.Alg
	m.K = raw.K.data
	m.X = raw.X.data
	m.Y = raw.Y.data
	m.N = raw.N.data
	m.E = raw.E.data
	m.D = raw.D.data
	m.P = raw.P.data
	m.Q = raw.Q.data
	m.Dp = raw.Dp.data
	m.Dq = raw.Dq.data
	m.Qi = raw.Qi.data
	m.X5U = raw.X5u
	if len(raw.X5c) > 0 {
		m.X5TSha1, err = base64.RawURLEncoding.DecodeString(raw.X5tSHA1)
		if err != nil {
			return err
		}
	}
	if len(raw.X5tSHA256) > 0 {
		m.X5TSha256, err = base64.RawURLEncoding.DecodeString(raw.X5tSHA256)
		if err != nil {
			return err
		}
	}
	return nil
}

func newBufferFromB64(in []byte) *byteBuffer {
	if len(in) == 0 {
		return nil
	}

	return &byteBuffer{data: in}
}

func base64RawUrlEncode(in []byte) string {
	if len(in) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(in)
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
