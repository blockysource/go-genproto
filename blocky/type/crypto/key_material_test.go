package cryptopb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

var test2048Key = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
MIIEnwIBAAKCAQBxY8hCshkKiXCUKydkrtQtQSRke28w4JotocDiVqou4k55DEDJ
akvWbXXDcakV4HA8R2tOGgbxvTjFo8EK470w9O9ipapPUSrRRaBsSOlkaaIs6OYh
4FLwZpqMNBVVEtguVUR/C34Y2pS9kRrHs6q+cGhDZolkWT7nGy5eSEvPDHg0EBq1
1hu6HmPmI3r0BInONqJg2rcK3U++wk1lnbD3ysCZsKOqRUms3n/IWKeTqXXmz2XK
J2t0NSXwiDmA9q0Gm+w0bXh3lzhtUP4MlzS+lnx9hK5bjzSbCUB5RXwMDG/uNMQq
C4MmA4BPceSfMyAIFjdRLGy/K7gbb2viOYRtAgEDAoIBAEuX2tchZgcGSw1yGkMf
OB4rbZhSSiCVvB5r1ew5xsnsNFCy1ducMo7zo9ehG2Pq9X2E8jQRWfZ+JdkX1gdC
fiCjSkHDxt+LceDZFZ2F8O2bwXNF7sFAN0rvEbLNY44MkB7jgv9c/rs8YykLZy/N
HH71mteZsO2Q1JoSHumFh99cwWHFhLxYh64qFeeH6Gqx6AM2YVBWHgs7OuKOvc8y
zUbf8xftPht1kMwwDR1XySiEYtBtn74JflK3DcT8oxOuCZBuX6sMJHKbVP41zDj+
FJZBmpAvNfCEYJUr1Hg+DpMLqLUg+D6v5vpliburbk9LxcKFZyyZ9QVe7GoqMLBu
eGsCgYEAummUj4MMKWJC2mv5rj/dt2pj2/B2HtP2RLypai4et1/Ru9nNk8cjMLzC
qXz6/RLuJ7/eD7asFS3y7EqxKxEmW0G8tTHjnzR/3wnpVipuWnwCDGU032HJVd13
LMe51GH97qLzuDZjMCz+VlbCNdSslMgWWK0XmRnN7Yqxvh6ao2kCgYEAm7fTRBhF
JtKcaJ7d8BQb9l8BNHfjayYOMq5CxoCyxa2pGBv/Mrnxv73Twp9Z/MP0ue5M5nZt
GMovpP5cGdJLQ2w5p4H3opcuWeYW9Yyru2EyCEAI/hD/Td3QVP0ukc19BDuPl5Wg
eIFs218uiVOU4pw3w+Et5B1PZ/F+ZLr5LGUCgYB8RmMKV11w7CyRnVEe1T56Ru09
Svlp4qQt0xucHr8k6ovSkTO32hd10yxw/fyot0lv1T61JHK4yUydhyDHYMQ81n3O
IUJqIv/qBpuOxvQ8UqwIQ3iU69uOk6TIhSaNlqlJwffQJEIgHf7kOdbOjchjMA7l
yLpmETPzscvUFGcXmwKBgGfP4i1lg283EvBp6Uq4EqQ/ViL6l5zECXce1y8Ady5z
xhASqiHRS9UpN9cU5qiCoyae3e75nhCGym3+6BE23Nede8UBT8G6HuaZZKOzHSeW
IVrVW1QLVN6T4DioybaI/gLSX7pjwFBWSJI/dFuNDexoJS1AyUK+NO/2VEMnUMhD
AoGAOsdn3Prnh/mjC95vraHCLap0bRBSexMdx77ImHgtFUUcSaT8DJHs+NZw1RdM
SZA0J+zVQ8q7B11jIgz5hMz+chedwoRjTL7a8VRTKHFmmBH0zlEuV7L79w6HkRCQ
VRg10GUN6heGLv0aOHbPdobcuVDH4sgOqpT1QnOuce34sQs=
-----END RSA TESTING KEY-----`))

var test3072Key = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
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
-----END RSA TESTING KEY-----`))

var test4096Key = parseKey(testingKey(`-----BEGIN RSA TESTING KEY-----
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
-----END RSA TESTING KEY-----`))

func TestKeyMaterial(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		for _, pk := range []struct {
			name string
			key  *rsa.PrivateKey
		}{
			{"2048", test2048Key},
			{"3072", test3072Key},
			{"4096", test4096Key},
		} {
			t.Run(pk.name, func(t *testing.T) {
				t.Run("Private", func(t *testing.T) {
					var kmc KeyMaterial
					if err := EncodeKey(pk.key, &kmc); err != nil {
						t.Fatal(err)
					}

					d, err := kmc.Decode()
					if err != nil {
						t.Fatal(err)
					}

					out, ok := d.(*rsa.PrivateKey)
					if !ok {
						t.Fatalf("unexpected key type: %T", d)
					}
					if !out.Equal(pk.key) {
						t.Fatalf("rsa key: %v,\nwant %v", out, pk)
					}
				})

				t.Run("Public", func(t *testing.T) {
					var kmc KeyMaterial
					public := pk.key.Public()
					if err := EncodeKey(public, &kmc); err != nil {
						t.Fatal(err)
					}

					d, err := kmc.Decode()
					if err != nil {
						t.Fatal(err)
					}

					out, ok := d.(*rsa.PublicKey)
					if !ok {
						t.Fatalf("unexpected key type: %T", d)
					}
					if !out.Equal(public) {
						t.Fatalf("unexpected key value: %v", out)
					}
				})
			})
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		for _, r := range []struct {
			name  string
			curve elliptic.Curve
		}{
			{"P256", elliptic.P256()},
			{"P384", elliptic.P384()},
			{"P521", elliptic.P521()},
		} {
			t.Run(r.name, func(t *testing.T) {
				priv, err := ecdsa.GenerateKey(r.curve, rand.New(rand.NewSource(0)))
				if err != nil {
					t.Fatal(err)
				}

				t.Run("Private", func(t *testing.T) {
					var kmc KeyMaterial
					if err := EncodeKey(priv, &kmc); err != nil {
						t.Fatal(err)
					}

					d, err := kmc.Decode()
					if err != nil {
						t.Fatal(err)
					}

					out, ok := d.(*ecdsa.PrivateKey)
					if !ok {
						t.Fatalf("unexpected key type: %T", d)
					}
					if !out.Equal(priv) {
						t.Fatalf("unexpected key value: %v", out)
					}
				})

				t.Run("Public", func(t *testing.T) {
					var kmc KeyMaterial
					public := priv.Public()
					if err := EncodeKey(public, &kmc); err != nil {
						t.Fatal(err)
					}

					d, err := kmc.Decode()
					if err != nil {
						t.Fatal(err)
					}

					out, ok := d.(*ecdsa.PublicKey)
					if !ok {
						t.Fatalf("unexpected key type: %T", d)
					}
					if !out.Equal(public) {
						t.Fatalf("unexpected key value: %v", out)
					}
				})
			})
		}
	})
	t.Run("Symmetric", func(t *testing.T) {
		rr := rand.New(rand.NewSource(0))
		sym := make(SymmetricKey, 256)
		if _, err := rr.Read(sym); err != nil {
			t.Fatal(err)
		}

		var kmc KeyMaterial
		if err := EncodeKey(sym, &kmc); err != nil {
			t.Fatal(err)
		}

		d, err := kmc.Decode()
		if err != nil {
			t.Fatal(err)
		}

		out, ok := d.(SymmetricKey)
		if !ok {
			t.Fatalf("unexpected key type: %T", d)
		}
		if !out.Equal(sym) {
			t.Fatalf("unexpected key value: %v", out)
		}
	})

	t.Run("OKP", func(t *testing.T) {
		rr := rand.New(rand.NewSource(0))
		_, priv, err := ed25519.GenerateKey(rr)
		if err != nil {
			t.Fatal(err)
		}

		t.Run("Private", func(t *testing.T) {
			var kmc KeyMaterial
			if err := EncodeKey(priv, &kmc); err != nil {
				t.Fatal(err)
			}

			d, err := kmc.Decode()
			if err != nil {
				t.Fatal(err)
			}

			out, ok := d.(ed25519.PrivateKey)
			if !ok {
				t.Fatalf("unexpected key type: %T", d)
			}
			if !out.Equal(priv) {
				t.Fatalf("unexpected key value: %v", out)
			}
		})

		t.Run("Public", func(t *testing.T) {
			var kmc KeyMaterial
			public := priv.Public()
			if err := EncodeKey(public, &kmc); err != nil {
				t.Fatal(err)
			}

			d, err := kmc.Decode()
			if err != nil {
				t.Fatal(err)
			}

			out, ok := d.(ed25519.PublicKey)
			if !ok {
				t.Fatalf("unexpected key type: %T", d)
			}
			if !out.Equal(public) {
				t.Fatalf("unexpected key value: %v", out)
			}
		})
	})
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func parseKey(s string) *rsa.PrivateKey {
	p, _ := pem.Decode([]byte(s))
	k, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}
