//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gobars/sigstore/pkg/signature/myhash"
	"github.com/gobars/sigstore/pkg/signature/sm2"
	"os"
	"path/filepath"

	"github.com/gobars/sigstore/pkg/cryptoutils"
	"github.com/gobars/sigstore/pkg/signature"
	bx509 "github.com/gobars/sigstore/pkg/signature/x509"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

const (
	CosignPrivateKeyPemType   = "ENCRYPTED COSIGN PRIVATE KEY"
	SigstorePrivateKeyPemType = "ENCRYPTED SIGSTORE PRIVATE KEY"
	// PEM-encoded PKCS #1 RSA private key
	RSAPrivateKeyPemType = "RSA PRIVATE KEY"
	// PEM-encoded ECDSA private key
	ECPrivateKeyPemType = "EC PRIVATE KEY"
	// PEM-encoded PKCS #8 RSA, ECDSA or ED25519 private key
	PrivateKeyPemType   = "PRIVATE KEY"
	BundleKey           = static.BundleAnnotationKey
	RFC3161TimestampKey = static.RFC3161TimestampAnnotationKey
)

// PassFunc is the function to be called to retrieve the signer password. If
// nil, then it assumes that no password is provided.
type PassFunc func(bool) ([]byte, error)

type Keys struct {
	private crypto.PrivateKey
	public  crypto.PublicKey
}

// TODO(jason): Move this to an internal package.
type KeysBytes struct {
	PrivateBytes []byte
	PublicBytes  []byte
	password     []byte
}

func (k *KeysBytes) Password() []byte {
	return k.password
}

// TODO(jason): Move this to an internal package.
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// TODO(jason): Move this to the only place it's used in cmd/cosign/cli/importkeypair, and unexport it.
func ImportKeyPair(keyPath string, pf PassFunc) (*KeysBytes, error) {
	kb, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(kb)
	if p == nil {
		return nil, fmt.Errorf("invalid pem block")
	}

	var pk crypto.Signer

	switch p.Type {
	case RSAPrivateKeyPemType:
		rsaPk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key: %w", err)
		}
		if err = cryptoutils.ValidatePubKey(rsaPk.Public()); err != nil {
			return nil, fmt.Errorf("error validating rsa key: %w", err)
		}
		pk = rsaPk
	case ECPrivateKeyPemType:
		ecdsaPk, err := x509.ParseECPrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key")
		}
		if err = cryptoutils.ValidatePubKey(ecdsaPk.Public()); err != nil {
			return nil, fmt.Errorf("error validating ecdsa key: %w", err)
		}
		pk = ecdsaPk
	case PrivateKeyPemType:
		pkcs8Pk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs #8 private key")
		}
		switch k := pkcs8Pk.(type) {
		case *rsa.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating rsa key: %w", err)
			}
			pk = k
		case *ecdsa.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating ecdsa key: %w", err)
			}
			pk = k
		case ed25519.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating ed25519 key: %w", err)
			}
			pk = k
		default:
			return nil, fmt.Errorf("unexpected private key")
		}
	default:
		return nil, fmt.Errorf("unsupported private key")
	}
	return marshalKeyPair(p.Type, Keys{pk, pk.Public()}, pf, false)
}

func marshalKeyPair(ptype string, keypair Keys, pf PassFunc, useSm2 bool) (key *KeysBytes, err error) {
	var x509Encoded, pubBytes []byte

	if useSm2 {
		key := keypair.private.(*sm2.PrivateKey)
		x509Encoded, err = bx509.MarshalSm2UnecryptedPrivateKey(key)
	} else {
		x509Encoded, err = x509.MarshalPKCS8PrivateKey(keypair.private)
	}
	if err != nil {
		return nil, fmt.Errorf("x509 encoding private key: %w", err)
	}

	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			return nil, err
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		return nil, err
	}

	// default to SIGSTORE, but keep support of COSIGN
	if ptype != CosignPrivateKeyPemType {
		ptype = SigstorePrivateKeyPemType
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  ptype,
	})

	if useSm2 {
		pubBytes, err = bx509.MarshalSm2PublicKey(keypair.public.(*sm2.PublicKey))
		if err != nil {
			return nil, err
		}
		pubBytes = cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, pubBytes)

	} else {
		// Now do the public key
		pubBytes, err = cryptoutils.MarshalPublicKeyToPEM(keypair.public)
	}

	if err != nil {
		return nil, err
	}

	return &KeysBytes{
		PrivateBytes: privBytes,
		PublicBytes:  pubBytes,
		password:     password,
	}, nil
}

// TODO(jason): Move this to an internal package.
func GenerateKeyPair(pf PassFunc, useSm2 bool) (*KeysBytes, error) {
	if !useSm2 {
		priv, err := GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		return marshalKeyPair(SigstorePrivateKeyPemType, Keys{priv, priv.Public()}, pf, useSm2)
	} else {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return marshalKeyPair(SigstorePrivateKeyPemType, Keys{priv, priv.Public()}, pf, useSm2)
	}

	// Emit SIGSTORE keys by default
}

// TODO(jason): Move this to an internal package.
func PemToECDSAKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key: was %T, require *ecdsa.PublicKey", pub)
	}
	return ecdsaPub, nil
}

// TODO(jason): Move this to pkg/signature, the only place it's used, and unimport it.
func LoadPrivateKey(key []byte, pass []byte) (signature.SignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}
	if p.Type != CosignPrivateKeyPemType && p.Type != SigstorePrivateKeyPemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	pk, err := ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		return signature.LoadRSAPKCS1v15SignerVerifier(pk, myhash.SHA256)
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASignerVerifier(pk, myhash.SHA256)
	case ed25519.PrivateKey:
		return signature.LoadED25519SignerVerifier(pk)
	case *sm2.PrivateKey:
		return signature.LoadSM2SignerVerifier(pk, myhash.SM3)
	default:
		return nil, errors.New("unsupported key type")
	}
}
