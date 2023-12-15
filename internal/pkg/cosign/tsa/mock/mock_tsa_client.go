// Copyright 2022 The Sigstore Authors.
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

package mock

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"github.com/gobars/sigstore/pkg/signature/myhash"
	"io"
	"time"

	"github.com/pkg/errors"

	"github.com/digitorus/timestamp"
	"github.com/gobars/sigstore/pkg/cryptoutils"
	"github.com/gobars/sigstore/pkg/signature"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/timestamp-authority/pkg/signer"
)

// TSAClient creates RFC3161 timestamps and implements client.TimestampAuthority.
// Messages to sign can either be provided in the initializer or through the request.
// Time can be provided in the initializer, or defaults to time.Now().
// All other timestamp parameters are hardcoded.
type TSAClient struct {
	client.TimestampAuthorityClient

	Signer    myhash.Signer
	CertChain []*x509.Certificate
	Time      time.Time
	Message   []byte
}

// TSAClientOptions provide customization for the mock TSA client.
type TSAClientOptions struct {
	// Time is an optional timestamp. Default is time.Now().
	Time time.Time
	// Message is the pre-hashed message to sign over, typically a raw signature.
	Message []byte
	// Signer is an optional signer created out of band. Client creates one if not set.
	Signer myhash.Signer
}

func NewTSAClient(o TSAClientOptions) (*TSAClient, error) {
	sv := o.Signer
	if sv == nil {
		var err error
		sv, _, err = signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, myhash.SHA256)
		if err != nil {
			return nil, err
		}
	}
	certChain, err := signer.NewTimestampingCertWithChain(toSigner(sv))
	if err != nil {
		return nil, errors.Wrap(err, "generating timestamping cert chain")
	}

	return &TSAClient{
		Signer:    sv,
		CertChain: certChain,
		Time:      o.Time,
		Message:   o.Message,
	}, nil
}

func (c *TSAClient) GetTimestampResponse(tsq []byte) ([]byte, error) {
	var hashAlg crypto.Hash
	var hashedMessage []byte

	if tsq != nil {
		req, err := timestamp.ParseRequest(tsq)
		if err != nil {
			return nil, err
		}
		hashAlg = req.HashAlgorithm
		hashedMessage = req.HashedMessage
	} else {
		hashAlg = crypto.SHA256
		h := hashAlg.New()
		h.Write(c.Message)
		hashedMessage = h.Sum(nil)
	}

	nonce, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	duration, _ := time.ParseDuration("1s")

	tsStruct := timestamp.Timestamp{
		HashAlgorithm:     hashAlg,
		HashedMessage:     hashedMessage,
		Nonce:             nonce,
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:          false,
		Accuracy:          duration,
		Qualified:         false,
		AddTSACertificate: true,
	}

	if c.Time.IsZero() {
		tsStruct.Time = time.Now()
	} else {
		tsStruct.Time = c.Time
	}

	return tsStruct.CreateResponseWithOpts(c.CertChain[0], toSigner(c.Signer), crypto.SHA256)
}

type SignerAdapter struct {
	signer myhash.Signer
}

type SignerOptsAdapter struct {
	opts crypto.SignerOpts
}

func (s SignerOptsAdapter) HashFunc() myhash.Hash {
	return myhash.Hash(s.opts.HashFunc())
}

func (s SignerAdapter) Public() crypto.PublicKey {
	return s.signer.Public()
}

func (s SignerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.signer.Sign(rand, digest, SignerOptsAdapter{opts: opts})
}

func toSigner(s myhash.Signer) crypto.Signer {
	return SignerAdapter{
		signer: s,
	}
}
