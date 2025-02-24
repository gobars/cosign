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

package cosign

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/cosign/v2/pkg/cosign/fulcioverifier/ctutil"

	"github.com/gobars/sigstore/pkg/cryptoutils"
	"github.com/gobars/sigstore/pkg/tuf"
)

// ContainsSCT checks if the certificate contains embedded SCTs. cert can either be
// DER or PEM encoded.
func ContainsSCT(cert []byte) (bool, error) {
	embeddedSCTs, err := x509util.ParseSCTsFromCertificate(cert)
	if err != nil {
		return false, err
	}
	if len(embeddedSCTs) != 0 {
		return true, nil
	}
	return false, nil
}

func getCTPublicKey(sct *ct.SignedCertificateTimestamp,
	pubKeys *TrustedTransparencyLogPubKeys) (*TransparencyLogPubKey, error) {
	keyID := hex.EncodeToString(sct.LogID.KeyID[:])
	pubKeyMetadata, ok := pubKeys.Keys[keyID]
	if !ok {
		return nil, errors.New("ctfe public key not found for payload. Check your TUF root (see cosign initialize) or set a custom key with env var SIGSTORE_CT_LOG_PUBLIC_KEY_FILE")
	}
	return &pubKeyMetadata, nil
}

// VerifySCT verifies SCTs against the Fulcio CT log public key.
//
// The SCT is a `Signed Certificate Timestamp`, which promises that
// the certificate issued by Fulcio was also added to the public CT log within
// some defined time period.
//
// VerifySCT can verify an SCT list embedded in the certificate, or a detached
// SCT provided by Fulcio.
//
// Note that we can't pass in the CheckOpts here which has both RawSCT and
// CTLogPubKeys due to import cycle, so they are pulled out from the struct
// to arguments here.
//
// By default the public keys comes from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE`. If using
// an alternate, the file can be PEM, or DER format.
func VerifySCT(_ context.Context, certPEM, chainPEM, rawSCT []byte, pubKeys *TrustedTransparencyLogPubKeys) error {
	if pubKeys == nil || len(pubKeys.Keys) == 0 {
		return errors.New("none of the CTFE keys have been found")
	}

	// parse certificate and chain
	cert, err := x509util.CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}
	certChain, err := x509util.CertificatesFromPEM(chainPEM)
	if err != nil {
		return err
	}
	if len(certChain) == 0 {
		return errors.New("no certificate chain found")
	}

	// fetch embedded SCT if present
	embeddedSCTs, err := x509util.ParseSCTsFromCertificate(certPEM)
	if err != nil {
		return err
	}
	// SCT must be either embedded or in header
	if len(embeddedSCTs) == 0 && len(rawSCT) == 0 {
		return errors.New("no SCT found")
	}

	// check SCT embedded in certificate
	if len(embeddedSCTs) != 0 {
		for _, sct := range embeddedSCTs {
			pubKeyMetadata, err := getCTPublicKey(sct, pubKeys)
			if err != nil {
				return err
			}
			err = ctutil.VerifySCT(pubKeyMetadata.PubKey, []*ctx509.Certificate{cert, certChain[0]}, sct, true)
			if err != nil {
				return fmt.Errorf("error verifying embedded SCT")
			}
			if pubKeyMetadata.Status != tuf.Active {
				fmt.Fprintf(os.Stderr, "**Info** Successfully verified embedded SCT using an expired verification key\n")
			}
		}
		return nil
	}

	// check SCT in response header
	var addChainResp ct.AddChainResponse
	if err := json.Unmarshal(rawSCT, &addChainResp); err != nil {
		return fmt.Errorf("unmarshal")
	}
	sct, err := addChainResp.ToSignedCertificateTimestamp()
	if err != nil {
		return err
	}
	pubKeyMetadata, err := getCTPublicKey(sct, pubKeys)
	if err != nil {
		return err
	}
	err = ctutil.VerifySCT(pubKeyMetadata.PubKey, []*ctx509.Certificate{cert}, sct, false)
	if err != nil {
		return fmt.Errorf("error verifying SCT")
	}
	if pubKeyMetadata.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified SCT using an expired verification key\n")
	}
	return nil
}

// VerifyEmbeddedSCT verifies an embedded SCT in a certificate.
func VerifyEmbeddedSCT(ctx context.Context, chain []*x509.Certificate, pubKeys *TrustedTransparencyLogPubKeys) error {
	if len(chain) < 2 {
		return errors.New("certificate chain must contain at least a certificate and its issuer")
	}
	certPEM, err := cryptoutils.MarshalCertificateToPEM(chain[0])
	if err != nil {
		return err
	}
	chainPEM, err := cryptoutils.MarshalCertificatesToPEM(chain[1:])
	if err != nil {
		return err
	}
	return VerifySCT(ctx, certPEM, chainPEM, []byte{}, pubKeys)
}
