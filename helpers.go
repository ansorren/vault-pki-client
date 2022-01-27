package pki

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/pkg/errors"
)

const (
	CsrPemBlockType         = "CERTIFICATE REQUEST"
	CertificatePemBlockType = "CERTIFICATE"
	PrivateKeyPemBlockType  = "PRIVATE KEY"
)

// parseCertificate decodes a PEM-encoded certificate and returns a
// Certificate struct.
func parseCertificate(cert []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("unable to decode certificate")
	}
	if block.Type == CertificatePemBlockType {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse certificate")
		}
		return c, nil
	}
	if strings.Contains(block.Type, PrivateKeyPemBlockType) {
		// if the first block is a private key, it means we got a bundle.
		// parse the rest of the chain
		return parseCertificate(rest)
	}
	return nil, errors.New("unrecognized block type")
}

// parseCSR decodes a PEM-encoded CSR and returns it.
func parseCSR(csr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, errors.New("unable to decode csr")
	}

	if block.Type != CsrPemBlockType {
		return nil, errors.New("not a valid certificate request")
	}

	certSignedRequest, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse certificate signed request")
	}
	return certSignedRequest, nil
}
