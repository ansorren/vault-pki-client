package pki

import (
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
)

// GenerateIntermediateCA generates an intermediate CA in the PKI secrets engine at the
// given path and then returns it.
func (c *Client) GenerateIntermediateCA(path string, commonName string) (*x509.CertificateRequest, error) {
	generateIntermediatePath := fmt.Sprintf("%s/intermediate/generate/internal", path)

	secret, err := c.Client.Logical().Write(generateIntermediatePath, map[string]interface{}{
		"common_name": commonName,
		"ttl":         DefaultMaxLeaseTTL,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate ca certificate")
	}

	csr, ok := secret.Data["csr"].(string)
	if !ok {
		return nil, errors.Wrapf(err, "unable to cast csr into string")
	}
	csrBytes := []byte(csr)

	certSignedRequest, err := parseCSR(csrBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse CSR")
	}
	return certSignedRequest, nil
}
