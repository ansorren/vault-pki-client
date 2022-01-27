package pki

import (
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
)

// GenerateRootCA generates a root CA in the PKI secrets engine at the
// given path and then returns it.
func (c *Client) GenerateRootCA(path string, commonName string) (*x509.Certificate, error) {
	generateRootPath := fmt.Sprintf("%s/root/generate/internal", path)

	secret, err := c.Client.Logical().Write(generateRootPath, map[string]interface{}{
		"common_name": commonName,
		"ttl":         DefaultMaxLeaseTTL,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate ca certificate")
	}

	cert, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.Wrapf(err, "unable to cast certificate into string")
	}

	certBytes := []byte(cert)

	certificate, err := parseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse certificate")
	}
	return certificate, nil
}
