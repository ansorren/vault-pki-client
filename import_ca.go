package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
)

// SetSignedCertificate sets the signed certificate into the
// intermediate PKI secrets engine at the given path.
func (c *Client) SetSignedCertificate(path string, cert interface{}) error {
	signedCertPath := fmt.Sprintf("%s/intermediate/set-signed", path)
	certStr, ok := cert.(string)
	if !ok {
		return errors.New("unable to cast certificate to string")
	}

	_, err := c.Client.Logical().Write(signedCertPath, map[string]interface{}{
		"certificate": certStr,
	})
	if err != nil {
		return errors.Wrapf(err, "unable to set signed certificate at path %s", path)
	}
	return nil
}

// SignIntermediateCA signs the CSR and imports it into the given
// root PKI secrets engine.
func (c *Client) SignIntermediateCA(path string, csr *x509.CertificateRequest) (interface{}, error) {
	var cert interface{}
	signPath := fmt.Sprintf("%s/root/sign-intermediate", path)

	block := &pem.Block{
		Type:    CsrPemBlockType,
		Headers: nil,
		Bytes:   csr.Raw,
	}

	var b = &bytes.Buffer{}
	err := pem.Encode(b, block)
	if err != nil {
		return cert, errors.Wrapf(err, "unable to encode pem block")
	}

	secret, err := c.Client.Logical().Write(signPath, map[string]interface{}{
		"csr":    b.String(),
		"format": "pem_bundle",
		"ttl":    DefaultMaxLeaseTTL,
	})
	if err != nil {
		return cert, errors.Wrapf(err, "unable to sign intermediate CA certificate")
	}

	cert, ok := secret.Data["certificate"]
	if !ok {
		return cert, errors.New("got malformed secret, could not lookup certificate key")
	}
	return cert, nil
}
