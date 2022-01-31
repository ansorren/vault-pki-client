package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_TestFullIntegration(t *testing.T) {
	rootClient, err := NewClient(
		WithAddress("http://localhost:8200"),
		WithToken("admin"),
	)
	require.Nil(t, err)

	intermediateClient, err := NewClient(
		WithAddress("http://localhost:8201"),
		WithToken("admin"),
	)

	require.Nil(t, err)

	cleanup(rootClient)
	cleanup(intermediateClient)

	defer cleanup(rootClient)
	defer cleanup(intermediateClient)

	err = rootClient.EnablePKIEngine("pki")
	require.Nil(t, err)

	err = intermediateClient.EnablePKIEngine("pki")
	require.Nil(t, err)

	_, err = rootClient.GenerateRootCA("pki", "foo")
	require.Nil(t, err)

	csr, err := intermediateClient.GenerateIntermediateCA("pki", "bar")
	require.Nil(t, err)

	signedCertificate, err := rootClient.SignIntermediateCA("pki", csr)
	require.Nil(t, err)

	err = intermediateClient.SetSignedCertificate("pki", signedCertificate)
	require.Nil(t, err)

	opts := CreatePKIRoleOptions{
		RoleName:         "foo",
		AllowedDomains:   []string{"localhost"},
		AllowSubdomains:  true,
		AllowBareDomains: true,
		AllowGlobDomains: true,
		MaxTTL:           "768h",
	}

	err = intermediateClient.CreatePKIRole("pki", opts)
	require.Nil(t, err)
}
