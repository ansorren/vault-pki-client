package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_GenerateIntermediateCA(t *testing.T) {
	client, err := NewClient(
		WithAddress("http://localhost:8201"),
		WithToken("admin"),
	)

	require.Nil(t, err)

	cleanup(client)
	defer cleanup(client)

	err = client.EnablePKIEngine("pki")
	require.Nil(t, err)

	csr, err := client.GenerateIntermediateCA("pki", "foo")
	require.Nil(t, err)

	require.Equal(t, "foo", csr.Subject.CommonName)
}
