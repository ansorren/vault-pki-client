package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_GenerateRootCA(t *testing.T) {
	client, err := NewClient(
		WithAddress("http://localhost:8200"),
		WithToken("admin"),
	)

	require.Nil(t, err)

	cleanup(client)
	defer cleanup(client)

	err = client.EnablePKIEngine("pki")
	require.Nil(t, err)

	c, err := client.GenerateRootCA("pki", "foo")
	require.Nil(t, err)

	require.True(t, c.IsCA)
	require.Equal(t, "foo", c.Subject.CommonName)
}
