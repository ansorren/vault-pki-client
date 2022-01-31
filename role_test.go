package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_CreatePKIRole(t *testing.T) {
	client, err := NewClient(
		WithAddress("http://localhost:8201"),
		WithToken("admin"),
	)
	require.Nil(t, err)

	cleanup(client)
	defer cleanup(client)

	err = client.EnablePKIEngine("pki")
	require.Nil(t, err)

	opts := CreatePKIRoleOptions{
		RoleName:         "foo",
		AllowedDomains:   []string{"localhost"},
		AllowSubdomains:  true,
		AllowBareDomains: true,
		AllowGlobDomains: true,
		MaxTTL:           "768h",
	}

	err = client.CreatePKIRole("pki", opts)
	require.Nil(t, err)
}
