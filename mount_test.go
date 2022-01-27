package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// cleanup is an helper function that unmounts the PKI secrets engine
func cleanup(c *Client) {
	_ = c.Client.Sys().Unmount("pki")
}

func TestClient_EnablePKIEngine(t *testing.T) {
	client, err := NewClient(
		WithAddress("http://localhost:8200"),
		WithToken("admin"),
	)
	require.Nil(t, err)

	cleanup(client)
	defer cleanup(client)

	err = client.EnablePKIEngine("pki")
	require.Nil(t, err)

	// enable again to test idempotency
	err = client.EnablePKIEngine("pki")
	require.Nil(t, err)
}
