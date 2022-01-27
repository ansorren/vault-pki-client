package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	_, err := NewClient(
		WithAddress("http://localhost:8200"),
		WithToken("admin"),
		WithConfig(nil),
	)

	require.Nil(t, err)
}
