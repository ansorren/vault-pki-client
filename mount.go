package pki

import (
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

const (
	DefaultLeaseTTL    = "24h"
	DefaultMaxLeaseTTL = "87600h"
)

// EnablePKIEngine enables the PKI engine at the given path.
func (c *Client) EnablePKIEngine(path string) error {
	sysClient := c.Client.Sys()
	pkiConfig := api.MountConfigInput{
		MaxLeaseTTL:     DefaultMaxLeaseTTL,
		DefaultLeaseTTL: DefaultLeaseTTL,
	}

	mountInfo := &api.MountInput{
		Type:   "pki",
		Config: pkiConfig,
	}

	err := sysClient.Mount(path, mountInfo)
	if err != nil {
		// if the path is already in use we assume the right secret engine is already mounted
		if strings.Contains(err.Error(), "path is already in use") {
			return nil
		}
		return errors.Wrapf(err, "cannot enable pki secret engine")
	}
	return nil
}
