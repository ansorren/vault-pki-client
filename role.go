package pki

import (
	"fmt"

	"github.com/pkg/errors"
)

// CreatePKIRoleOptions is the data structure that holds the
// configuration required to create a PKI Role.
type CreatePKIRoleOptions struct {
	RoleName         string
	AllowedDomains   []string
	AllowSubdomains  bool
	AllowBareDomains bool
	AllowGlobDomains bool
	MaxTTL           string
}

// CreatePKIRole creates a PKI role with the given options at the given path.
func (c *Client) CreatePKIRole(path string, opts CreatePKIRoleOptions) error {
	pkiRolePath := fmt.Sprintf("%s/roles/%s", path, opts.RoleName)

	_, err := c.Client.Logical().Write(pkiRolePath, map[string]interface{}{
		"allowed_domains":    opts.AllowedDomains,
		"allow_subdomains":   opts.AllowSubdomains,
		"allow_bare_domains": opts.AllowBareDomains,
		"allow_glob_domains": opts.AllowGlobDomains,
		"max_ttl":            opts.MaxTTL,
	})

	if err != nil {
		return errors.Wrapf(err, "unable to create pki role %s at path %s", opts.RoleName, path)
	}

	return nil
}
