package pki

import (
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// Client is the vault client that knows how to talk to the
type Client struct {
	Address string
	Token   string
	Client  *api.Client
}

type Option func(client *Client) error

// WithAddress sets the given address on the client.
func WithAddress(vaultAddr string) Option {
	return func(c *Client) error {
		c.Address = vaultAddr
		return nil
	}
}

// WithToken sets the given token on the client.
func WithToken(vaultToken string) Option {
	return func(c *Client) error {
		c.Token = vaultToken
		return nil
	}
}

// WithConfig instantiates a vault client with the given config.
func WithConfig(config *api.Config) Option {
	return func(c *Client) error {
		client, err := api.NewClient(config)
		if err != nil {
			return errors.Wrapf(err, "unable to set client")
		}
		c.Client = client
		return nil
	}
}

// NewClient instantiates a new PKI client.
func NewClient(options ...Option) (*Client, error) {
	var c = &Client{}
	defaultVaultClient, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to instantiate default vault client")
	}
	c.Client = defaultVaultClient

	for _, option := range options {
		err := option(c)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to set option")
		}
	}
	c.Client.SetToken(c.Token)
	err = c.Client.SetAddress(c.Address)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to set vault address to %s", c.Address)
	}
	return c, nil
}
