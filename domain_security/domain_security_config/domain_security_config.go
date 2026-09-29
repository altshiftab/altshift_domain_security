// Package domain_security_config configures a domain security assessment.
package domain_security_config

import (
	"context"
	"net"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
)

// DefaultDkimSelectors is the short list of selectors an assessment probes when
// the caller names none.
//
// DKIM offers no way to enumerate a domain's selectors, so they can only be
// guessed at, and every guess costs a DNS query. This list is the handful that
// covers the common providers. For an exhaustive sweep, pass
// dnsUtilsClient.CommonDkimSelectors() instead - it carries far more selectors,
// at a proportionally larger number of lookups.
var DefaultDkimSelectors = []string{
	"google",
	"selector1",
	"selector2",
	"k1",
	"k2",
	"sig1",
	"mail",
	"email",
	"default",
	"dkim",
}

type Option func(*Config)

// StatusReader reads the states a registry records a domain in. *registration.Checker satisfies it.
type StatusReader interface {
	Statuses(ctx context.Context, domain string) ([]string, error)
}

type Config struct {
	DnsClient *dnsUtilsClient.Client
	// StatusReader is where the registration locks are read. Nil is an RDAP checker of its own.
	StatusReader StatusReader
	// AllowedNetworks are the networks the domain's owner acknowledges sending
	// from. An SPF record authorising anything outside them is reported.
	// Leaving it empty disables the check rather than failing everything.
	AllowedNetworks []*net.IPNet
	DkimSelectors   []string
}

func New(options ...Option) *Config {
	config := &Config{
		DnsClient:     dnsUtilsClient.DefaultClient,
		DkimSelectors: DefaultDkimSelectors,
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		option(config)
	}

	return config
}

func WithDnsClient(dnsClient *dnsUtilsClient.Client) Option {
	return func(config *Config) {
		config.DnsClient = dnsClient
	}
}

func WithAllowedNetworks(allowedNetworks ...*net.IPNet) Option {
	return func(config *Config) {
		config.AllowedNetworks = allowedNetworks
	}
}

func WithStatusReader(statusReader StatusReader) Option {
	return func(config *Config) {
		config.StatusReader = statusReader
	}
}

func WithDkimSelectors(dkimSelectors ...string) Option {
	return func(config *Config) {
		config.DkimSelectors = dkimSelectors
	}
}
