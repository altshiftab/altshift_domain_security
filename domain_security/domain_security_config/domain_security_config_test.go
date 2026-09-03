package domain_security_config

import (
	"net"
	"slices"
	"testing"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
)

func mustParseCidr(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net parse cidr: %v", err)
	}

	return network
}

func TestNew(t *testing.T) {
	t.Parallel()

	otherClient := dnsUtilsClient.New()
	network := mustParseCidr(t, "192.0.2.0/24")

	testCases := []struct {
		name    string
		options []Option
		check   func(*testing.T, *Config)
	}{
		{
			name: "defaults",
			check: func(t *testing.T, config *Config) {
				if config.DnsClient != dnsUtilsClient.DefaultClient {
					t.Error("DnsClient is not the default client")
				}
				if !slices.Equal(config.DkimSelectors, DefaultDkimSelectors) {
					t.Errorf("DkimSelectors = %v, want the default list", config.DkimSelectors)
				}
				if len(config.AllowedNetworks) != 0 {
					t.Errorf("AllowedNetworks = %v, want none", config.AllowedNetworks)
				}
			},
		},
		{
			name:    "dns client",
			options: []Option{WithDnsClient(otherClient)},
			check: func(t *testing.T, config *Config) {
				if config.DnsClient != otherClient {
					t.Error("DnsClient is not the supplied client")
				}
			},
		},
		{
			name:    "allowed networks",
			options: []Option{WithAllowedNetworks(network)},
			check: func(t *testing.T, config *Config) {
				if len(config.AllowedNetworks) != 1 || config.AllowedNetworks[0] != network {
					t.Errorf("AllowedNetworks = %v, want the supplied network", config.AllowedNetworks)
				}
			},
		},
		{
			name:    "dkim selectors override the default list",
			options: []Option{WithDkimSelectors("alpha", "beta")},
			check: func(t *testing.T, config *Config) {
				if !slices.Equal(config.DkimSelectors, []string{"alpha", "beta"}) {
					t.Errorf("DkimSelectors = %v, want [alpha beta]", config.DkimSelectors)
				}
			},
		},
		{
			name:    "a nil option is skipped rather than panicking",
			options: []Option{nil},
			check: func(t *testing.T, config *Config) {
				if config.DnsClient == nil {
					t.Error("DnsClient = nil")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := New(testCase.options...)
			if config == nil {
				t.Fatal("New() = nil")
			}

			testCase.check(t, config)
		})
	}
}

func TestDefaultDkimSelectorsAreDistinct(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, len(DefaultDkimSelectors))
	for _, selector := range DefaultDkimSelectors {
		if selector == "" {
			t.Error("a default selector is empty")
		}
		if seen[selector] {
			t.Errorf("selector %q is listed more than once, costing a duplicate lookup", selector)
		}
		seen[selector] = true
	}
}
