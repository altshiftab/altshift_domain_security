package discovery_config

import (
	"testing"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	otherClient := dnsUtilsClient.New()

	testCases := []struct {
		name   string
		option Option
		check  func(*testing.T, *Config)
	}{
		{
			name: "defaults to the default dns client",
			check: func(t *testing.T, config *Config) {
				if config.DnsClient != dnsUtilsClient.DefaultClient {
					t.Error("DnsClient is not the default client")
				}
			},
		},
		{
			name:   "whoisxml api key",
			option: WithWhoisXmlApiKey("key"),
			check: func(t *testing.T, config *Config) {
				if config.WhoisXmlApiKey != "key" {
					t.Errorf("WhoisXmlApiKey = %q, want %q", config.WhoisXmlApiKey, "key")
				}
			},
		},
		{
			name:   "hackertarget api key",
			option: WithHackerTargetApiKey("key"),
			check: func(t *testing.T, config *Config) {
				if config.HackerTargetApiKey != "key" {
					t.Errorf("HackerTargetApiKey = %q, want %q", config.HackerTargetApiKey, "key")
				}
			},
		},
		{
			name:   "historical reverse whois",
			option: WithHistoricalReverseWhois(true),
			check: func(t *testing.T, config *Config) {
				if !config.HistoricalReverseWhois {
					t.Error("HistoricalReverseWhois = false, want true")
				}
			},
		},
		{
			name:   "fetch options",
			option: WithFetchOptions(fetch_config.WithMethod("POST")),
			check: func(t *testing.T, config *Config) {
				if len(config.FetchOptions) != 1 {
					t.Errorf("len(FetchOptions) = %d, want 1", len(config.FetchOptions))
				}
			},
		},
		{
			name:   "dns client",
			option: WithDnsClient(otherClient),
			check: func(t *testing.T, config *Config) {
				if config.DnsClient != otherClient {
					t.Error("DnsClient is not the supplied client")
				}
			},
		},
		{
			name:   "a nil option is skipped rather than panicking",
			option: nil,
			check: func(t *testing.T, config *Config) {
				if config == nil {
					t.Error("New() = nil")
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var options []Option
			if testCase.option != nil || testCase.name == "a nil option is skipped rather than panicking" {
				options = append(options, testCase.option)
			}

			config := New(options...)
			if config == nil {
				t.Fatal("New() = nil")
			}

			testCase.check(t, config)
		})
	}
}
