// Package discovery_config configures a domain discovery run.
package discovery_config

import (
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Option func(*Config)

// Config holds everything a discovery run needs. A source with no API key is
// simply not consulted, so a run can be narrowed by leaving keys out rather
// than by selecting sources explicitly.
type Config struct {
	WhoisXmlApiKey         string
	HistoricalReverseWhois bool
	HackerTargetApiKey     string
	FetchOptions           []fetch_config.Option
	DnsClient              *dnsUtilsClient.Client
}

func New(options ...Option) *Config {
	config := &Config{DnsClient: dnsUtilsClient.DefaultClient}
	for _, option := range options {
		if option == nil {
			continue
		}
		option(config)
	}

	return config
}

func WithWhoisXmlApiKey(whoisXmlApiKey string) Option {
	return func(config *Config) {
		config.WhoisXmlApiKey = whoisXmlApiKey
	}
}

// WithHistoricalReverseWhois searches registrations as they once were rather
// than as they stand now.
func WithHistoricalReverseWhois(historicalReverseWhois bool) Option {
	return func(config *Config) {
		config.HistoricalReverseWhois = historicalReverseWhois
	}
}

func WithHackerTargetApiKey(hackerTargetApiKey string) Option {
	return func(config *Config) {
		config.HackerTargetApiKey = hackerTargetApiKey
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = fetchOptions
	}
}

func WithDnsClient(dnsClient *dnsUtilsClient.Client) Option {
	return func(config *Config) {
		config.DnsClient = dnsClient
	}
}
