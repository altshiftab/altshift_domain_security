package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery/discovery_config"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/miekg/dns"
)

// getDomains consults every source the config carries a key for. A source that
// fails is logged and skipped rather than failing the run: a partial answer
// from the other source is worth more than no answer at all.
func getDomains(
	ctx context.Context,
	domainName string,
	config *discovery_config.Config,
) ([]*domainTypes.Domain, error) {
	if domainName == "" {
		return nil, nil
	}

	if config == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("config"))
	}

	var allDomains []*domainTypes.Domain
	var allDomainsMutex sync.Mutex
	var waitGroup sync.WaitGroup

	if whoisXmlApiKey := config.WhoisXmlApiKey; whoisXmlApiKey != "" {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			reverseWhoisDomains, err := ReverseWhois(
				ctx,
				domainName,
				whoisXmlApiKey,
				config.HistoricalReverseWhois,
				config.FetchOptions...,
			)
			if err != nil {
				slog.ErrorContext(
					altshiftContext.WithError(
						ctx,
						altshiftErrors.New(
							fmt.Errorf("reverse whois: %w", err),
							domainName, config.HistoricalReverseWhois,
						),
					),
					"An error occurred when performing reverse whois. Skipping the source.",
				)
				return
			}

			if len(reverseWhoisDomains) > 0 {
				allDomainsMutex.Lock()
				allDomains = append(allDomains, reverseWhoisDomains...)
				allDomainsMutex.Unlock()
			}
		}()
	}

	if hackerTargetApiKey := config.HackerTargetApiKey; hackerTargetApiKey != "" {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			reverseIpDomains, err := ReverseIpDomain(
				ctx,
				domainName,
				hackerTargetApiKey,
				config.DnsClient,
				config.FetchOptions...,
			)
			if err != nil {
				slog.ErrorContext(
					altshiftContext.WithError(
						ctx,
						altshiftErrors.New(fmt.Errorf("reverse ip domain: %w", err), domainName),
					),
					"An error occurred when performing a reverse IP lookup. Skipping the source.",
				)
				return
			}

			// Too many co-hosted domains means shared hosting, which says
			// nothing about ownership.
			if numDomains := len(reverseIpDomains); numDomains == 0 || numDomains >= sharedHostingDomainLimit {
				return
			}

			allDomainsMutex.Lock()
			allDomains = append(allDomains, reverseIpDomains...)
			allDomainsMutex.Unlock()
		}()
	}

	waitGroup.Wait()

	return MergeDomains(allDomains...), nil
}

// GetDomains returns every domain the configured sources attribute to the same
// owner as the given domain, whether or not those domains still resolve.
func GetDomains(
	ctx context.Context,
	domainName string,
	options ...discovery_config.Option,
) ([]*domainTypes.Domain, error) {
	return getDomains(ctx, domainName, discovery_config.New(options...))
}

func getActiveDomains(
	ctx context.Context,
	domainName string,
	config *discovery_config.Config,
) ([]*domainTypes.Domain, error) {
	if config == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("config"))
	}

	allDomains, err := getDomains(ctx, domainName, config)
	if err != nil {
		return nil, fmt.Errorf("get domains: %w", err)
	}

	activeDomains, err := FilterDomainNamesActive(ctx, allDomains, config.DnsClient)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("filter domain names active: %w", err), allDomains)
	}

	return activeDomains, nil
}

// GetActiveDomains narrows GetDomains to the domains that still resolve.
func GetActiveDomains(
	ctx context.Context,
	domainName string,
	options ...discovery_config.Option,
) ([]*domainTypes.Domain, error) {
	return getActiveDomains(ctx, domainName, discovery_config.New(options...))
}

// AddSendingMetadata records whether each domain looks like it is used to send
// email, guessing from the presence of MX records.
//
// The guess is only ever recorded as a guess: an operator's own assertion lives
// in MarkedNonSending and is never written here. A lookup that fails leaves the
// guess unset, which is the conservative reading - an unknown domain is treated
// as sending.
func AddSendingMetadata(
	ctx context.Context,
	domains []*domainTypes.Domain,
	dnsClient *dnsUtilsClient.Client,
) error {
	if len(domains) == 0 {
		return nil
	}

	if dnsClient == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	var waitGroup sync.WaitGroup

	for _, domain := range domains {
		if domain == nil {
			continue
		}

		domainName := domain.Domain
		if domainName == "" {
			continue
		}

		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			ctxWithDnsContext := dnsUtilsContext.WithDnsContext(ctx)

			records, err := dnsClient.GetDnsAnswers(ctxWithDnsContext, domainName, dns.TypeMX)
			if err != nil {
				// A domain that does not exist is not a failure to report; it
				// simply carries no guess.
				if rcodeError, ok := errors.AsType[*dnsUtilsErrors.RcodeError](err); ok && rcodeError != nil {
					if rcodeError.Rcode == dns.RcodeNameError {
						return
					}
				}

				slog.WarnContext(
					altshiftContext.WithError(
						ctxWithDnsContext,
						altshiftErrors.New(
							fmt.Errorf("get dns answers: %w", err),
							domainName, dnsClient,
						),
					),
					"An error occurred when looking up MX records for a domain. Leaving the sending guess unset.",
				)

				return
			}

			var mxRecordPresent bool
			for _, record := range records {
				if _, ok := record.(*dns.MX); ok {
					mxRecordPresent = true
					break
				}
			}

			domainMetadata := domain.Metadata
			if domainMetadata == nil {
				domainMetadata = &domainTypes.Metadata{}
				domain.Metadata = domainMetadata
			}

			// A domain with mail exchangers handles mail; one without is the
			// candidate for being non-sending.
			guessedNonSending := !mxRecordPresent
			domainMetadata.GuessedNonSending = &guessedNonSending
		}()
	}

	waitGroup.Wait()

	return nil
}

// GetActiveDomainsWithMetadata is GetActiveDomains with the sending guess filled in.
func GetActiveDomainsWithMetadata(
	ctx context.Context,
	domainName string,
	options ...discovery_config.Option,
) ([]*domainTypes.Domain, error) {
	config := discovery_config.New(options...)

	activeDomains, err := getActiveDomains(ctx, domainName, config)
	if err != nil {
		return nil, fmt.Errorf("get active domains: %w", err)
	}

	if err := AddSendingMetadata(ctx, activeDomains, config.DnsClient); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("add sending metadata: %w", err))
	}

	return activeDomains, nil
}

// GetValidatedActiveDomainsWithMetadata is the full discovery run: every source,
// narrowed to what resolves, annotated with the sending guess, and with anything
// that does not parse as a domain dropped.
func GetValidatedActiveDomainsWithMetadata(
	ctx context.Context,
	domainName string,
	options ...discovery_config.Option,
) ([]*domainTypes.Domain, error) {
	activeDomains, err := GetActiveDomainsWithMetadata(ctx, domainName, options...)
	if err != nil {
		return nil, fmt.Errorf("get active domains with metadata: %w", err)
	}

	return FilterDomainsValid(ctx, activeDomains), nil
}
