// Package discovery finds the domains that belong to the same owner as a given
// domain, and records why each one was attributed.
//
// Two sources are consulted, neither of which is authoritative on its own:
// reverse whois, which matches registration records, and reverse IP, which
// matches co-hosted addresses. Each domain carries the inferences that produced
// it so a consumer can weigh them.
package discovery

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/whoisxml"
	whoisXmlTypes "github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/whoisxml/types"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	"github.com/altshiftab/altshift_domain_security/types/inference"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// sharedHostingDomainLimit bounds how many domains a single address may map to
// before the reverse-IP answer is discarded. Past this, the address is shared
// hosting and co-location says nothing about ownership.
const sharedHostingDomainLimit = 25

// The confidence each source is worth on the 1-to-5 scale. A registration
// record naming the same party is strong evidence; sharing an address is weak.
const (
	reverseWhoisConfidence = 4
	reverseIpConfidence    = 2
)

// excludedRegisteredDomains are registered domains that co-location can never
// say anything about, because everyone is on them.
var excludedRegisteredDomains = map[string]struct{}{
	"googleusercontent.com": {},
}

func extractRegisteredDomainNames(domainNames []string) []string {
	if len(domainNames) == 0 {
		return nil
	}

	registeredDomainsSet := make(map[string]struct{})

	for _, domainName := range domainNames {
		parts := domain_parts.New(domainName)
		if parts == nil {
			continue
		}

		if parts.RegisteredDomain != "" && parts.TopLevelDomain != "" {
			registeredDomainsSet[parts.RegisteredDomain] = struct{}{}
		}
	}

	return slices.Collect(maps.Keys(registeredDomainsSet))
}

// MergeDomains collapses domains that name the same host, keeping the union of
// their inferences so a domain found by two sources carries both reasons.
func MergeDomains(domains ...*domainTypes.Domain) []*domainTypes.Domain {
	domainsSet := make(map[string]*domainTypes.Domain)

	for _, domain := range domains {
		if domain == nil {
			continue
		}

		domainName := domain.Domain
		if domainName == "" {
			continue
		}

		existingDomain, ok := domainsSet[domainName]
		if !ok {
			domainsSet[domainName] = domain
			continue
		}

		existingDomainMetadata := existingDomain.Metadata
		if existingDomainMetadata == nil {
			existingDomainMetadata = &domainTypes.Metadata{}
			existingDomain.Metadata = existingDomainMetadata
		}

		if domainMetadata := domain.Metadata; domainMetadata != nil {
			existingDomainMetadata.Inferences = append(
				existingDomainMetadata.Inferences,
				domainMetadata.Inferences...,
			)
		}
	}

	return slices.Collect(maps.Values(domainsSet))
}

// ReverseWhois finds domains whose registration records carry an email address
// at the given domain. The API bills per search, so each term is previewed for
// a match count before the results are purchased.
func ReverseWhois(
	ctx context.Context,
	domainName string,
	apiKey string,
	historicalSearch bool,
	fetchOptions ...fetch_config.Option,
) ([]*domainTypes.Domain, error) {
	if domainName == "" {
		return nil, nil
	}

	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("whoisxml api key"))
	}

	searchType := whoisxml.SearchTypeCurrent
	if historicalSearch {
		searchType = whoisxml.SearchTypeHistoric
	}

	// Both the domain itself and any subdomain of it, as a registrant address
	// at either is the same party.
	termStrings := []string{fmt.Sprintf("*@%s", domainName), fmt.Sprintf("*@*.%s", domainName)}

	var domains []*domainTypes.Domain
	var domainsMutex sync.Mutex

	errGroup, errGroupCtx := errgroup.WithContext(ctx)

	for _, term := range termStrings {
		errGroup.Go(
			func() error {
				requestData := &whoisXmlTypes.ReverseWhoisRequest{
					ApiKey: apiKey,
					AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
						{Field: "Email", Term: term, Exclude: false},
					},
					SearchType: searchType,
					Mode:       whoisxml.ModePreview,
				}

				previewResponse, err := whoisxml.QueryReverseWhois(errGroupCtx, requestData, fetchOptions...)
				if err != nil {
					return altshiftErrors.New(
						fmt.Errorf("whoisxml query reverse whois (preview): %w", err),
						term, searchType,
					)
				}
				if previewResponse == nil {
					return altshiftErrors.NewWithTrace(nil_error.New("reverse whois preview response"), term)
				}

				if previewResponse.DomainsCount == 0 {
					return nil
				}

				// A purchase request differs from the preview only in its mode,
				// but the preview must not be mutated: it is the request the
				// other term's goroutine is not sharing, and reusing the struct
				// keeps the search terms identical between the two calls.
				purchaseRequestData := *requestData
				purchaseRequestData.Mode = whoisxml.ModePurchase

				purchaseResponse, err := whoisxml.QueryReverseWhois(errGroupCtx, &purchaseRequestData, fetchOptions...)
				if err != nil {
					return altshiftErrors.New(
						fmt.Errorf("whoisxml query reverse whois (purchase): %w", err),
						term, searchType,
					)
				}
				if purchaseResponse == nil {
					return altshiftErrors.NewWithTrace(nil_error.New("reverse whois purchase response"), term)
				}

				termDomains := make([]*domainTypes.Domain, 0, len(purchaseResponse.DomainsList))
				for _, domainListName := range purchaseResponse.DomainsList {
					if domainListName == domainName {
						continue
					}

					termDomains = append(
						termDomains,
						&domainTypes.Domain{
							Domain: domainListName,
							Metadata: &domainTypes.Metadata{
								Inferences: []*inference.Inference{
									{
										Confidence: reverseWhoisConfidence,
										Chain:      []string{"Reverse Whois", term},
									},
								},
							},
						},
					)
				}

				if len(termDomains) > 0 {
					domainsMutex.Lock()
					domains = append(domains, termDomains...)
					domainsMutex.Unlock()
				}

				return nil
			},
		)
	}

	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("err group wait: %w", err)
	}

	return domains, nil
}

// getDomainIpv4Addresses resolves a domain to its IPv4 addresses through the
// run's own resolver, so discovery and the security assessment that follows see
// the same DNS.
func getDomainIpv4Addresses(
	ctx context.Context,
	domainName string,
	dnsClient *dnsUtilsClient.Client,
) ([]net.IP, error) {
	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	records, err := dnsClient.GetDnsAnswers(ctx, domainName, dns.TypeA)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("get dns answers: %w", err), domainName)
	}

	var ipv4Addresses []net.IP
	for _, record := range records {
		aRecord, ok := record.(*dns.A)
		if !ok || aRecord == nil {
			continue
		}

		if ipv4 := aRecord.A.To4(); ipv4 != nil {
			ipv4Addresses = append(ipv4Addresses, ipv4)
		}
	}

	return ipv4Addresses, nil
}

// ReverseIpDomain finds the registered domains co-hosted with the given domain.
func ReverseIpDomain(
	ctx context.Context,
	domainName string,
	apiKey string,
	dnsClient *dnsUtilsClient.Client,
	fetchOptions ...fetch_config.Option,
) ([]*domainTypes.Domain, error) {
	if domainName == "" {
		return nil, nil
	}

	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("hackertarget api key"))
	}

	// HackerTarget's reverse IP lookup is IPv4-only.
	ipv4Addresses, err := getDomainIpv4Addresses(ctx, domainName, dnsClient)
	if err != nil {
		return nil, fmt.Errorf("get domain ipv4 addresses: %w", err)
	}
	if len(ipv4Addresses) == 0 {
		return nil, nil
	}

	var reverseIpDomains []*domainTypes.Domain

	for _, ipv4Address := range ipv4Addresses {
		reverseIpDomainNames, err := hackertarget.QueryReverseIp(ctx, ipv4Address, apiKey, fetchOptions...)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("hackertarget query reverse ip: %w", err), ipv4Address)
		}

		for _, registeredDomainName := range extractRegisteredDomainNames(reverseIpDomainNames) {
			if registeredDomainName == domainName {
				continue
			}

			if _, ok := excludedRegisteredDomains[registeredDomainName]; ok {
				continue
			}

			reverseIpDomains = append(
				reverseIpDomains,
				&domainTypes.Domain{
					Domain: registeredDomainName,
					Metadata: &domainTypes.Metadata{
						Inferences: []*inference.Inference{
							{
								Confidence: reverseIpConfidence,
								Chain:      []string{"Reverse IP address", ipv4Address.String()},
							},
						},
					},
				},
			)
		}
	}

	return reverseIpDomains, nil
}
