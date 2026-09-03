package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// FilterDomainNamesActive keeps the domains that resolve.
//
// A lookup that errors keeps the domain rather than dropping it: discovery
// exists to widen the set of domains to look at, and a resolver hiccup is a
// worse reason to lose one than a positive answer is to keep it.
func FilterDomainNamesActive(
	ctx context.Context,
	domains []*domainTypes.Domain,
	dnsClient *dnsUtilsClient.Client,
) ([]*domainTypes.Domain, error) {
	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	if len(domains) == 0 {
		return nil, nil
	}

	var activeDomains []*domainTypes.Domain
	var activeDomainsMutex sync.Mutex
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

			exists, err := dnsClient.DomainExists(ctxWithDnsContext, domainName)
			if err != nil {
				slog.WarnContext(
					altshiftContext.WithError(
						ctxWithDnsContext,
						altshiftErrors.New(
							fmt.Errorf("domain exists: %w", err),
							domainName, dnsClient,
						),
					),
					"An error occurred when checking whether a domain resolves. Keeping it as a fallback.",
				)
			} else if !exists {
				return
			}

			activeDomainsMutex.Lock()
			activeDomains = append(activeDomains, domain)
			activeDomainsMutex.Unlock()
		}()
	}

	waitGroup.Wait()

	return activeDomains, nil
}

// FilterDomainsValid drops the domains that do not parse. A source can return
// junk, and the caller should not have to sort it out.
func FilterDomainsValid(ctx context.Context, domains []*domainTypes.Domain) []*domainTypes.Domain {
	var validDomains []*domainTypes.Domain

	for _, domain := range domains {
		if err := domain.Validate(); err != nil {
			ctxWithError := altshiftContext.WithError(
				ctx,
				altshiftErrors.New(fmt.Errorf("domain validate: %w", err), domain),
			)

			if errors.Is(err, altshiftErrors.ErrValidationError) {
				slog.WarnContext(ctxWithError, "A domain did not pass validation. Skipping.")
			} else {
				slog.ErrorContext(ctxWithError, "An error occurred when validating a domain. Skipping.")
			}

			continue
		}

		validDomains = append(validDomains, domain)
	}

	return validDomains
}
