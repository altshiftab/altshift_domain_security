// Package domain_security assesses what a domain's DNS says about how well it
// is defended against being impersonated: its SPF, DKIM and DMARC policies, and
// whether DNSSEC and registrar locks are in place.
package domain_security

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/Motmedel/whois/pkg/whois"
	"github.com/altshiftab/altshift_domain_security/domain_security/domain_security_config"
	"github.com/altshiftab/altshift_domain_security/pkg/dkim"
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc"
	dmarcRuleId "github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/spf"
	spfRuleId "github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	dkimTypes "github.com/altshiftab/altshift_domain_security/types/dkim"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftDmarc "github.com/altshiftab/utils_go/pkg/dns/dmarc"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
	altshiftUtils "github.com/altshiftab/utils_go/pkg/utils"
	"github.com/yl2chen/cidranger"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// dkimLookupConcurrency bounds the selector guesses in flight at once. The
// selectors are guesses, most of which miss, so the sweep is throttled to keep
// one assessment from flooding a resolver.
const dkimLookupConcurrency = 10

// observedAt reads the time the DNS exchanges on this context were made.
func observedAt(ctx context.Context) (time.Time, error) {
	dnsContext, err := altshiftUtils.GetNonZeroContextValue[*dnsUtilsTypes.DnsContext](ctx, dnsUtilsContext.DnsContextKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("get non zero context value: %w", err)
	}

	lastObserved := dnsContext.Time
	if lastObserved == nil {
		return time.Time{}, altshiftErrors.NewWithTrace(nil_error.New("last observed"))
	}

	return *lastObserved, nil
}

// newNetworkRanger indexes the acknowledged networks for containment checks.
func newNetworkRanger(networks []*net.IPNet) (cidranger.Ranger, error) {
	ranger := cidranger.NewPCTrieRanger()

	for _, network := range networks {
		if network == nil {
			continue
		}

		entry := cidranger.NewBasicRangerEntry(*network)
		if err := ranger.Insert(entry); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("cidr ranger insert: %w", err), entry)
		}
	}

	return ranger, nil
}

// gatherDnssec reports whether the zone is signed, or nil when that could not
// be established.
//
// A failure here is not allowed to cost the rest of the assessment. Resolvers
// differ in what they will answer a DNSSEC probe with - a stub resolver may
// refuse the query outright while answering everything else - and losing the
// SPF, DKIM and DMARC findings over it would be a poor trade. Nil reads as "not
// established", which is distinct from a zone that is genuinely unsigned.
func gatherDnssec(
	ctx context.Context,
	domain string,
	dnsClient *dnsUtilsClient.Client,
) *domainTypes.DnssecData {
	ctxWithDns := dnsUtilsContext.WithDnsContext(ctx)

	supportsDnssec, err := dnsClient.SupportsDnssec(ctxWithDns, domain)
	if err != nil {
		slog.WarnContext(
			altshiftContext.WithError(
				ctxWithDns,
				altshiftErrors.New(fmt.Errorf("supports dnssec: %w", err), domain, dnsClient),
			),
			"An error occurred when checking for DNSSEC. Continuing without DNSSEC data.",
		)

		return nil
	}

	lastObserved, err := observedAt(ctxWithDns)
	if err != nil {
		slog.WarnContext(
			altshiftContext.WithError(ctxWithDns, altshiftErrors.New(fmt.Errorf("observed at: %w", err))),
			"The DNSSEC observation time could not be established. Continuing without DNSSEC data.",
		)

		return nil
	}

	return &domainTypes.DnssecData{
		Observation: domainTypes.NewObservation(lastObserved),
		Covered:     &supportsDnssec,
	}
}

// GetDomainDmarcSecurity reports the domain's DMARC record and what is wrong
// with it, and whether DMARC covers the domain at all.
//
// Coverage is not the same as having a record: a subdomain with no record of
// its own is still covered if its organizational domain carries a valid one,
// which is why a missing record sends this looking one level up.
func GetDomainDmarcSecurity(
	ctx context.Context,
	domain string,
	dnsClient *dnsUtilsClient.Client,
) (*altshiftDmarc.Record, []*problemTypes.Problem, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}

	if dnsClient == nil {
		return nil, nil, false, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	if domain == "" {
		return nil, nil, false, nil
	}

	record, err := dnsClient.GetDmarcRecord(ctx, domain)
	if err != nil {
		if errors.Is(err, dnsUtilsErrors.ErrMultipleRecords) {
			problem := dmarc.MakeRuleIdProblem(dmarcRuleId.MultipleRecords)

			if multipleRecordsError, ok := errors.AsType[*dnsUtilsErrors.MultipleRecordsError](err); ok {
				var quotedTxtRecords []string
				for _, multipleRecord := range multipleRecordsError.Records {
					quotedTxtRecords = append(quotedTxtRecords, fmt.Sprintf("%q", multipleRecord))
				}
				problem.Details = fmt.Sprintf("Encountered records: %s", strings.Join(quotedTxtRecords, ", "))
			}

			return nil, []*problemTypes.Problem{problem}, true, nil
		}

		if altshiftErrors.IsAny(err, altshiftErrors.ErrSyntaxError, altshiftErrors.ErrSemanticError) {
			// A record that fails to parse is still returned, raw, so the
			// problem can quote what was actually published.
			if record == nil {
				return nil, nil, false, altshiftErrors.NewWithTrace(nil_error.New("record"))
			}

			problem := dmarc.MakeRuleIdProblem(dmarcRuleId.SyntaxError)
			problem.Details = fmt.Sprintf("Encountered record: %s", record.Raw)

			return record, []*problemTypes.Problem{problem}, false, nil
		}

		return record, nil, false, altshiftErrors.New(fmt.Errorf("get dmarc record: %w", err), domain, dnsClient)
	}

	if record != nil {
		problems, err := dmarc.AnalyzeRecord(ctx, record, dnsClient)
		if err != nil {
			return record, nil, false, altshiftErrors.New(
				fmt.Errorf("analyze record: %w", err),
				record, dnsClient,
			)
		}

		return record, problems, true, nil
	}

	// No record on the domain itself. Whether that matters depends on whether
	// the organizational domain covers it.

	missingRecordProblem := dmarc.MakeRuleIdProblem(dmarcRuleId.MissingRecord)
	if missingRecordProblem == nil {
		return nil, nil, false, altshiftErrors.NewWithTrace(nil_error.New("missing record problem"))
	}
	problems := []*problemTypes.Problem{missingRecordProblem}

	parts := domain_parts.New(domain)
	if parts == nil {
		return nil, nil, false, altshiftErrors.NewWithTrace(nil_error.New("domain parts"), domain)
	}

	organizationalDomain := parts.RegisteredDomain

	if domain == organizationalDomain {
		// This is the organizational domain, so there is nothing above it to
		// fall back on: the domain is uncovered.
		missingRecordProblem.Severity = problemTypes.SeverityHigh
		return nil, problems, false, nil
	}

	organizationalDomainRecord, err := dnsClient.GetDmarcRecord(ctx, organizationalDomain)
	if err != nil {
		// A malformed or duplicated record up the tree is handled below, by
		// judging the record itself; anything else is a real failure.
		if !altshiftErrors.IsAny(
			err,
			altshiftErrors.ErrSyntaxError,
			altshiftErrors.ErrSemanticError,
			dnsUtilsErrors.ErrMultipleRecords,
		) {
			return nil, nil, false, altshiftErrors.New(
				fmt.Errorf("get dmarc record (organizational domain): %w", err),
				organizationalDomain,
			)
		}
	}
	if organizationalDomainRecord == nil {
		missingRecordProblem.Severity = problemTypes.SeverityHigh
		return nil, problems, false, nil
	}

	organizationalDomainProblems, err := dmarc.AnalyzeRecord(ctx, organizationalDomainRecord, dnsClient)
	if err != nil {
		return nil, nil, false, altshiftErrors.New(
			fmt.Errorf("analyze record (organizational domain): %w", err),
			organizationalDomainRecord, dnsClient,
		)
	}

	// The subdomain is covered only if the record it is falling back on parses.
	for _, problem := range organizationalDomainProblems {
		if problem.Id == dmarcRuleId.SyntaxError {
			missingRecordProblem.Severity = problemTypes.SeverityHigh
			return nil, problems, false, nil
		}
	}

	return nil, problems, true, nil
}

// GetDomainSpfSecurity walks the domain's SPF record and everything its
// include: and redirect= terms reach, reporting each record it passes through.
func GetDomainSpfSecurity(
	ctx context.Context,
	domain string,
	dnsClient *dnsUtilsClient.Client,
) ([]*spfTypes.TracedRecordWithProblems, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	if domain == "" {
		return nil, nil
	}

	tracedRecordWithProblems, err := spf.RecursiveAnalyzeRecord(ctx, domain, dnsClient)
	if err != nil {
		return nil, fmt.Errorf("recursive analyze record: %w", err)
	}

	return tracedRecordWithProblems, nil
}

// GetDomainSecurity gathers everything the DNS and the registry say about how
// well the domain is defended.
//
// The blocks are gathered concurrently and each carries its own observation
// time, because they do not complete together. DNSSEC and WHOIS are only asked
// about for a registered domain: a subdomain has neither of its own.
func GetDomainSecurity(
	ctx context.Context,
	domain string,
	options ...domain_security_config.Option,
) (*domainTypes.Metadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if domain == "" {
		return nil, nil
	}

	config := domain_security_config.New(options...)

	dnsClient := config.DnsClient
	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	parts := domain_parts.New(domain)
	if parts == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("domain parts"), domain)
	}

	allowedNetworkRanger, err := newNetworkRanger(config.AllowedNetworks)
	if err != nil {
		return nil, fmt.Errorf("new network ranger: %w", err)
	}

	domainMetadata := &domainTypes.Metadata{}

	errGroup, errGroupCtx := errgroup.WithContext(ctx)

	if parts.Subdomain == "" {
		errGroup.Go(
			func() error {
				domainMetadata.DnssecData = gatherDnssec(errGroupCtx, domain, dnsClient)

				return nil
			},
		)

		errGroup.Go(
			func() error {
				// WHOIS is the one source here that is neither authenticated
				// nor reliably available, so a failure downgrades the answer
				// rather than failing the assessment.
				lastObserved := time.Now()

				whoisData, err := whois.Query(errGroupCtx, domain)
				if err != nil {
					slog.WarnContext(
						altshiftContext.WithError(
							errGroupCtx,
							altshiftErrors.New(fmt.Errorf("whois query: %w", err), domain),
						),
						"An error occurred when querying WHOIS. Continuing without WHOIS data.",
					)

					return nil
				}

				domainMetadata.WhoisData = &domainTypes.WhoisData{
					Observation: domainTypes.NewObservation(lastObserved),
				}

				if len(whoisData) == 0 {
					return nil
				}

				parsedWhoisData, err := whois.Parse(whoisData)
				if err != nil {
					slog.WarnContext(
						altshiftContext.WithError(
							errGroupCtx,
							altshiftErrors.New(fmt.Errorf("whois parse: %w", err), whoisData),
						),
						"An error occurred when parsing WHOIS data. Continuing with observed WHOIS metadata.",
					)

					return nil
				}

				// The locks are reported as false rather than left unset once
				// the record has been read: "the registry does not hold this
				// lock" is an answer, and distinct from not having looked.
				var serverTransferProhibited bool
				var serverUpdateProhibited bool
				var serverDeleteProhibited bool
				var clientTransferProhibited bool
				var clientUpdateProhibited bool
				var clientDeleteProhibited bool

				if parsedDomain := parsedWhoisData.Domain; parsedDomain != nil {
					for _, status := range parsedDomain.Status {
						// Registries and registrars are inconsistent about the
						// case they publish these in, and some append the ICANN
						// URL to the code.
						switch {
						case strings.EqualFold(status, "serverTransferProhibited"):
							serverTransferProhibited = true
						case strings.EqualFold(status, "serverUpdateProhibited"):
							serverUpdateProhibited = true
						case strings.EqualFold(status, "serverDeleteProhibited"):
							serverDeleteProhibited = true
						case strings.EqualFold(status, "clientTransferProhibited"):
							clientTransferProhibited = true
						case strings.EqualFold(status, "clientUpdateProhibited"):
							clientUpdateProhibited = true
						case strings.EqualFold(status, "clientDeleteProhibited"):
							clientDeleteProhibited = true
						}
					}
				}

				domainMetadata.WhoisData.ServerTransferProhibited = &serverTransferProhibited
				domainMetadata.WhoisData.ServerUpdateProhibited = &serverUpdateProhibited
				domainMetadata.WhoisData.ServerDeleteProhibited = &serverDeleteProhibited
				domainMetadata.WhoisData.ClientTransferProhibited = &clientTransferProhibited
				domainMetadata.WhoisData.ClientUpdateProhibited = &clientUpdateProhibited
				domainMetadata.WhoisData.ClientDeleteProhibited = &clientDeleteProhibited

				return nil
			},
		)
	}

	errGroup.Go(
		func() error {
			ctxWithDns := dnsUtilsContext.WithDnsContext(errGroupCtx)

			record, problems, isCovered, err := GetDomainDmarcSecurity(ctxWithDns, domain, dnsClient)
			if err != nil {
				return fmt.Errorf("get domain dmarc security: %w", err)
			}

			lastObserved, err := observedAt(ctxWithDns)
			if err != nil {
				return fmt.Errorf("observed at: %w", err)
			}

			domainMetadata.DmarcData = &domainTypes.DmarcData{
				Observation: domainTypes.NewObservation(lastObserved),
				Record:      record,
				Problems:    problems,
				IsCovered:   &isCovered,
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
			ctxWithDns := dnsUtilsContext.WithDnsContext(errGroupCtx)

			tracedRecordWithProblems, err := GetDomainSpfSecurity(ctxWithDns, domain, dnsClient)
			if err != nil {
				return fmt.Errorf("get domain spf security: %w", err)
			}

			if err := addUnacknowledgedNetworkProblems(tracedRecordWithProblems, config.AllowedNetworks, allowedNetworkRanger); err != nil {
				return fmt.Errorf("add unacknowledged network problems: %w", err)
			}

			lastObserved, err := observedAt(ctxWithDns)
			if err != nil {
				return fmt.Errorf("observed at: %w", err)
			}

			domainMetadata.SpfData = &domainTypes.SpfData{
				Observation:      domainTypes.NewObservation(lastObserved),
				RecordCollection: tracedRecordWithProblems,
			}

			return nil
		},
	)

	errGroup.Go(
		func() error {
			recordCollection, err := analyzeDkimSelectors(errGroupCtx, domain, config.DkimSelectors, dnsClient)
			if err != nil {
				return fmt.Errorf("analyze dkim selectors: %w", err)
			}

			// The DKIM sweep is many independent lookups rather than one
			// exchange, so it is stamped when the sweep finished instead of
			// from a DNS context that would only describe the last of them.
			domainMetadata.DkimData = &domainTypes.DkimData{
				Observation:      domainTypes.NewObservation(time.Now()),
				RecordCollection: recordCollection,
			}

			return nil
		},
	)

	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("err group wait: %w", err)
	}

	return domainMetadata, nil
}

// addUnacknowledgedNetworkProblems reports the networks the domain's own SPF
// record authorises that the owner has not acknowledged sending from.
//
// Only the domain's own record is judged, not the records its includes reach:
// a provider's include is exactly how a domain delegates sending to addresses
// it does not own, so holding those to the same list would flag every one.
func addUnacknowledgedNetworkProblems(
	tracedRecordsWithProblems []*spfTypes.TracedRecordWithProblems,
	allowedNetworks []*net.IPNet,
	ranger cidranger.Ranger,
) error {
	if len(tracedRecordsWithProblems) == 0 || len(allowedNetworks) == 0 {
		return nil
	}

	if ranger == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("ranger"))
	}

	base := tracedRecordsWithProblems[0]
	if base == nil {
		return nil
	}

	record := base.Record
	if record == nil {
		return nil
	}

	for _, observedNetwork := range altshiftSpf.ExtractNetworks(record, true) {
		if observedNetwork == nil {
			continue
		}

		observedNetworkIpAddress := observedNetwork.IP

		found, err := ranger.Contains(observedNetworkIpAddress)
		if err != nil {
			return altshiftErrors.NewWithTrace(
				fmt.Errorf("cidr ranger contains: %w", err),
				observedNetworkIpAddress,
			)
		}
		if found {
			continue
		}

		problem := spf.MakeRuleIdProblem(spfRuleId.UnacknowledgedNetwork)
		if problem == nil {
			return altshiftErrors.NewWithTrace(nil_error.New("problem"))
		}
		problem.Details = observedNetwork.String()

		base.Problems = append(base.Problems, problem)
	}

	return nil
}

// analyzeDkimSelectors probes each candidate selector and analyses whatever
// records turn up. A selector that fails to resolve is skipped rather than
// failing the sweep: the selectors are guesses, and most of them miss.
func analyzeDkimSelectors(
	ctx context.Context,
	domain string,
	dkimSelectors []string,
	dnsClient *dnsUtilsClient.Client,
) ([]*dkimTypes.RecordWithProblems, error) {
	if len(dkimSelectors) == 0 {
		return nil, nil
	}

	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	var waitGroup sync.WaitGroup
	weightedSemaphore := semaphore.NewWeighted(int64(dkimLookupConcurrency))

	var recordCollection []*dkimTypes.RecordWithProblems
	var recordCollectionMutex sync.Mutex

	for _, selector := range dkimSelectors {
		if err := weightedSemaphore.Acquire(ctx, 1); err != nil {
			// The context is done; stop starting work and report whatever the
			// already-started lookups produced.
			break
		}

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			defer weightedSemaphore.Release(1)

			ctxWithDns := dnsUtilsContext.WithDnsContext(ctx)

			record, err := dnsClient.GetDkimRecord(ctxWithDns, domain, selector)
			if err != nil {
				slog.WarnContext(
					altshiftContext.WithError(
						ctxWithDns,
						altshiftErrors.New(
							fmt.Errorf("get dkim record: %w", err),
							domain, selector, dnsClient,
						),
					),
					"An error occurred when getting a DKIM record. Skipping the selector.",
				)

				return
			}
			if record == nil {
				return
			}

			problems, err := dkim.Analyze(record)
			if err != nil {
				slog.ErrorContext(
					altshiftContext.WithError(
						ctxWithDns,
						altshiftErrors.New(fmt.Errorf("analyze: %w", err), record),
					),
					"An error occurred when analyzing a DKIM record. Recording it without problems.",
				)
			}

			recordCollectionMutex.Lock()
			recordCollection = append(
				recordCollection,
				&dkimTypes.RecordWithProblems{Record: record, Problems: problems},
			)
			recordCollectionMutex.Unlock()
		}()
	}

	waitGroup.Wait()

	return recordCollection, nil
}
