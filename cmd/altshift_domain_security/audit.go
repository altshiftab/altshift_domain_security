package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/altshift_domain_security/domain_security"
	"github.com/altshiftab/altshift_domain_security/domain_security/domain_security_config"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery/discovery_config"
	"github.com/altshiftab/altshift_domain_security/pkg/report"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// defaultAuditConcurrency bounds how many domains are assessed at once. Each
// assessment is a recursive SPF walk plus a DKIM selector sweep, so a wide
// discovery result would otherwise put hundreds of queries in flight at once.
const defaultAuditConcurrency = 5

// auditConfig is what an audit run needs, gathered from the command line.
type auditConfig struct {
	Domain             string
	DnsClient          *dnsUtilsClient.Client
	WhoisXmlApiKey     string
	HackerTargetApiKey string
	Historical         bool
	DkimSelectors      []string
	AllowedNetworks    []*net.IPNet
	Concurrency        int
	MinSeverity        string
}

// domainReport is one domain's result. The coverage fields are pointers because
// "not established" is a distinct answer from "no": a subdomain has no DNSSEC
// delegation or registration of its own, so neither is looked up for one.
type domainReport struct {
	Domain        string            `json:"domain"`
	DnssecCovered *bool             `json:"dnssec_covered,omitzero"`
	DmarcCovered  *bool             `json:"dmarc_covered,omitzero"`
	RegistryLocks []string          `json:"registry_locks,omitzero"`
	ClientLocks   []string          `json:"client_locks,omitzero"`
	Findings      []*report.Finding `json:"findings"`
	// Error records an assessment that failed. The domain is still listed, so a
	// reader can tell "nothing wrong" from "never looked".
	Error string `json:"error,omitzero"`
}

type auditReport struct {
	Seed         string          `json:"seed"`
	Domains      []*domainReport `json:"domains"`
	Counts       map[string]int  `json:"counts"`
	DomainCount  int             `json:"domain_count"`
	FindingCount int             `json:"finding_count"`
}

// auditDomains settles which domains the run covers: the seed, plus whatever
// discovery attributes to the same owner when a source key was supplied. The
// seed is always included - discovery deliberately excludes it, and an audit
// that skipped the domain it was pointed at would be surprising.
func auditDomains(ctx context.Context, config *auditConfig) ([]string, error) {
	if config == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("config"))
	}

	domainNames := map[string]struct{}{config.Domain: {}}

	if config.WhoisXmlApiKey != "" || config.HackerTargetApiKey != "" {
		discovered, err := discovery.GetValidatedActiveDomainsWithMetadata(
			ctx,
			config.Domain,
			discovery_config.WithDnsClient(config.DnsClient),
			discovery_config.WithWhoisXmlApiKey(config.WhoisXmlApiKey),
			discovery_config.WithHackerTargetApiKey(config.HackerTargetApiKey),
			discovery_config.WithHistoricalReverseWhois(config.Historical),
		)
		if err != nil {
			return nil, fmt.Errorf("get validated active domains with metadata: %w", err)
		}

		for _, domain := range discovered {
			if domain != nil && domain.Domain != "" {
				domainNames[domain.Domain] = struct{}{}
			}
		}
	}

	names := slices.Collect(maps.Keys(domainNames))
	slices.Sort(names)

	return names, nil
}

// runAudit discovers, assesses and flattens, in that order.
func runAudit(ctx context.Context, config *auditConfig) (*auditReport, error) {
	if config == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("config"))
	}

	domainNames, err := auditDomains(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("audit domains: %w", err)
	}

	securityOptions := []domain_security_config.Option{
		domain_security_config.WithDnsClient(config.DnsClient),
		domain_security_config.WithAllowedNetworks(config.AllowedNetworks...),
	}
	if len(config.DkimSelectors) > 0 {
		securityOptions = append(securityOptions, domain_security_config.WithDkimSelectors(config.DkimSelectors...))
	}

	concurrency := config.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	// An assessment is many DNS lookups, so the domains are assessed a few at a
	// time rather than all at once - a wide discovery result would otherwise
	// put hundreds of queries in flight.
	semaphore := make(chan struct{}, concurrency)

	domainReports := make([]*domainReport, len(domainNames))

	var waitGroup sync.WaitGroup
	for i, domainName := range domainNames {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				domainReports[i] = &domainReport{Domain: domainName, Error: ctx.Err().Error()}
				return
			}

			domainReports[i] = assessOne(ctx, domainName, config.MinSeverity, securityOptions)
		}()
	}

	waitGroup.Wait()

	auditResult := &auditReport{
		Seed:        config.Domain,
		Domains:     domainReports,
		DomainCount: len(domainReports),
	}

	var allFindings []*report.Finding
	for _, domainResult := range domainReports {
		if domainResult != nil {
			allFindings = append(allFindings, domainResult.Findings...)
		}
	}

	auditResult.Counts = report.Counts(allFindings)
	auditResult.FindingCount = len(allFindings)

	return auditResult, nil
}

// assessOne assesses a single domain. A failure is recorded against the domain
// rather than failing the run: one unreachable domain should not cost the
// report on every other.
func assessOne(
	ctx context.Context,
	domainName string,
	minSeverity string,
	securityOptions []domain_security_config.Option,
) *domainReport {
	domainResult := &domainReport{Domain: domainName, Findings: []*report.Finding{}}

	metadata, err := domain_security.GetDomainSecurity(ctx, domainName, securityOptions...)
	if err != nil {
		wrapped := altshiftErrors.New(fmt.Errorf("get domain security: %w", err), domainName)

		slog.ErrorContext(
			altshiftContext.WithError(ctx, wrapped),
			"An error occurred when assessing a domain. Recording it against the domain.",
		)

		domainResult.Error = err.Error()

		return domainResult
	}
	if metadata == nil {
		return domainResult
	}

	if dnssecData := metadata.DnssecData; dnssecData != nil {
		domainResult.DnssecCovered = dnssecData.Covered
	}
	if dmarcData := metadata.DmarcData; dmarcData != nil {
		domainResult.DmarcCovered = dmarcData.IsCovered
	}
	domainResult.RegistryLocks, domainResult.ClientLocks = domainLocks(metadata.WhoisData)

	for _, finding := range report.Collect(domainName, metadata) {
		if finding == nil || finding.Problem == nil {
			continue
		}
		if !report.AtLeast(finding.Problem.Severity, minSeverity) {
			continue
		}

		domainResult.Findings = append(domainResult.Findings, finding)
	}

	return domainResult
}

// lock pairs a lock's name with whether the party in question holds it. Held is
// a pointer because unset means the status was never read, which is not the
// same as the lock being absent.
type lock struct {
	Name string
	Held *bool
}

// domainLocks names the locks each party holds, kept apart because they mean
// different things: the registry's server* locks are usually a paid service,
// while the registrar's client* locks are the ordinary protection most domains
// have.
func domainLocks(whoisData *domainTypes.WhoisData) ([]string, []string) {
	if whoisData == nil {
		return nil, nil
	}

	held := func(locks []*lock) []string {
		var names []string
		for _, entry := range locks {
			if entry != nil && entry.Held != nil && *entry.Held {
				names = append(names, entry.Name)
			}
		}

		return names
	}

	registry := held([]*lock{
		{Name: "transfer", Held: whoisData.ServerTransferProhibited},
		{Name: "update", Held: whoisData.ServerUpdateProhibited},
		{Name: "delete", Held: whoisData.ServerDeleteProhibited},
	})
	client := held([]*lock{
		{Name: "transfer", Held: whoisData.ClientTransferProhibited},
		{Name: "update", Held: whoisData.ClientUpdateProhibited},
		{Name: "delete", Held: whoisData.ClientDeleteProhibited},
	})

	return registry, client
}

// formatLocks renders both parties' locks, naming which is which so a reader
// can tell a paid registry lock from an ordinary registrar one.
func formatLocks(registry []string, client []string) string {
	var parts []string
	if len(registry) > 0 {
		parts = append(parts, "registry:"+strings.Join(registry, ","))
	}
	if len(client) > 0 {
		parts = append(parts, "client:"+strings.Join(client, ","))
	}

	if len(parts) == 0 {
		return "none"
	}

	return strings.Join(parts, " ")
}

// coverage renders a tri-state: yes, no, or never looked.
func coverage(value *bool) string {
	if value == nil {
		return "-"
	}
	if *value {
		return "yes"
	}

	return "no"
}

// writeAuditText renders the report for a person reading a terminal.
func writeAuditText(writer io.Writer, auditResult *auditReport) error {
	if auditResult == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("audit result"))
	}

	var builder strings.Builder

	for _, domainResult := range auditResult.Domains {
		if domainResult == nil {
			continue
		}

		builder.WriteString(domainResult.Domain)
		builder.WriteString("\n")

		if domainResult.Error != "" {
			builder.WriteString("  ! not assessed: " + domainResult.Error + "\n\n")
			continue
		}

		fmt.Fprintf(
			&builder,
			"  dnssec %s · dmarc %s · locks %s\n",
			coverage(domainResult.DnssecCovered),
			coverage(domainResult.DmarcCovered),
			formatLocks(domainResult.RegistryLocks, domainResult.ClientLocks),
		)

		if len(domainResult.Findings) == 0 {
			builder.WriteString("  no problems\n\n")
			continue
		}

		for _, finding := range domainResult.Findings {
			if finding == nil || finding.Problem == nil {
				continue
			}

			line := fmt.Sprintf(
				"  %-6s %-6s %-40s %s",
				strings.ToUpper(finding.Problem.Severity),
				finding.Source,
				finding.Problem.Id,
				findingContext(finding),
			)

			// The columns are padded, so a finding with nothing in the last one
			// would otherwise leave the padding hanging off the end of the line.
			builder.WriteString(strings.TrimRight(line, " "))
			builder.WriteString("\n")
		}

		builder.WriteString("\n")
	}

	fmt.Fprintf(
		&builder,
		"%d domain(s), %d problem(s)%s\n",
		auditResult.DomainCount,
		auditResult.FindingCount,
		formatCounts(auditResult.Counts),
	)

	if _, err := io.WriteString(writer, builder.String()); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("write string: %w", err))
	}

	return nil
}

// findingContext is the trailing column: whatever locates the problem within
// the domain, then the problem's own details.
//
// For SPF the trace matters most - a problem reported against a domain often
// lives in a record its includes reached, and naming that record is the
// difference between an actionable finding and a confusing one.
func findingContext(finding *report.Finding) string {
	if finding == nil || finding.Problem == nil {
		return ""
	}

	var parts []string

	switch {
	case finding.Selector != "":
		parts = append(parts, "selector="+finding.Selector)
	case len(finding.DomainTrace) > 1:
		parts = append(parts, "via "+strings.Join(finding.DomainTrace, " > "))
	}

	if details := finding.Problem.Details; details != "" {
		parts = append(parts, details)
	}

	return strings.Join(parts, "  ")
}

// formatCounts renders the severity tally, most serious first, omitting the
// severities that did not occur.
func formatCounts(counts map[string]int) string {
	var parts []string
	for _, severity := range []string{
		problemTypes.SeverityHigh,
		problemTypes.SeverityMedium,
		problemTypes.SeverityLow,
		problemTypes.SeverityInfo,
	} {
		if count := counts[severity]; count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count, severity))
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return " (" + strings.Join(parts, ", ") + ")"
}
