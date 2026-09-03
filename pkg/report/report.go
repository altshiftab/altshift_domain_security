// Package report flattens a domain's assessment into a list of findings.
//
// A Metadata carries its problems three levels down, split across the SPF walk,
// the DKIM selector sweep and the DMARC record, and says nothing about which
// domain it describes. Anything presenting an assessment - a terminal, a
// ticket, a dashboard - wants the opposite: one ranked list, each entry naming
// where it came from.
package report

import (
	"cmp"
	"slices"

	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
)

// The mechanism a finding came from.
const (
	SourceSpf    = "spf"
	SourceDkim   = "dkim"
	SourceDmarc  = "dmarc"
	SourceDnssec = "dnssec"
	SourceWhois  = "whois"
)

// RuleIdDnssecNotCovered is this package's own rule, not one of the analyses'.
//
// DNSSEC coverage arrives as a bare boolean rather than through a rule, because
// there is nothing to analyse: the zone is either signed or it is not. A report
// that left it in a header field would count a domain with no DNSSEC as having
// no problems, which is the wrong answer to "what is wrong with this domain".
const RuleIdDnssecNotCovered = "dnssec_not_covered"

// RuleIdNoDomainLocks is this package's second own rule, for the same reason as
// the first: the locks arrive as booleans, not through an analysis.
//
// Most domains carry the registrar's client* locks, so holding none at all -
// from either the registry or the registrar - is unusual rather than routine,
// and means a transfer or deletion faces no standing objection.
const RuleIdNoDomainLocks = "no_domain_locks"

func noDomainLocksProblem() *problemTypes.Problem {
	return &problemTypes.Problem{
		Id:    RuleIdNoDomainLocks,
		Title: "The domain holds no transfer, update or delete lock",
		Description: "Neither the registry nor the registrar has set a status code objecting to " +
			"the domain being transferred, altered or deleted, so a request to do any of those " +
			"meets no standing obstacle.",
		Severity: problemTypes.SeverityLow,
	}
}

// dnssecNotCoveredProblem is what an unsigned zone is reported as. It is low
// rather than high: an unsigned zone is the norm on most of the internet, and
// it weakens a domain rather than exposing it outright.
func dnssecNotCoveredProblem() *problemTypes.Problem {
	return &problemTypes.Problem{
		Id:    RuleIdDnssecNotCovered,
		Title: "The zone is not signed with DNSSEC",
		Description: "Without DNSSEC, a resolver cannot tell the domain's real answers from " +
			"forged ones, so every other record this report relies on can be spoofed in transit.",
		Severity: problemTypes.SeverityLow,
	}
}

// Finding is one problem, with enough context to act on it: which domain, which
// mechanism, and - where the mechanism has more than one place to look - which
// record within it.
type Finding struct {
	Domain  string                `json:"domain"`
	Source  string                `json:"source"`
	Problem *problemTypes.Problem `json:"problem"`

	// Selector names the DKIM selector the record was published at. Empty for
	// anything else.
	Selector string `json:"selector,omitzero"`
	// DomainTrace is the path of include: and redirect= terms followed to reach
	// the SPF record. Empty for anything else. Its last element is the domain
	// whose record actually carries the problem, which is not necessarily the
	// domain being assessed.
	DomainTrace []string `json:"domain_trace,omitzero"`
}

// severityRank orders severities from most to least serious. An unrecognised
// severity sorts last rather than being dropped: an unranked finding is still a
// finding.
func severityRank(severity string) int {
	switch severity {
	case problemTypes.SeverityHigh:
		return 0
	case problemTypes.SeverityMedium:
		return 1
	case problemTypes.SeverityLow:
		return 2
	case problemTypes.SeverityInfo:
		return 3
	default:
		return 4
	}
}

// AtLeast reports whether the severity is at least as serious as the floor.
// An unrecognised floor admits everything, so a caller cannot silently filter
// its whole report away by misspelling one.
func AtLeast(severity string, floor string) bool {
	if severityRank(floor) == 4 {
		return true
	}

	return severityRank(severity) <= severityRank(floor)
}

// Collect flattens one domain's assessment. The result is sorted most serious
// first, then by source and rule, so two runs over the same data read the same.
func Collect(domainName string, metadata *domainTypes.Metadata) []*Finding {
	if metadata == nil {
		return nil
	}

	var findings []*Finding

	if spfData := metadata.SpfData; spfData != nil {
		for _, tracedRecord := range spfData.RecordCollection {
			if tracedRecord == nil {
				continue
			}

			for _, problem := range tracedRecord.Problems {
				if problem == nil {
					continue
				}

				findings = append(
					findings,
					&Finding{
						Domain:      domainName,
						Source:      SourceSpf,
						Problem:     problem,
						DomainTrace: tracedRecord.DomainTrace,
					},
				)
			}
		}
	}

	if dmarcData := metadata.DmarcData; dmarcData != nil {
		for _, problem := range dmarcData.Problems {
			if problem == nil {
				continue
			}

			findings = append(
				findings,
				&Finding{Domain: domainName, Source: SourceDmarc, Problem: problem},
			)
		}
	}

	if dnssecData := metadata.DnssecData; dnssecData != nil {
		// A nil Covered means the question was never put - a subdomain has no
		// delegation of its own - which is not the same as an unsigned zone.
		if covered := dnssecData.Covered; covered != nil && !*covered {
			findings = append(
				findings,
				&Finding{Domain: domainName, Source: SourceDnssec, Problem: dnssecNotCoveredProblem()},
			)
		}
	}

	// A WHOIS query that failed leaves every lock unset, which is not the same
	// as a domain holding none; only a domain whose statuses were actually read
	// can be said to hold nothing.
	if whoisData := metadata.WhoisData; whoisData.AnyLockKnown() && !whoisData.AnyLockHeld() {
		findings = append(
			findings,
			&Finding{Domain: domainName, Source: SourceWhois, Problem: noDomainLocksProblem()},
		)
	}

	if dkimData := metadata.DkimData; dkimData != nil {
		for _, recordWithProblems := range dkimData.RecordCollection {
			if recordWithProblems == nil {
				continue
			}

			var selector string
			if record := recordWithProblems.Record; record != nil {
				selector = record.Selector
			}

			for _, problem := range recordWithProblems.Problems {
				if problem == nil {
					continue
				}

				findings = append(
					findings,
					&Finding{
						Domain:   domainName,
						Source:   SourceDkim,
						Problem:  problem,
						Selector: selector,
					},
				)
			}
		}
	}

	Sort(findings)

	return findings
}

// Sort orders findings most serious first, breaking ties so the output is
// stable across runs.
func Sort(findings []*Finding) {
	slices.SortStableFunc(findings, func(a *Finding, b *Finding) int {
		if a == nil || b == nil {
			return cmp.Compare(boolToInt(a == nil), boolToInt(b == nil))
		}

		var aSeverity, aId string
		if a.Problem != nil {
			aSeverity, aId = a.Problem.Severity, a.Problem.Id
		}

		var bSeverity, bId string
		if b.Problem != nil {
			bSeverity, bId = b.Problem.Severity, b.Problem.Id
		}

		return cmp.Or(
			cmp.Compare(severityRank(aSeverity), severityRank(bSeverity)),
			cmp.Compare(a.Domain, b.Domain),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(aId, bId),
			cmp.Compare(a.Selector, b.Selector),
		)
	})
}

func boolToInt(value bool) int {
	if value {
		return 1
	}

	return 0
}

// Counts tallies findings by severity, for a closing line that says how bad the
// result is without the reader counting rows.
func Counts(findings []*Finding) map[string]int {
	counts := make(map[string]int)

	for _, finding := range findings {
		if finding == nil || finding.Problem == nil {
			continue
		}

		counts[finding.Problem.Severity]++
	}

	return counts
}
