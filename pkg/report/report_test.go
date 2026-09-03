package report

import (
	"slices"
	"testing"

	dkimTypes "github.com/altshiftab/altshift_domain_security/types/dkim"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	altshiftDkim "github.com/altshiftab/utils_go/pkg/dns/dkim"
)

func problem(id string, severity string) *problemTypes.Problem {
	return &problemTypes.Problem{Id: id, Severity: severity}
}

func ptr[T any](value T) *T {
	return &value
}

func findingIds(findings []*Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding != nil && finding.Problem != nil {
			ids = append(ids, finding.Problem.Id)
		}
	}

	return ids
}

func TestCollect(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		metadata    *domainTypes.Metadata
		expectedIds []string
	}{
		{name: "nil metadata", metadata: nil, expectedIds: []string{}},
		{name: "empty metadata", metadata: &domainTypes.Metadata{}, expectedIds: []string{}},
		{
			name: "spf problems are flattened across every record walked",
			metadata: &domainTypes.Metadata{
				SpfData: &domainTypes.SpfData{
					RecordCollection: []*spfTypes.TracedRecordWithProblems{
						{
							DomainTrace: []string{"example.com"},
							Problems:    []*problemTypes.Problem{problem("insufficient_all", problemTypes.SeverityHigh)},
						},
						{
							DomainTrace: []string{"example.com", "spf.provider.net"},
							Problems:    []*problemTypes.Problem{problem("ptr_used", problemTypes.SeverityInfo)},
						},
					},
				},
			},
			expectedIds: []string{"insufficient_all", "ptr_used"},
		},
		{
			name: "dmarc problems",
			metadata: &domainTypes.Metadata{
				DmarcData: &domainTypes.DmarcData{
					Problems: []*problemTypes.Problem{problem("insufficient_p", problemTypes.SeverityHigh)},
				},
			},
			expectedIds: []string{"insufficient_p"},
		},
		{
			name: "dkim problems carry their selector",
			metadata: &domainTypes.Metadata{
				DkimData: &domainTypes.DkimData{
					RecordCollection: []*dkimTypes.RecordWithProblems{
						{
							Record:   &altshiftDkim.Record{Selector: "selector1"},
							Problems: []*problemTypes.Problem{problem("testing_dkim_flag", problemTypes.SeverityInfo)},
						},
					},
				},
			},
			expectedIds: []string{"testing_dkim_flag"},
		},
		{
			// An unsigned zone arrives as a bare boolean and would otherwise be
			// counted as "no problems".
			name: "an unsigned zone becomes a finding",
			metadata: &domainTypes.Metadata{
				DnssecData: &domainTypes.DnssecData{Covered: ptr(false)},
			},
			expectedIds: []string{RuleIdDnssecNotCovered},
		},
		{
			name: "a signed zone does not",
			metadata: &domainTypes.Metadata{
				DnssecData: &domainTypes.DnssecData{Covered: ptr(true)},
			},
			expectedIds: []string{},
		},
		{
			// A subdomain has no delegation of its own, so the question was
			// never put; that is not the same as an unsigned zone.
			name: "an unasked dnssec question does not",
			metadata: &domainTypes.Metadata{
				DnssecData: &domainTypes.DnssecData{Covered: nil},
			},
			expectedIds: []string{},
		},
		{
			name: "nil entries are skipped rather than panicking",
			metadata: &domainTypes.Metadata{
				SpfData:   &domainTypes.SpfData{RecordCollection: []*spfTypes.TracedRecordWithProblems{nil}},
				DmarcData: &domainTypes.DmarcData{Problems: []*problemTypes.Problem{nil}},
				DkimData:  &domainTypes.DkimData{RecordCollection: []*dkimTypes.RecordWithProblems{nil}},
			},
			expectedIds: []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			findings := Collect("example.com", testCase.metadata)

			if got := findingIds(findings); !slices.Equal(got, testCase.expectedIds) {
				t.Errorf("Collect() ids = %v, want %v", got, testCase.expectedIds)
			}

			for _, finding := range findings {
				if finding.Domain != "example.com" {
					t.Errorf("finding domain = %q, want example.com", finding.Domain)
				}
				if finding.Source == "" {
					t.Error("a finding has no source")
				}
			}
		})
	}
}

func TestCollect_SourcesAndContextAreCarried(t *testing.T) {
	t.Parallel()

	metadata := &domainTypes.Metadata{
		SpfData: &domainTypes.SpfData{
			RecordCollection: []*spfTypes.TracedRecordWithProblems{
				{
					DomainTrace: []string{"example.com", "spf.provider.net"},
					Problems:    []*problemTypes.Problem{problem("ptr_used", problemTypes.SeverityInfo)},
				},
			},
		},
		DkimData: &domainTypes.DkimData{
			RecordCollection: []*dkimTypes.RecordWithProblems{
				{
					Record:   &altshiftDkim.Record{Selector: "selector1"},
					Problems: []*problemTypes.Problem{problem("testing_dkim_flag", problemTypes.SeverityInfo)},
				},
			},
		},
	}

	bySource := make(map[string]*Finding)
	for _, finding := range Collect("example.com", metadata) {
		bySource[finding.Source] = finding
	}

	spfFinding, ok := bySource[SourceSpf]
	if !ok {
		t.Fatal("no SPF finding")
	}
	// A problem reported against a domain often lives in a record its includes
	// reached, so the trace has to survive the flattening.
	if !slices.Equal(spfFinding.DomainTrace, []string{"example.com", "spf.provider.net"}) {
		t.Errorf("spf trace = %v, want the full path", spfFinding.DomainTrace)
	}
	if spfFinding.Selector != "" {
		t.Errorf("spf finding carries a selector %q", spfFinding.Selector)
	}

	dkimFinding, ok := bySource[SourceDkim]
	if !ok {
		t.Fatal("no DKIM finding")
	}
	if dkimFinding.Selector != "selector1" {
		t.Errorf("dkim selector = %q, want selector1", dkimFinding.Selector)
	}
}

func TestSort(t *testing.T) {
	t.Parallel()

	findings := []*Finding{
		{Domain: "b.example.com", Source: SourceSpf, Problem: problem("z", problemTypes.SeverityInfo)},
		{Domain: "a.example.com", Source: SourceDmarc, Problem: problem("y", problemTypes.SeverityHigh)},
		{Domain: "a.example.com", Source: SourceSpf, Problem: problem("x", problemTypes.SeverityLow)},
		{Domain: "a.example.com", Source: SourceDkim, Problem: problem("w", problemTypes.SeverityMedium)},
		{Domain: "a.example.com", Source: SourceSpf, Problem: problem("v", "nonsense")},
	}

	Sort(findings)

	// Most serious first; an unrecognised severity sorts last rather than being
	// lost.
	expected := []string{"y", "w", "x", "z", "v"}
	if got := findingIds(findings); !slices.Equal(got, expected) {
		t.Errorf("Sort() ids = %v, want %v", got, expected)
	}
}

func TestSort_IsStableAcrossRuns(t *testing.T) {
	t.Parallel()

	build := func() []*Finding {
		return []*Finding{
			{Domain: "a.example.com", Source: SourceSpf, Problem: problem("b", problemTypes.SeverityHigh)},
			{Domain: "a.example.com", Source: SourceSpf, Problem: problem("a", problemTypes.SeverityHigh)},
			{Domain: "a.example.com", Source: SourceDmarc, Problem: problem("c", problemTypes.SeverityHigh)},
		}
	}

	first := build()
	Sort(first)

	second := build()
	Sort(second)

	if !slices.Equal(findingIds(first), findingIds(second)) {
		t.Error("two sorts of the same data disagree")
	}
}

func TestAtLeast(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		severity string
		floor    string
		expected bool
	}{
		{name: "high passes a high floor", severity: problemTypes.SeverityHigh, floor: problemTypes.SeverityHigh, expected: true},
		{name: "info does not pass a high floor", severity: problemTypes.SeverityInfo, floor: problemTypes.SeverityHigh, expected: false},
		{name: "medium passes a low floor", severity: problemTypes.SeverityMedium, floor: problemTypes.SeverityLow, expected: true},
		{name: "info passes an info floor", severity: problemTypes.SeverityInfo, floor: problemTypes.SeverityInfo, expected: true},
		{name: "low does not pass a medium floor", severity: problemTypes.SeverityLow, floor: problemTypes.SeverityMedium, expected: false},
		{
			// A misspelled floor must not silently filter the whole report away.
			name:     "an unrecognised floor admits everything",
			severity: problemTypes.SeverityInfo,
			floor:    "nonsense",
			expected: true,
		},
		{
			name:     "an unrecognised severity does not pass a real floor",
			severity: "nonsense",
			floor:    problemTypes.SeverityInfo,
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := AtLeast(testCase.severity, testCase.floor); got != testCase.expected {
				t.Errorf("AtLeast(%q, %q) = %v, want %v", testCase.severity, testCase.floor, got, testCase.expected)
			}
		})
	}
}

func TestCounts(t *testing.T) {
	t.Parallel()

	findings := []*Finding{
		{Problem: problem("a", problemTypes.SeverityHigh)},
		{Problem: problem("b", problemTypes.SeverityHigh)},
		{Problem: problem("c", problemTypes.SeverityInfo)},
		{Problem: nil},
		nil,
	}

	counts := Counts(findings)

	if counts[problemTypes.SeverityHigh] != 2 {
		t.Errorf("high = %d, want 2", counts[problemTypes.SeverityHigh])
	}
	if counts[problemTypes.SeverityInfo] != 1 {
		t.Errorf("info = %d, want 1", counts[problemTypes.SeverityInfo])
	}
	if counts[problemTypes.SeverityMedium] != 0 {
		t.Errorf("medium = %d, want 0", counts[problemTypes.SeverityMedium])
	}
}

func TestCollect_DomainLocks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		whoisData     *domainTypes.WhoisData
		expectFinding bool
	}{
		{name: "no whois data at all", whoisData: nil},
		{
			// A WHOIS query that failed leaves everything unset. Reporting "no
			// locks" would be asserting something never looked at.
			name:      "the query failed, so nothing was read",
			whoisData: &domainTypes.WhoisData{},
		},
		{
			name: "the registrar holds locks",
			whoisData: &domainTypes.WhoisData{
				ServerTransferProhibited: ptr(false),
				ServerUpdateProhibited:   ptr(false),
				ServerDeleteProhibited:   ptr(false),
				ClientTransferProhibited: ptr(true),
				ClientUpdateProhibited:   ptr(false),
				ClientDeleteProhibited:   ptr(false),
			},
		},
		{
			name: "the registry holds locks",
			whoisData: &domainTypes.WhoisData{
				ServerTransferProhibited: ptr(true),
				ClientTransferProhibited: ptr(false),
			},
		},
		{
			name: "read, and neither party holds anything",
			whoisData: &domainTypes.WhoisData{
				ServerTransferProhibited: ptr(false),
				ServerUpdateProhibited:   ptr(false),
				ServerDeleteProhibited:   ptr(false),
				ClientTransferProhibited: ptr(false),
				ClientUpdateProhibited:   ptr(false),
				ClientDeleteProhibited:   ptr(false),
			},
			expectFinding: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			findings := Collect("example.com", &domainTypes.Metadata{WhoisData: testCase.whoisData})

			var sawFinding bool
			for _, finding := range findings {
				if finding.Problem.Id == RuleIdNoDomainLocks {
					sawFinding = true
					if finding.Source != SourceWhois {
						t.Errorf("source = %q, want %q", finding.Source, SourceWhois)
					}
				}
			}

			if sawFinding != testCase.expectFinding {
				t.Errorf("no-locks finding reported = %v, want %v", sawFinding, testCase.expectFinding)
			}
		})
	}
}
