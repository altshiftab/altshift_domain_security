package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/altshiftab/altshift_domain_security/pkg/report"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	"github.com/miekg/dns"
)

func ptr[T any](value T) *T {
	return &value
}

// newFakeDnsClient serves TXT records from an in-memory map and answers
// everything else NXDOMAIN.
func newFakeDnsClient(t *testing.T, records map[string][]string) *dnsUtilsClient.Client {
	t.Helper()

	packetConn, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}

	started := make(chan struct{})
	mux := dns.NewServeMux()
	server := &dns.Server{
		PacketConn:        packetConn,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}

	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true

		for _, question := range request.Question {
			entries, ok := records[dns.CanonicalName(question.Name)]
			if !ok {
				message.Rcode = dns.RcodeNameError
				continue
			}
			if question.Qtype != dns.TypeTXT {
				continue
			}
			for _, entry := range entries {
				message.Answer = append(
					message.Answer,
					&dns.TXT{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						Txt: []string{entry},
					},
				)
			}
		}

		_ = writer.WriteMsg(message)
	})

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
		waitGroup.Wait()
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server failed to start")
	}

	address := packetConn.LocalAddr()
	if address == nil {
		t.Fatal("the listener reports no local address")
	}

	return dnsUtilsClient.New(dnsUtilsClientConfig.WithAddress(address.String()))
}

func TestDomainLocks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		whoisData        *domainTypes.WhoisData
		expectedRegistry []string
		expectedClient   []string
	}{
		{name: "no whois data", whoisData: nil},
		{name: "nothing read", whoisData: &domainTypes.WhoisData{}},
		{
			name: "locks explicitly not held",
			whoisData: &domainTypes.WhoisData{
				ServerTransferProhibited: ptr(false),
				ClientTransferProhibited: ptr(false),
			},
		},
		{
			name:             "a registry lock",
			whoisData:        &domainTypes.WhoisData{ServerTransferProhibited: ptr(true)},
			expectedRegistry: []string{"transfer"},
		},
		{
			// The ordinary case: every lock a typical domain has is the
			// registrar's, and reading only the registry's would report none.
			name: "the registrar's locks alone",
			whoisData: &domainTypes.WhoisData{
				ClientTransferProhibited: ptr(true),
				ClientUpdateProhibited:   ptr(true),
				ClientDeleteProhibited:   ptr(true),
			},
			expectedClient: []string{"transfer", "update", "delete"},
		},
		{
			name: "both parties, kept apart",
			whoisData: &domainTypes.WhoisData{
				ServerTransferProhibited: ptr(true),
				ClientUpdateProhibited:   ptr(true),
			},
			expectedRegistry: []string{"transfer"},
			expectedClient:   []string{"update"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			registry, client := domainLocks(testCase.whoisData)

			if strings.Join(registry, ",") != strings.Join(testCase.expectedRegistry, ",") {
				t.Errorf("registry locks = %v, want %v", registry, testCase.expectedRegistry)
			}
			if strings.Join(client, ",") != strings.Join(testCase.expectedClient, ",") {
				t.Errorf("client locks = %v, want %v", client, testCase.expectedClient)
			}
		})
	}
}

func TestFormatLocks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		registry []string
		client   []string
		expected string
	}{
		{name: "none", expected: "none"},
		{name: "registry only", registry: []string{"transfer"}, expected: "registry:transfer"},
		{
			name:     "client only",
			client:   []string{"transfer", "update", "delete"},
			expected: "client:transfer,update,delete",
		},
		{
			name:     "both, each attributed",
			registry: []string{"transfer"},
			client:   []string{"update"},
			expected: "registry:transfer client:update",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := formatLocks(testCase.registry, testCase.client); got != testCase.expected {
				t.Errorf("formatLocks() = %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		value    *bool
		expected string
	}{
		{name: "never asked", value: nil, expected: "-"},
		{name: "covered", value: ptr(true), expected: "yes"},
		{name: "not covered", value: ptr(false), expected: "no"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := coverage(testCase.value); got != testCase.expected {
				t.Errorf("coverage() = %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestFormatCounts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		counts   map[string]int
		expected string
	}{
		{name: "nothing found", counts: map[string]int{}, expected: ""},
		{
			name:     "one severity",
			counts:   map[string]int{problemTypes.SeverityHigh: 2},
			expected: " (2 high)",
		},
		{
			name: "most serious first, absent severities omitted",
			counts: map[string]int{
				problemTypes.SeverityInfo: 4,
				problemTypes.SeverityHigh: 1,
			},
			expected: " (1 high, 4 info)",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := formatCounts(testCase.counts); got != testCase.expected {
				t.Errorf("formatCounts() = %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestFindingContext(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		finding  *report.Finding
		expected string
	}{
		{name: "nil finding", finding: nil, expected: ""},
		{name: "no problem", finding: &report.Finding{}, expected: ""},
		{
			name: "details alone",
			finding: &report.Finding{
				Problem: &problemTypes.Problem{Details: "Encountered policy: none"},
			},
			expected: "Encountered policy: none",
		},
		{
			name: "a dkim selector",
			finding: &report.Finding{
				Selector: "selector1",
				Problem:  &problemTypes.Problem{},
			},
			expected: "selector=selector1",
		},
		{
			// A problem reported against a domain often lives in a record its
			// includes reached; naming that record is what makes it actionable.
			name: "an spf trace names the record the problem is in",
			finding: &report.Finding{
				DomainTrace: []string{"example.com", "spf.provider.net"},
				Problem:     &problemTypes.Problem{Details: "PTR used"},
			},
			expected: "via example.com > spf.provider.net  PTR used",
		},
		{
			name: "a single-element trace is not worth printing",
			finding: &report.Finding{
				DomainTrace: []string{"example.com"},
				Problem:     &problemTypes.Problem{Details: "PTR used"},
			},
			expected: "PTR used",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := findingContext(testCase.finding); got != testCase.expected {
				t.Errorf("findingContext() = %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestWriteAuditText(t *testing.T) {
	t.Parallel()

	auditResult := &auditReport{
		Seed: "example.com",
		Domains: []*domainReport{
			{
				Domain:        "clean.example.com",
				DnssecCovered: ptr(true),
				DmarcCovered:  ptr(true),
				RegistryLocks: []string{"transfer"},
				ClientLocks:   []string{"update"},
				Findings:      []*report.Finding{},
			},
			{
				Domain:       "bad.example.com",
				DmarcCovered: ptr(false),
				Findings: []*report.Finding{
					{
						Domain:  "bad.example.com",
						Source:  report.SourceDmarc,
						Problem: &problemTypes.Problem{Id: "insufficient_p", Severity: problemTypes.SeverityHigh},
					},
				},
			},
			{Domain: "broken.example.com", Error: "resolver unreachable"},
		},
		Counts:       map[string]int{problemTypes.SeverityHigh: 1},
		DomainCount:  3,
		FindingCount: 1,
	}

	var builder strings.Builder
	if err := writeAuditText(&builder, auditResult); err != nil {
		t.Fatalf("writeAuditText() = %v, want nil", err)
	}

	output := builder.String()

	for _, expected := range []string{
		"clean.example.com",
		"no problems",
		"registry:transfer client:update",
		"HIGH",
		"insufficient_p",
		"! not assessed: resolver unreachable",
		"3 domain(s), 1 problem(s) (1 high)",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("output is missing %q\n---\n%s", expected, output)
		}
	}

	// A domain that could not be assessed must not be reported as clean.
	if strings.Contains(output, "broken.example.com\n  dnssec") {
		t.Error("a failed domain was given a coverage line")
	}

	for _, line := range strings.Split(output, "\n") {
		if line != strings.TrimRight(line, " ") {
			t.Errorf("line has trailing whitespace: %q", line)
		}
	}
}

func TestWriteAuditText_NilReport(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	if err := writeAuditText(&builder, nil); err == nil {
		t.Error("writeAuditText(nil) = nil error, want an error")
	}
}

// The whole chain, end to end, against a resolver under the test's control:
// settle the domain set, assess it, flatten the problems, rank them.
//
// A subdomain is used deliberately. DNSSEC and WHOIS are only asked about for a
// registered domain, and WHOIS would reach the network.
func TestRunAudit_EndToEnd(t *testing.T) {
	t.Parallel()

	dnsClient := newFakeDnsClient(t, map[string][]string{
		// ?all is neutral, which is not a sufficient policy.
		"mail.example.com.":                      {"v=spf1 ip4:198.51.100.0/24 ?all"},
		"_dmarc.mail.example.com.":               {"v=DMARC1; p=none"},
		"selector1._domainkey.mail.example.com.": {"v=DKIM1; k=rsa; t=y; p="},
	})

	auditResult, err := runAudit(
		context.Background(),
		&auditConfig{
			Domain:          "mail.example.com",
			DnsClient:       dnsClient,
			DkimSelectors:   []string{"selector1"},
			AllowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			Concurrency:     2,
			MinSeverity:     problemTypes.SeverityInfo,
		},
	)
	if err != nil {
		t.Fatalf("runAudit() = %v, want nil", err)
	}

	if auditResult.DomainCount != 1 {
		t.Fatalf("DomainCount = %d, want 1", auditResult.DomainCount)
	}
	if auditResult.Seed != "mail.example.com" {
		t.Errorf("Seed = %q, want mail.example.com", auditResult.Seed)
	}

	domainResult := auditResult.Domains[0]
	if domainResult.Error != "" {
		t.Fatalf("the assessment failed: %s", domainResult.Error)
	}

	foundIds := make(map[string]string)
	for _, finding := range domainResult.Findings {
		foundIds[finding.Problem.Id] = finding.Source
	}

	// One from each mechanism, proving the flattening reaches all of them.
	for id, expectedSource := range map[string]string{
		"insufficient_all":       report.SourceSpf,
		"unacknowledged_network": report.SourceSpf,
		"insufficient_p":         report.SourceDmarc,
		"testing_dkim_flag":      report.SourceDkim,
	} {
		source, ok := foundIds[id]
		if !ok {
			t.Errorf("%q was not reported; got %v", id, foundIds)
			continue
		}
		if source != expectedSource {
			t.Errorf("%q source = %q, want %q", id, source, expectedSource)
		}
	}

	// Ranked most serious first.
	previous := -1
	for _, finding := range domainResult.Findings {
		rank := map[string]int{
			problemTypes.SeverityHigh:   0,
			problemTypes.SeverityMedium: 1,
			problemTypes.SeverityLow:    2,
			problemTypes.SeverityInfo:   3,
		}[finding.Problem.Severity]

		if rank < previous {
			t.Errorf("findings are not ranked: %q (%s) follows a less serious one", finding.Problem.Id, finding.Problem.Severity)
		}
		previous = rank
	}

	if auditResult.FindingCount != len(domainResult.Findings) {
		t.Errorf("FindingCount = %d, want %d", auditResult.FindingCount, len(domainResult.Findings))
	}
}

func TestRunAudit_MinSeverityFilters(t *testing.T) {
	t.Parallel()

	dnsClient := newFakeDnsClient(t, map[string][]string{
		"mail.example.com.":                      {"v=spf1 ip4:198.51.100.0/24 ?all"},
		"_dmarc.mail.example.com.":               {"v=DMARC1; p=none"},
		"selector1._domainkey.mail.example.com.": {"v=DKIM1; k=rsa; t=y; p="},
	})

	newConfig := func(minSeverity string) *auditConfig {
		return &auditConfig{
			Domain:        "mail.example.com",
			DnsClient:     dnsClient,
			DkimSelectors: []string{"selector1"},
			Concurrency:   1,
			MinSeverity:   minSeverity,
		}
	}

	all, err := runAudit(context.Background(), newConfig(problemTypes.SeverityInfo))
	if err != nil {
		t.Fatalf("runAudit() = %v, want nil", err)
	}

	high, err := runAudit(context.Background(), newConfig(problemTypes.SeverityHigh))
	if err != nil {
		t.Fatalf("runAudit() = %v, want nil", err)
	}

	if high.FindingCount == 0 {
		t.Fatal("no high-severity findings survived, so the filter proves nothing")
	}
	if high.FindingCount >= all.FindingCount {
		t.Errorf("a high floor kept %d of %d findings, want fewer", high.FindingCount, all.FindingCount)
	}

	for _, domainResult := range high.Domains {
		for _, finding := range domainResult.Findings {
			if finding.Problem.Severity != problemTypes.SeverityHigh {
				t.Errorf("a %q finding survived a high floor", finding.Problem.Severity)
			}
		}
	}
}

func TestRunAudit_NilConfig(t *testing.T) {
	t.Parallel()

	if _, err := runAudit(context.Background(), nil); err == nil {
		t.Error("runAudit(nil) = nil error, want an error")
	}
}

func TestAuditDomains_SeedIsAlwaysIncluded(t *testing.T) {
	t.Parallel()

	// Discovery deliberately excludes the domain it was pointed at, and with no
	// source key it is not run at all; the audit must still cover the seed.
	domainNames, err := auditDomains(
		context.Background(),
		&auditConfig{Domain: "example.com", DnsClient: dnsUtilsClient.DefaultClient},
	)
	if err != nil {
		t.Fatalf("auditDomains() = %v, want nil", err)
	}

	if len(domainNames) != 1 || domainNames[0] != "example.com" {
		t.Errorf("auditDomains() = %v, want [example.com]", domainNames)
	}
}

func mustParseCidr(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net parse cidr: %v", err)
	}

	return network
}
