package domain_security

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/altshiftab/altshift_domain_security/domain_security/domain_security_config"
	dmarcRuleId "github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id"
	spfRuleId "github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
	"github.com/miekg/dns"
)

// fakeDNS answers TXT questions from an in-memory map keyed by canonical name.
type fakeDNS struct {
	records map[string][]string
	server  *dns.Server
	addr    string
	wg      sync.WaitGroup
}

func newFakeDNS(t *testing.T, records map[string][]string) *fakeDNS {
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

	fake := &fakeDNS{records: records, server: server, addr: localAddr(t, packetConn)}
	mux.HandleFunc(".", fake.handle)

	fake.wg.Add(1)
	go func() {
		defer fake.wg.Done()
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
		fake.wg.Wait()
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server failed to start")
	}

	return fake
}

func (fake *fakeDNS) handle(writer dns.ResponseWriter, request *dns.Msg) {
	message := new(dns.Msg)
	message.SetReply(request)
	message.Authoritative = true

	for _, question := range request.Question {
		entries, ok := fake.records[dns.CanonicalName(question.Name)]
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
}

func (fake *fakeDNS) client() *dnsUtilsClient.Client {
	return dnsUtilsClient.New(dnsUtilsClientConfig.WithAddress(fake.addr))
}

func mustParseCidr(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("net parse cidr: %v", err)
	}

	return network
}

func problemIds(problems []*problemTypes.Problem) []string {
	ids := make([]string, 0, len(problems))
	for _, problem := range problems {
		if problem != nil {
			ids = append(ids, problem.Id)
		}
	}
	sort.Strings(ids)

	return ids
}

func TestObservedAt(t *testing.T) {
	t.Parallel()

	t.Run("a context carrying no dns context is an error", func(t *testing.T) {
		t.Parallel()

		if _, err := observedAt(context.Background()); err == nil {
			t.Error("observedAt() = nil error, want an error")
		}
	})

	t.Run("a dns context with no exchange yet is an error", func(t *testing.T) {
		t.Parallel()

		// The context is present but nothing has been looked up through it, so
		// there is no instant to report.
		if _, err := observedAt(dnsUtilsContext.WithDnsContext(context.Background())); err == nil {
			t.Error("observedAt() = nil error, want an error")
		}
	})

	t.Run("reports when the exchange was made", func(t *testing.T) {
		t.Parallel()

		fake := newFakeDNS(t, map[string][]string{"example.com.": {"v=spf1 -all"}})

		before := time.Now()
		ctx := dnsUtilsContext.WithDnsContext(context.Background())
		if _, err := fake.client().GetSpfRecord(ctx, "example.com"); err != nil {
			t.Fatalf("get spf record: %v", err)
		}
		after := time.Now()

		lastObserved, err := observedAt(ctx)
		if err != nil {
			t.Fatalf("observedAt() = %v, want nil", err)
		}

		if lastObserved.Before(before) || lastObserved.After(after) {
			t.Errorf("observedAt() = %v, want it between %v and %v", lastObserved, before, after)
		}
	})
}

func TestNetworkPrefix(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		network  *net.IPNet
		expected string
	}{
		{name: "nil", network: nil},
		{name: "ipv4", network: mustParseCidr(t, "192.0.2.0/24"), expected: "192.0.2.0/24"},
		{name: "ipv6", network: mustParseCidr(t, "2001:db8::/32"), expected: "2001:db8::/32"},
		{
			name:     "a 16-byte ipv4 address with a 32-bit mask",
			network:  &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
			expected: "192.0.2.0/24",
		},
		{
			name:     "a 16-byte ipv4 address with a 128-bit mask",
			network:  &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(120, 128)},
			expected: "192.0.2.0/24",
		},
		{
			name:     "host bits are masked off",
			network:  &net.IPNet{IP: net.ParseIP("192.0.2.9").To4(), Mask: net.CIDRMask(24, 32)},
			expected: "192.0.2.0/24",
		},
		{
			name:    "a 16-byte ipv4 address with too short a 128-bit mask",
			network: &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(64, 128)},
		},
		{
			name:    "an ipv6 address with a 32-bit mask",
			network: &net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(24, 32)},
		},
		{
			name:    "a non-canonical mask",
			network: &net.IPNet{IP: net.ParseIP("192.0.2.0").To4(), Mask: net.IPv4Mask(255, 0, 255, 0)},
		},
		{
			name:    "an address of no length",
			network: &net.IPNet{Mask: net.CIDRMask(24, 32)},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			prefix, ok := networkPrefix(testCase.network)
			if testCase.expected == "" {
				if ok {
					t.Fatalf("networkPrefix() = %v, want none", prefix)
				}
				return
			}
			if !ok {
				t.Fatalf("networkPrefix() reported none, want %s", testCase.expected)
			}

			if got := prefix.String(); got != testCase.expected {
				t.Errorf("networkPrefix() = %s, want %s", got, testCase.expected)
			}
		})
	}
}

func TestNetworkCovered(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		allowed  []string
		observed string
		expected bool
	}{
		{name: "nothing allowed covers nothing", allowed: nil, observed: "192.0.2.0/24", expected: false},
		{name: "an equal network", allowed: []string{"192.0.2.0/24"}, observed: "192.0.2.0/24", expected: true},
		{name: "a narrower network inside", allowed: []string{"192.0.2.0/24"}, observed: "192.0.2.128/25", expected: true},
		{name: "a single address inside", allowed: []string{"192.0.2.0/24"}, observed: "192.0.2.9/32", expected: true},
		{name: "a network outside", allowed: []string{"192.0.2.0/24"}, observed: "198.51.100.0/24", expected: false},
		{
			name:     "a wider network sharing its first address",
			allowed:  []string{"10.0.0.0/24"},
			observed: "10.0.0.0/8",
			expected: false,
		},
		{
			name:     "any one allowed network is enough",
			allowed:  []string{"192.0.2.0/24", "10.0.0.0/8"},
			observed: "10.1.0.0/16",
			expected: true,
		},
		{name: "ipv6 inside", allowed: []string{"2001:db8::/32"}, observed: "2001:db8:1::/48", expected: true},
		{name: "families do not mix", allowed: []string{"::/0"}, observed: "192.0.2.0/24", expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			allowed := make([]netip.Prefix, 0, len(testCase.allowed))
			for _, allowedPrefix := range testCase.allowed {
				allowed = append(allowed, netip.MustParsePrefix(allowedPrefix))
			}

			observed := netip.MustParsePrefix(testCase.observed)
			if got := networkCovered(allowed, observed); got != testCase.expected {
				t.Errorf("networkCovered(%v, %s) = %v, want %v", testCase.allowed, observed, got, testCase.expected)
			}
		})
	}
}

func TestAddUnacknowledgedNetworkProblems(t *testing.T) {
	t.Parallel()

	recordWithNetworks := func(raw string) []*spfTypes.TracedRecordWithProblems {
		record, err := altshiftSpf.ParseSpfRecord([]byte(raw))
		if err != nil {
			t.Fatalf("parse spf record: %v", err)
		}

		return []*spfTypes.TracedRecordWithProblems{{Record: record, DomainTrace: []string{"example.com"}}}
	}

	testCases := []struct {
		name            string
		records         []*spfTypes.TracedRecordWithProblems
		allowedNetworks []*net.IPNet
		expectedDetails []string
	}{
		{
			name:            "no records is a no-op",
			records:         nil,
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
		},
		{
			name:            "no acknowledged networks disables the check",
			records:         recordWithNetworks("v=spf1 ip4:198.51.100.0/24 -all"),
			allowedNetworks: nil,
		},
		{
			name:            "an authorised network inside the list is not reported",
			records:         recordWithNetworks("v=spf1 ip4:192.0.2.0/24 -all"),
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
		},
		{
			name:            "an authorised network outside the list is reported",
			records:         recordWithNetworks("v=spf1 ip4:198.51.100.0/24 -all"),
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			expectedDetails: []string{"198.51.100.0/24"},
		},
		{
			name:            "each unacknowledged network is reported separately",
			records:         recordWithNetworks("v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.0/24 -all"),
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
			expectedDetails: []string{"198.51.100.0/24", "203.0.113.0/24"},
		},
		{
			name:            "a wider network starting inside the list is reported",
			records:         recordWithNetworks("v=spf1 ip4:10.0.0.0/8 -all"),
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "10.0.0.0/24")},
			expectedDetails: []string{"10.0.0.0/8"},
		},
		{
			name:            "a narrower network inside the list is not reported",
			records:         recordWithNetworks("v=spf1 ip4:192.0.2.9 -all"),
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
		},
		{
			name:            "a record that is absent is a no-op",
			records:         []*spfTypes.TracedRecordWithProblems{{DomainTrace: []string{"example.com"}}},
			allowedNetworks: []*net.IPNet{mustParseCidr(t, "192.0.2.0/24")},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := addUnacknowledgedNetworkProblems(testCase.records, testCase.allowedNetworks); err != nil {
				t.Fatalf("addUnacknowledgedNetworkProblems() = %v, want nil", err)
			}

			var details []string
			if len(testCase.records) > 0 && testCase.records[0] != nil {
				for _, problem := range testCase.records[0].Problems {
					if problem != nil && problem.Id == spfRuleId.UnacknowledgedNetwork {
						details = append(details, problem.Details)
					}
				}
			}
			sort.Strings(details)

			if !slices.Equal(details, testCase.expectedDetails) {
				t.Errorf("unacknowledged networks = %v, want %v", details, testCase.expectedDetails)
			}
		})
	}
}

func TestGetDomainDmarcSecurity(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"_dmarc.strict.example.com.":  {"v=DMARC1; p=reject; sp=reject"},
		"_dmarc.broken.example.com.":  {"v=DMARC1; p=nonsense; !!"},
		"_dmarc.doubled.example.com.": {"v=DMARC1; p=reject", "v=DMARC1; p=none"},
		// The organizational domain of mail.covered.com, which is what a
		// subdomain with no record of its own falls back to.
		"_dmarc.covered.com.": {"v=DMARC1; p=reject; sp=reject"},
	})

	testCases := []struct {
		name              string
		domain            string
		expectedProblems  []string
		expectedIsCovered bool
	}{
		{
			name:              "a strict record on the domain itself",
			domain:            "strict.example.com",
			expectedProblems:  []string{},
			expectedIsCovered: true,
		},
		{
			name:              "multiple records are reported and still count as covered",
			domain:            "doubled.example.com",
			expectedProblems:  []string{dmarcRuleId.MultipleRecords},
			expectedIsCovered: true,
		},
		{
			name:              "a subdomain falls back to a valid organizational record",
			domain:            "mail.covered.com",
			expectedProblems:  []string{dmarcRuleId.MissingRecord},
			expectedIsCovered: true,
		},
		{
			name:              "an organizational domain with no record is uncovered",
			domain:            "absent.example.com",
			expectedProblems:  []string{dmarcRuleId.MissingRecord},
			expectedIsCovered: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, problems, isCovered, err := GetDomainDmarcSecurity(context.Background(), testCase.domain, fake.client())
			if err != nil {
				t.Fatalf("GetDomainDmarcSecurity() = %v, want nil", err)
			}

			if got := problemIds(problems); !slices.Equal(got, testCase.expectedProblems) {
				t.Errorf("problems = %v, want %v", got, testCase.expectedProblems)
			}

			if isCovered != testCase.expectedIsCovered {
				t.Errorf("isCovered = %v, want %v", isCovered, testCase.expectedIsCovered)
			}
		})
	}
}

func TestGetDomainDmarcSecurity_MissingRecordOnOrganizationalDomainIsHigh(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{})

	_, problems, _, err := GetDomainDmarcSecurity(context.Background(), "example.com", fake.client())
	if err != nil {
		t.Fatalf("GetDomainDmarcSecurity() = %v, want nil", err)
	}

	if len(problems) != 1 {
		t.Fatalf("len(problems) = %d, want 1", len(problems))
	}

	// An organizational domain with no record is uncovered outright, which is
	// more serious than a subdomain that may still inherit one.
	if problems[0].Severity != problemTypes.SeverityHigh {
		t.Errorf("severity = %q, want %q", problems[0].Severity, problemTypes.SeverityHigh)
	}
}

func TestGetDomainSecurity_Guards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		domain    string
		dnsClient *dnsUtilsClient.Client
		wantNil   bool
		wantErr   bool
	}{
		{name: "an empty domain returns nothing", domain: "", wantNil: true},
		{name: "a nil dns client is an error", domain: "example.com", dnsClient: nil, wantErr: true},
		{name: "an unparseable domain is an error", domain: "not a domain", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := []domain_security_config.Option{domain_security_config.WithDnsClient(testCase.dnsClient)}

			metadata, err := GetDomainSecurity(context.Background(), testCase.domain, options...)

			if testCase.wantErr {
				if err == nil {
					t.Fatal("GetDomainSecurity() = nil error, want an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetDomainSecurity() = %v, want nil", err)
			}
			if testCase.wantNil && metadata != nil {
				t.Errorf("GetDomainSecurity() = %v, want nil", metadata)
			}
		})
	}
}

// A subdomain is assessed without the DNSSEC and registration lookups, which
// belong to a registered domain, so this exercises the whole gather without
// reaching a registry.
func TestGetDomainSecurity_Subdomain(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"mail.example.com.":                      {"v=spf1 ip4:198.51.100.0/24 -all"},
		"_dmarc.mail.example.com.":               {"v=DMARC1; p=reject; sp=reject"},
		"selector1._domainkey.mail.example.com.": {"v=DKIM1; k=rsa; p="},
	})

	metadata, err := GetDomainSecurity(
		context.Background(),
		"mail.example.com",
		domain_security_config.WithDnsClient(fake.client()),
		domain_security_config.WithAllowedNetworks(mustParseCidr(t, "192.0.2.0/24")),
		domain_security_config.WithDkimSelectors("selector1", "absent"),
	)
	if err != nil {
		t.Fatalf("GetDomainSecurity() = %v, want nil", err)
	}
	if metadata == nil {
		t.Fatal("GetDomainSecurity() = nil, want metadata")
	}

	if metadata.DnssecData != nil {
		t.Error("DnssecData is set for a subdomain, which has no delegation of its own")
	}
	if metadata.WhoisData != nil {
		t.Error("WhoisData is set for a subdomain, which has no registration of its own")
	}

	if metadata.SpfData == nil {
		t.Fatal("SpfData = nil, want it set")
	}
	if len(metadata.SpfData.RecordCollection) == 0 {
		t.Fatal("SpfData.RecordCollection is empty")
	}

	// The record authorises 198.51.100.0/24, which is not acknowledged.
	var sawUnacknowledged bool
	for _, problem := range metadata.SpfData.RecordCollection[0].Problems {
		if problem != nil && problem.Id == spfRuleId.UnacknowledgedNetwork {
			sawUnacknowledged = true
			if !strings.Contains(problem.Details, "198.51.100.0/24") {
				t.Errorf("details = %q, want it to name the network", problem.Details)
			}
		}
	}
	if !sawUnacknowledged {
		t.Error("the unacknowledged network was not reported")
	}

	if metadata.DmarcData == nil {
		t.Fatal("DmarcData = nil, want it set")
	}
	if metadata.DmarcData.IsCovered == nil || !*metadata.DmarcData.IsCovered {
		t.Error("DmarcData.IsCovered is not true")
	}

	if metadata.DkimData == nil {
		t.Fatal("DkimData = nil, want it set")
	}
	// Only the selector that exists is recorded; the guess that missed is not.
	if len(metadata.DkimData.RecordCollection) != 1 {
		t.Fatalf("len(DkimData.RecordCollection) = %d, want 1", len(metadata.DkimData.RecordCollection))
	}
	if selector := metadata.DkimData.RecordCollection[0].Record.Selector; selector != "selector1" {
		t.Errorf("selector = %q, want %q", selector, "selector1")
	}

	if metadata.DkimData.ObservedAt == "" {
		t.Error("DkimData carries no observation time")
	}
}

func TestAnalyzeDkimSelectors(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"a._domainkey.example.com.": {"v=DKIM1; k=rsa; p="},
		"b._domainkey.example.com.": {"v=DKIM1; k=rsa; p="},
	})

	testCases := []struct {
		name      string
		selectors []string
		dnsClient *dnsUtilsClient.Client
		expected  int
		wantErr   bool
	}{
		{name: "no selectors is a no-op", selectors: nil, dnsClient: fake.client(), expected: 0},
		{
			name:      "a nil dns client with selectors is an error",
			selectors: []string{"a"},
			dnsClient: nil,
			wantErr:   true,
		},
		{name: "one present selector", selectors: []string{"a"}, dnsClient: fake.client(), expected: 1},
		{name: "two present selectors", selectors: []string{"a", "b"}, dnsClient: fake.client(), expected: 2},
		{
			name:      "guesses that miss are skipped",
			selectors: []string{"a", "missing", "alsomissing"},
			dnsClient: fake.client(),
			expected:  1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			records, err := analyzeDkimSelectors(context.Background(), "example.com", testCase.selectors, testCase.dnsClient)

			if testCase.wantErr {
				if err == nil {
					t.Fatal("analyzeDkimSelectors() = nil error, want an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("analyzeDkimSelectors() = %v, want nil", err)
			}
			if len(records) != testCase.expected {
				t.Errorf("len(records) = %d, want %d", len(records), testCase.expected)
			}
		})
	}
}

// More selectors than the concurrency limit must all be probed.
func TestAnalyzeDkimSelectors_BeyondTheConcurrencyLimit(t *testing.T) {
	t.Parallel()

	records := make(map[string][]string)
	selectors := make([]string, 0, dkimLookupConcurrency*3)
	for i := range dkimLookupConcurrency * 3 {
		selector := "s" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		selectors = append(selectors, selector)
		records[selector+"._domainkey.example.com."] = []string{"v=DKIM1; k=rsa; p="}
	}

	fake := newFakeDNS(t, records)

	found, err := analyzeDkimSelectors(context.Background(), "example.com", selectors, fake.client())
	if err != nil {
		t.Fatalf("analyzeDkimSelectors() = %v, want nil", err)
	}

	if len(found) != len(selectors) {
		t.Errorf("len(found) = %d, want %d", len(found), len(selectors))
	}
}

// localAddr reports the address a listener actually bound to.
func localAddr(t *testing.T, packetConn net.PacketConn) string {
	t.Helper()

	address := packetConn.LocalAddr()
	if address == nil {
		t.Fatal("the listener reports no local address")
	}

	return address.String()
}

// newDnssecDns serves DNSKEY answers, or refuses them with the given rcode.
func newDnssecDns(t *testing.T, rcode int, answerWithKey bool) *dnsUtilsClient.Client {
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
		message.Rcode = rcode

		if answerWithKey {
			for _, question := range request.Question {
				if question.Qtype != dns.TypeDNSKEY {
					continue
				}
				message.Answer = append(
					message.Answer,
					&dns.DNSKEY{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeDNSKEY,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						Flags:     257,
						Protocol:  3,
						Algorithm: 13,
						PublicKey: "AwEAAQ==",
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

// A resolver that will not answer the DNSSEC probe must not cost the rest of
// the assessment. Resolvers differ here - a stub resolver was seen refusing
// this query intermittently while answering everything else - and losing the
// SPF, DKIM and DMARC findings over it would be a poor trade.
func TestGatherDnssec(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		rcode           int
		answerWithKey   bool
		expectData      bool
		expectedCovered bool
	}{
		{
			name:            "a signed zone",
			rcode:           dns.RcodeSuccess,
			answerWithKey:   true,
			expectData:      true,
			expectedCovered: true,
		},
		{
			name:       "an unsigned zone",
			rcode:      dns.RcodeSuccess,
			expectData: true,
		},
		{
			// What the resolver on the developer's own machine did.
			name:  "the resolver refuses the query",
			rcode: dns.RcodeFormatError,
		},
		{name: "the resolver fails", rcode: dns.RcodeServerFailure},
		{name: "the domain does not exist", rcode: dns.RcodeNameError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			dnssecData := gatherDnssec(
				t.Context(),
				"example.com",
				newDnssecDns(t, testCase.rcode, testCase.answerWithKey),
			)

			if !testCase.expectData {
				// Nil reads as "not established", which is distinct from a zone
				// that is genuinely unsigned.
				if dnssecData != nil {
					t.Errorf("gatherDnssec() = %+v, want nil", dnssecData)
				}

				return
			}

			if dnssecData == nil {
				t.Fatal("gatherDnssec() = nil, want data")
			}
			if dnssecData.Covered == nil {
				t.Fatal("Covered = nil, want it set")
			}
			if *dnssecData.Covered != testCase.expectedCovered {
				t.Errorf("Covered = %v, want %v", *dnssecData.Covered, testCase.expectedCovered)
			}
			if dnssecData.ObservedAt == "" {
				t.Error("the observation carries no time")
			}
		})
	}
}

func TestGatherDnssec_NilDnsClient(t *testing.T) {
	t.Parallel()

	if dnssecData := gatherDnssec(t.Context(), "example.com", nil); dnssecData != nil {
		t.Errorf("gatherDnssec() = %+v, want nil", dnssecData)
	}
}

type fakeStatusReader struct {
	statuses []string
	err      error
}

func (fake *fakeStatusReader) Statuses(_ context.Context, _ string) ([]string, error) {
	return fake.statuses, fake.err
}

func TestLockStates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		statuses []string
		expected []string
	}{
		{name: "as RDAP writes them", statuses: []string{"client transfer prohibited", "server update prohibited"}, expected: []string{"clienttransferprohibited", "serverupdateprohibited"}},
		{name: "as EPP codes", statuses: []string{"clientDeleteProhibited"}, expected: []string{"clientdeleteprohibited"}},
		{name: "with the ICANN URL", statuses: []string{"serverTransferProhibited https://icann.org/epp#serverTransferProhibited"}, expected: []string{"servertransferprohibited"}},
		{name: "none", statuses: nil, expected: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			states := lockStates(testCase.statuses)
			for _, code := range testCase.expected {
				if !states[code] {
					t.Errorf("expected %s among %v", code, states)
				}
			}
			if len(states) != len(testCase.expected) {
				t.Errorf("got %v, expected exactly %v", states, testCase.expected)
			}
		})
	}
}

// TestGetDomainSecurity_Locks holds that a registered domain's locks come from what the registry
// says, and that a registry that cannot be read leaves them unknown rather than failing the rest.
func TestGetDomainSecurity_Locks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		reader    *fakeStatusReader
		expectNil bool
		transfer  bool
		delete    bool
	}{
		{
			name:     "the registry's states",
			reader:   &fakeStatusReader{statuses: []string{"active", "client transfer prohibited", "serverDeleteProhibited"}},
			transfer: true,
			delete:   true,
		},
		{
			name:      "a registry with no RDAP server",
			reader:    &fakeStatusReader{err: errors.New("no rdap")}, //nolint:err113 // a stub's failure.
			expectNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fake := newFakeDNS(t, map[string][]string{
				"example.com.":        {"v=spf1 -all"},
				"_dmarc.example.com.": {"v=DMARC1; p=reject"},
			})

			metadata, err := GetDomainSecurity(
				context.Background(),
				"example.com",
				domain_security_config.WithDnsClient(fake.client()),
				domain_security_config.WithStatusReader(testCase.reader),
			)
			if err != nil {
				t.Fatalf("GetDomainSecurity() = %v, want nil", err)
			}
			if metadata == nil {
				t.Fatal("GetDomainSecurity() = nil, want metadata")
			}

			whoisData := metadata.WhoisData
			if testCase.expectNil {
				if whoisData != nil {
					t.Errorf("expected no lock data, got %+v", whoisData)
				}
				return
			}

			if whoisData == nil || whoisData.ClientTransferProhibited == nil || whoisData.ServerDeleteProhibited == nil ||
				whoisData.ClientUpdateProhibited == nil {
				t.Fatalf("expected every lock known, got %+v", whoisData)
			}
			if *whoisData.ClientTransferProhibited != testCase.transfer || *whoisData.ServerDeleteProhibited != testCase.delete {
				t.Errorf("got transfer %v delete %v", *whoisData.ClientTransferProhibited, *whoisData.ServerDeleteProhibited)
			}
			if *whoisData.ClientUpdateProhibited {
				t.Error("expected an unrecorded lock reported as not held")
			}
		})
	}
}
