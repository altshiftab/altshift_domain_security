package discovery

import (
	"net"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	"github.com/altshiftab/altshift_domain_security/types/inference"
	"github.com/miekg/dns"
)

// zone is what the fake resolver knows about one name.
type zone struct {
	a        []string
	mx       []string
	servfail bool
}

// fakeDNS answers A and MX questions from an in-memory map. A name that is
// absent is answered NXDOMAIN, which is how a domain that does not exist looks.
type fakeDNS struct {
	zones  map[string]zone
	server *dns.Server
	addr   string
	wg     sync.WaitGroup
}

func newFakeDNS(t *testing.T, zones map[string]zone) *fakeDNS {
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

	fake := &fakeDNS{zones: zones, server: server, addr: localAddr(t, packetConn)}
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
		name := dns.CanonicalName(question.Name)

		entry, ok := fake.zones[name]
		if !ok {
			message.Rcode = dns.RcodeNameError
			continue
		}

		if entry.servfail {
			message.Rcode = dns.RcodeServerFailure
			continue
		}

		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 60}

		switch question.Qtype {
		case dns.TypeA:
			for _, address := range entry.a {
				aHeader := header
				aHeader.Rrtype = dns.TypeA
				message.Answer = append(message.Answer, &dns.A{Hdr: aHeader, A: net.ParseIP(address)})
			}
		case dns.TypeMX:
			for _, exchange := range entry.mx {
				mxHeader := header
				mxHeader.Rrtype = dns.TypeMX
				message.Answer = append(message.Answer, &dns.MX{Hdr: mxHeader, Preference: 10, Mx: dns.Fqdn(exchange)})
			}
		}
	}

	_ = writer.WriteMsg(message)
}

func (fake *fakeDNS) client() *dnsUtilsClient.Client {
	return dnsUtilsClient.New(dnsUtilsClientConfig.WithAddress(fake.addr))
}

func domainNames(domains []*domainTypes.Domain) []string {
	names := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain != nil {
			names = append(names, domain.Domain)
		}
	}
	sort.Strings(names)

	return names
}

func TestExtractRegisteredDomainNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		domainNames []string
		expected    []string
	}{
		{name: "no input", domainNames: nil, expected: nil},
		{
			name:        "subdomains collapse onto their registered domain",
			domainNames: []string{"a.example.com", "b.example.com", "example.com"},
			expected:    []string{"example.com"},
		},
		{
			name:        "distinct registered domains are kept apart",
			domainNames: []string{"a.example.com", "other.example.org"},
			expected:    []string{"example.com", "example.org"},
		},
		{
			name:        "multi-part suffixes resolve to the registrable name",
			domainNames: []string{"shop.example.co.uk"},
			expected:    []string{"example.co.uk"},
		},
		{
			name:        "unparseable names are dropped",
			domainNames: []string{"not a domain", "localhost", "example.com"},
			expected:    []string{"example.com"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := extractRegisteredDomainNames(testCase.domainNames)
			sort.Strings(got)

			if !slices.Equal(got, testCase.expected) {
				t.Errorf("extractRegisteredDomainNames() = %v, want %v", got, testCase.expected)
			}
		})
	}
}

func TestMergeDomains(t *testing.T) {
	t.Parallel()

	makeDomain := func(name string, chain ...string) *domainTypes.Domain {
		return &domainTypes.Domain{
			Domain: name,
			Metadata: &domainTypes.Metadata{
				Inferences: []*inference.Inference{{Confidence: 3, Chain: chain}},
			},
		}
	}

	testCases := []struct {
		name           string
		domains        []*domainTypes.Domain
		expectedNames  []string
		expectedChains map[string]int
	}{
		{name: "nothing merges to nothing", domains: nil, expectedNames: []string{}},
		{
			name:           "nil entries and empty names are dropped",
			domains:        []*domainTypes.Domain{nil, {Domain: ""}, makeDomain("example.com", "a")},
			expectedNames:  []string{"example.com"},
			expectedChains: map[string]int{"example.com": 1},
		},
		{
			name: "a domain found twice keeps both reasons",
			domains: []*domainTypes.Domain{
				makeDomain("example.com", "Reverse Whois"),
				makeDomain("example.com", "Reverse IP address"),
			},
			expectedNames:  []string{"example.com"},
			expectedChains: map[string]int{"example.com": 2},
		},
		{
			name: "distinct domains are kept apart",
			domains: []*domainTypes.Domain{
				makeDomain("one.example.com", "a"),
				makeDomain("two.example.com", "b"),
			},
			expectedNames:  []string{"one.example.com", "two.example.com"},
			expectedChains: map[string]int{"one.example.com": 1, "two.example.com": 1},
		},
		{
			name: "a duplicate without metadata does not lose the original's",
			domains: []*domainTypes.Domain{
				makeDomain("example.com", "Reverse Whois"),
				{Domain: "example.com"},
			},
			expectedNames:  []string{"example.com"},
			expectedChains: map[string]int{"example.com": 1},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			merged := MergeDomains(testCase.domains...)

			if got := domainNames(merged); !slices.Equal(got, testCase.expectedNames) {
				t.Fatalf("MergeDomains() names = %v, want %v", got, testCase.expectedNames)
			}

			for _, domain := range merged {
				expectedCount, ok := testCase.expectedChains[domain.Domain]
				if !ok {
					continue
				}

				var count int
				if domain.Metadata != nil {
					count = len(domain.Metadata.Inferences)
				}
				if count != expectedCount {
					t.Errorf("%s has %d inferences, want %d", domain.Domain, count, expectedCount)
				}
			}
		})
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
