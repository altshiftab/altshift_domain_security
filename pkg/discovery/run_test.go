package discovery

import (
	"context"
	"slices"
	"testing"

	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
)

func TestFilterDomainNamesActive(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string]zone{
		"resolves.example.com.": {a: []string{"192.0.2.1"}},
		"broken.example.com.":   {servfail: true},
	})

	testCases := []struct {
		name     string
		domains  []*domainTypes.Domain
		expected []string
	}{
		{name: "no domains", domains: nil, expected: []string{}},
		{
			name:     "a domain that resolves is kept",
			domains:  []*domainTypes.Domain{{Domain: "resolves.example.com"}},
			expected: []string{"resolves.example.com"},
		},
		{
			name:     "a domain that does not exist is dropped",
			domains:  []*domainTypes.Domain{{Domain: "missing.example.com"}},
			expected: []string{},
		},
		{
			// Discovery exists to widen the set of domains to look at, so a
			// resolver failure must not silently narrow it.
			name:     "a lookup failure keeps the domain",
			domains:  []*domainTypes.Domain{{Domain: "broken.example.com"}},
			expected: []string{"broken.example.com"},
		},
		{
			name: "nil entries and empty names are skipped",
			domains: []*domainTypes.Domain{
				nil,
				{Domain: ""},
				{Domain: "resolves.example.com"},
			},
			expected: []string{"resolves.example.com"},
		},
		{
			name: "a mixed set is narrowed to what resolves",
			domains: []*domainTypes.Domain{
				{Domain: "resolves.example.com"},
				{Domain: "missing.example.com"},
			},
			expected: []string{"resolves.example.com"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			active, err := FilterDomainNamesActive(context.Background(), testCase.domains, fake.client())
			if err != nil {
				t.Fatalf("FilterDomainNamesActive() = %v, want nil", err)
			}

			if got := domainNames(active); !slices.Equal(got, testCase.expected) {
				t.Errorf("FilterDomainNamesActive() = %v, want %v", got, testCase.expected)
			}
		})
	}
}

func TestFilterDomainNamesActive_NilDnsClient(t *testing.T) {
	t.Parallel()

	domains := []*domainTypes.Domain{{Domain: "example.com"}}

	if _, err := FilterDomainNamesActive(context.Background(), domains, nil); err == nil {
		t.Error("FilterDomainNamesActive() = nil error, want an error for a nil dns client")
	}
}

func TestFilterDomainsValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		domains  []*domainTypes.Domain
		expected []string
	}{
		{name: "no domains", domains: nil, expected: []string{}},
		{
			name: "junk from a source is dropped",
			domains: []*domainTypes.Domain{
				{Domain: "example.com"},
				{Domain: "not a domain"},
				{Domain: ""},
				nil,
			},
			expected: []string{"example.com"},
		},
		{
			name: "valid domains are kept",
			domains: []*domainTypes.Domain{
				{Domain: "example.com"},
				{Domain: "mail.example.co.uk"},
			},
			expected: []string{"example.com", "mail.example.co.uk"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			valid := FilterDomainsValid(context.Background(), testCase.domains)

			if got := domainNames(valid); !slices.Equal(got, testCase.expected) {
				t.Errorf("FilterDomainsValid() = %v, want %v", got, testCase.expected)
			}
		})
	}
}

// AddSendingMetadata records a guess about whether a domain sends mail. A domain
// with mail exchangers handles mail; one without is the candidate for being
// non-sending, and the guess must not be recorded the other way round.
func TestAddSendingMetadata(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string]zone{
		"sender.example.com.":    {mx: []string{"mail.example.com"}},
		"nonsender.example.com.": {a: []string{"192.0.2.1"}},
		"broken.example.com.":    {servfail: true},
	})

	testCases := []struct {
		name       string
		domainName string
		expected   *bool
	}{
		{
			name:       "a domain with MX records is not guessed non-sending",
			domainName: "sender.example.com",
			expected:   ptr(false),
		},
		{
			name:       "a domain without MX records is guessed non-sending",
			domainName: "nonsender.example.com",
			expected:   ptr(true),
		},
		{
			name:       "a domain that does not exist carries no guess",
			domainName: "missing.example.com",
			expected:   nil,
		},
		{
			name:       "a lookup failure leaves the guess unset",
			domainName: "broken.example.com",
			expected:   nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			domain := &domainTypes.Domain{Domain: testCase.domainName}

			if err := AddSendingMetadata(context.Background(), []*domainTypes.Domain{domain}, fake.client()); err != nil {
				t.Fatalf("AddSendingMetadata() = %v, want nil", err)
			}

			var got *bool
			if domain.Metadata != nil {
				got = domain.Metadata.GuessedNonSending
			}

			switch {
			case testCase.expected == nil && got != nil:
				t.Errorf("GuessedNonSending = %v, want unset", *got)
			case testCase.expected != nil && got == nil:
				t.Errorf("GuessedNonSending = unset, want %v", *testCase.expected)
			case testCase.expected != nil && got != nil && *got != *testCase.expected:
				t.Errorf("GuessedNonSending = %v, want %v", *got, *testCase.expected)
			}
		})
	}
}

func TestAddSendingMetadata_Guards(t *testing.T) {
	t.Parallel()

	t.Run("no domains is not an error", func(t *testing.T) {
		t.Parallel()

		if err := AddSendingMetadata(context.Background(), nil, nil); err != nil {
			t.Errorf("AddSendingMetadata() = %v, want nil", err)
		}
	})

	t.Run("a nil dns client with domains is an error", func(t *testing.T) {
		t.Parallel()

		domains := []*domainTypes.Domain{{Domain: "example.com"}}
		if err := AddSendingMetadata(context.Background(), domains, nil); err == nil {
			t.Error("AddSendingMetadata() = nil error, want an error for a nil dns client")
		}
	})
}

func TestGetDomains_NoSourcesConfigured(t *testing.T) {
	t.Parallel()

	// With no API key for either source, a run consults nothing and returns
	// nothing rather than failing.
	domains, err := GetDomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetDomains() = %v, want nil", err)
	}
	if len(domains) != 0 {
		t.Errorf("GetDomains() = %v, want none", domains)
	}
}

func TestGetDomains_EmptyDomainName(t *testing.T) {
	t.Parallel()

	domains, err := GetDomains(context.Background(), "")
	if err != nil {
		t.Fatalf("GetDomains() = %v, want nil", err)
	}
	if domains != nil {
		t.Errorf("GetDomains() = %v, want nil", domains)
	}
}

func ptr[T any](value T) *T {
	return &value
}
