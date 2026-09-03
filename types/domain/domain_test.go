package domain

import (
	"errors"
	"slices"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

func TestDomain_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		domain  *Domain
		wantErr bool
	}{
		{name: "nil domain", domain: nil, wantErr: true},
		{name: "empty domain name", domain: &Domain{}, wantErr: true},
		{name: "not a domain", domain: &Domain{Domain: "not a domain"}, wantErr: true},
		{name: "bare label", domain: &Domain{Domain: "localhost"}, wantErr: true},
		{name: "registered domain", domain: &Domain{Domain: "example.com"}, wantErr: false},
		{name: "subdomain", domain: &Domain{Domain: "mail.example.com"}, wantErr: false},
		{name: "multi-part suffix", domain: &Domain{Domain: "example.co.uk"}, wantErr: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := testCase.domain.Validate()
			if testCase.wantErr {
				if err == nil {
					t.Fatal("Validate() = nil, want an error")
				}

				// The failures have to reach an endpoint as a client error
				// rather than a server error.
				if !errors.Is(err, altshiftErrors.ErrValidationError) {
					t.Errorf("Validate() error = %v, want it to wrap ErrValidationError", err)
				}

				return
			}

			if err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestNewValidated(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                 string
		domainString         string
		wantErr              bool
		wantRegisteredDomain string
		wantSubdomain        string
		wantTopLevelDomain   string
	}{
		{
			name:                 "registered domain",
			domainString:         "example.com",
			wantRegisteredDomain: "example.com",
			wantTopLevelDomain:   "com",
		},
		{
			name:                 "subdomain is broken out",
			domainString:         "mail.example.com",
			wantRegisteredDomain: "example.com",
			wantSubdomain:        "mail",
			wantTopLevelDomain:   "com",
		},
		{
			name:                 "multi-part suffix",
			domainString:         "shop.example.co.uk",
			wantRegisteredDomain: "example.co.uk",
			wantSubdomain:        "shop",
			wantTopLevelDomain:   "co.uk",
		},
		{name: "invalid", domainString: "not a domain", wantErr: true},
		{name: "empty", domainString: "", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			domain, err := NewValidated(testCase.domainString)
			if testCase.wantErr {
				if err == nil {
					t.Fatal("NewValidated() = nil error, want an error")
				}
				if domain != nil {
					t.Errorf("NewValidated() domain = %v, want nil", domain)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewValidated() = %v, want nil", err)
			}
			if domain == nil {
				t.Fatal("NewValidated() domain = nil, want a domain")
			}

			if domain.Domain != testCase.domainString {
				t.Errorf("Domain = %q, want %q", domain.Domain, testCase.domainString)
			}
			if domain.RegisteredDomain != testCase.wantRegisteredDomain {
				t.Errorf("RegisteredDomain = %q, want %q", domain.RegisteredDomain, testCase.wantRegisteredDomain)
			}
			if domain.Subdomain != testCase.wantSubdomain {
				t.Errorf("Subdomain = %q, want %q", domain.Subdomain, testCase.wantSubdomain)
			}
			if domain.TopLevelDomain != testCase.wantTopLevelDomain {
				t.Errorf("TopLevelDomain = %q, want %q", domain.TopLevelDomain, testCase.wantTopLevelDomain)
			}
		})
	}
}

func TestNewObservation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		observedAt time.Time
		wantString string
	}{
		{
			name:       "whole second",
			observedAt: time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC),
			wantString: "2026-08-19T12:30:00.000000000Z",
		},
		{
			name:       "sub-second precision is kept",
			observedAt: time.Date(2026, 8, 19, 12, 30, 0, 123456789, time.UTC),
			wantString: "2026-08-19T12:30:00.123456789Z",
		},
		{
			name:       "a non-UTC instant is rendered in UTC",
			observedAt: time.Date(2026, 8, 19, 14, 30, 0, 0, time.FixedZone("CEST", 2*60*60)),
			wantString: "2026-08-19T12:30:00.000000000Z",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			observation := NewObservation(testCase.observedAt)

			if observation.ObservedAt != testCase.wantString {
				t.Errorf("ObservedAt = %q, want %q", observation.ObservedAt, testCase.wantString)
			}

			// The string is the only record of the instant, so it has to
			// recover it exactly.
			parsed, err := time.Parse(time.RFC3339Nano, observation.ObservedAt)
			if err != nil {
				t.Fatalf("time parse: %v", err)
			}
			if !parsed.Equal(testCase.observedAt) {
				t.Errorf("%q parses back to %v, want %v", observation.ObservedAt, parsed, testCase.observedAt)
			}
		})
	}
}

func TestWhoisData_LockPredicates(t *testing.T) {
	t.Parallel()

	ptr := func(value bool) *bool { return &value }

	testCases := []struct {
		name          string
		whoisData     *WhoisData
		expectedKnown bool
		expectedHeld  bool
	}{
		{name: "nil"},
		{name: "nothing read", whoisData: &WhoisData{}},
		{
			name:          "read, none held",
			whoisData:     &WhoisData{ServerTransferProhibited: ptr(false), ClientTransferProhibited: ptr(false)},
			expectedKnown: true,
		},
		{
			name:          "a registry lock held",
			whoisData:     &WhoisData{ServerUpdateProhibited: ptr(true)},
			expectedKnown: true,
			expectedHeld:  true,
		},
		{
			// The common case: only the registrar's locks are set, and reading
			// the registry's half alone would report the domain as unlocked.
			name:          "a registrar lock held",
			whoisData:     &WhoisData{ClientDeleteProhibited: ptr(true)},
			expectedKnown: true,
			expectedHeld:  true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.whoisData.AnyLockKnown(); got != testCase.expectedKnown {
				t.Errorf("AnyLockKnown() = %v, want %v", got, testCase.expectedKnown)
			}
			if got := testCase.whoisData.AnyLockHeld(); got != testCase.expectedHeld {
				t.Errorf("AnyLockHeld() = %v, want %v", got, testCase.expectedHeld)
			}
		})
	}
}

// The padded fraction exists so the rendered timestamps can be ordered as
// plain strings. With a trimmed fraction a whole second sorts last, because
// "." precedes "Z".
func TestNewObservation_SortsLexicographicallyByInstant(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 19, 12, 30, 0, 0, time.UTC)

	instants := []time.Time{
		base.Add(500 * time.Millisecond),
		base,
		base.Add(123456789 * time.Nanosecond),
		base.Add(time.Second),
	}

	rendered := make([]string, 0, len(instants))
	for _, instant := range instants {
		rendered = append(rendered, NewObservation(instant).ObservedAt)
	}

	sorted := slices.Clone(rendered)
	slices.Sort(sorted)

	chronological := slices.Clone(instants)
	slices.SortFunc(chronological, func(a time.Time, b time.Time) int { return a.Compare(b) })

	expected := make([]string, 0, len(chronological))
	for _, instant := range chronological {
		expected = append(expected, NewObservation(instant).ObservedAt)
	}

	if !slices.Equal(sorted, expected) {
		t.Errorf("string order = %v\nwant chronological order = %v", sorted, expected)
	}
}

func TestNewObservation_RoundTripsEveryFraction(t *testing.T) {
	t.Parallel()

	// The string is the sole record of the instant, so nothing may be lost -
	// including a fraction that is entirely zero, or one with leading zeros
	// that a trimming layout would render differently.
	for _, nanoseconds := range []int{0, 1, 999999999, 500000000, 123456789, 7} {
		instant := time.Date(2026, 8, 19, 12, 30, 0, nanoseconds, time.UTC)

		observation := NewObservation(instant)

		parsed, err := time.Parse(time.RFC3339Nano, observation.ObservedAt)
		if err != nil {
			t.Fatalf("time parse %q: %v", observation.ObservedAt, err)
		}

		if parsed.UnixNano() != instant.UnixNano() {
			t.Errorf("%q parses back to %d nanos, want %d", observation.ObservedAt, parsed.UnixNano(), instant.UnixNano())
		}
	}
}
