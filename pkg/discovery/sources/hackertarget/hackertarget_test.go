package hackertarget

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	hackerTargetErrors "github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/hackertarget/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// stubTransport answers every request with one canned body, and records the
// request it was asked to make.
type stubTransport struct {
	body    string
	request *http.Request
}

func (transport *stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.request = request

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(transport.body)),
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Request:    request,
	}, nil
}

func newStubbedFetchOption(body string) (fetch_config.Option, *stubTransport) {
	transport := &stubTransport{body: body}

	return fetch_config.WithHttpClient(&http.Client{Transport: transport}), transport
}

func TestQueryReverseIp_Guards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		ipAddress   net.IP
		apiKey      string
		wantDomains bool
		wantErr     error
	}{
		{name: "no address returns nothing", ipAddress: nil, apiKey: "key"},
		{name: "empty api key", ipAddress: net.ParseIP("192.0.2.1"), apiKey: ""},
		{
			name:      "ipv6 is rejected",
			ipAddress: net.ParseIP("2001:db8::1"),
			apiKey:    "key",
			wantErr:   hackerTargetErrors.ErrNotIpv4,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			option, _ := newStubbedFetchOption("")

			domains, err := QueryReverseIp(context.Background(), testCase.ipAddress, testCase.apiKey, option)

			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("QueryReverseIp() error = %v, want %v", err, testCase.wantErr)
				}
				return
			}

			if testCase.apiKey == "" {
				if err == nil {
					t.Fatal("QueryReverseIp() = nil error, want an error for an empty api key")
				}
				return
			}

			if err != nil {
				t.Fatalf("QueryReverseIp() = %v, want nil", err)
			}
			if domains != nil {
				t.Errorf("QueryReverseIp() = %v, want nil", domains)
			}
		})
	}
}

func TestQueryReverseIp_ApiErrorsAreRecognisedByBody(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		wantErr error
	}{
		{
			name:    "quota exceeded",
			body:    "API count exceeded - Increase Quota with Membership",
			wantErr: hackerTargetErrors.ErrQuotaExceeded,
		},
		{
			name:    "bad search parameter",
			body:    "error check your search parameter",
			wantErr: hackerTargetErrors.ErrBadSearchParameter,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			option, _ := newStubbedFetchOption(testCase.body)

			_, err := QueryReverseIp(context.Background(), net.ParseIP("192.0.2.1"), "key", option)
			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("QueryReverseIp() error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestQueryReverseIp_ParsesNamesAndSendsTheQuery(t *testing.T) {
	t.Parallel()

	option, transport := newStubbedFetchOption("one.example.com\ntwo.example.com")

	domains, err := QueryReverseIp(context.Background(), net.ParseIP("192.0.2.1"), "secret", option)
	if err != nil {
		t.Fatalf("QueryReverseIp() = %v, want nil", err)
	}

	expected := []string{"one.example.com", "two.example.com"}
	if !slices.Equal(domains, expected) {
		t.Errorf("QueryReverseIp() = %v, want %v", domains, expected)
	}

	if transport.request == nil {
		t.Fatal("no request was made")
	}

	query := transport.request.URL.Query()
	if got := query.Get("q"); got != "192.0.2.1" {
		t.Errorf("q = %q, want %q", got, "192.0.2.1")
	}
	if got := query.Get("apikey"); got != "secret" {
		t.Errorf("apikey = %q, want %q", got, "secret")
	}
}

func TestQueryReverseIp_Ipv4MappedAddressIsAccepted(t *testing.T) {
	t.Parallel()

	option, transport := newStubbedFetchOption("one.example.com")

	// An IPv4 address parsed from text is held in 16-byte form; the query must
	// still go out as dotted quad.
	if _, err := QueryReverseIp(context.Background(), net.ParseIP("198.51.100.7"), "key", option); err != nil {
		t.Fatalf("QueryReverseIp() = %v, want nil", err)
	}

	if transport.request == nil {
		t.Fatal("no request was made")
	}

	if got := transport.request.URL.Query().Get("q"); got != "198.51.100.7" {
		t.Errorf("q = %q, want %q", got, "198.51.100.7")
	}
}
