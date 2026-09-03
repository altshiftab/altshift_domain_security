package whoisxml

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	whoisXmlTypes "github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/whoisxml/types"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// recordingTransport answers with one canned body and keeps every request body
// it was given, so a test can check what was actually sent.
type recordingTransport struct {
	body string

	mutex         sync.Mutex
	methods       []string
	requestBodies []string
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var requestBody []byte
	if request.Body != nil {
		requestBody, _ = io.ReadAll(request.Body)
	}

	transport.mutex.Lock()
	transport.methods = append(transport.methods, request.Method)
	transport.requestBodies = append(transport.requestBodies, string(requestBody))
	transport.mutex.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(transport.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    request,
	}, nil
}

func (transport *recordingTransport) sentBodies() []string {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()

	return slices.Clone(transport.requestBodies)
}

func newStubbedFetchOption(body string) (fetch_config.Option, *recordingTransport) {
	transport := &recordingTransport{body: body}

	return fetch_config.WithHttpClient(&http.Client{Transport: transport}), transport
}

func TestQueryReverseWhois_NilRequestData(t *testing.T) {
	t.Parallel()

	option, _ := newStubbedFetchOption("{}")

	response, err := QueryReverseWhois(context.Background(), nil, option)
	if err == nil {
		t.Fatal("QueryReverseWhois() = nil error, want an error for nil request data")
	}
	if response != nil {
		t.Errorf("QueryReverseWhois() = %v, want nil", response)
	}
}

func TestQueryReverseWhois_PostsTheRequestAndDecodesTheResponse(t *testing.T) {
	t.Parallel()

	option, transport := newStubbedFetchOption(`{"domainsCount":2,"domainsList":["one.example.com","two.example.com"]}`)

	requestData := &whoisXmlTypes.ReverseWhoisRequest{
		ApiKey:     "secret",
		SearchType: SearchTypeCurrent,
		Mode:       ModePreview,
		AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
			{Field: "Email", Term: "*@example.com"},
		},
	}

	response, err := QueryReverseWhois(context.Background(), requestData, option)
	if err != nil {
		t.Fatalf("QueryReverseWhois() = %v, want nil", err)
	}
	if response == nil {
		t.Fatal("QueryReverseWhois() = nil, want a response")
	}

	if response.DomainsCount != 2 {
		t.Errorf("DomainsCount = %d, want 2", response.DomainsCount)
	}
	if !slices.Equal(response.DomainsList, []string{"one.example.com", "two.example.com"}) {
		t.Errorf("DomainsList = %v, want [one.example.com two.example.com]", response.DomainsList)
	}

	transport.mutex.Lock()
	methods := slices.Clone(transport.methods)
	transport.mutex.Unlock()

	if len(methods) != 1 || methods[0] != http.MethodPost {
		t.Errorf("methods = %v, want one POST", methods)
	}

	bodies := transport.sentBodies()
	if len(bodies) != 1 {
		t.Fatalf("len(bodies) = %d, want 1", len(bodies))
	}

	var sent whoisXmlTypes.ReverseWhoisRequest
	if err := json.Unmarshal([]byte(bodies[0]), &sent); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if sent.ApiKey != "secret" {
		t.Errorf("sent ApiKey = %q, want %q", sent.ApiKey, "secret")
	}
	if sent.Mode != ModePreview {
		t.Errorf("sent Mode = %q, want %q", sent.Mode, ModePreview)
	}
}

// A reverse-whois run issues these queries concurrently from one shared option
// slice. Adding the method with append would write into that slice's spare
// capacity, which every concurrent call shares, so the guarantee under test is
// that the caller's slice - including the capacity beyond its length - comes
// back untouched.
func TestQueryReverseWhois_ConcurrentCallsDoNotWriteTheCallersOptionSlice(t *testing.T) {
	t.Parallel()

	option, transport := newStubbedFetchOption(`{"domainsCount":0}`)

	// Spare capacity is what makes an aliasing bug reachable at all. Each slot
	// in it is filled with a sentinel that is distinguishable from the POST an
	// append would overwrite it with.
	const sentinelMethod = "SENTINEL"

	sharedOptions := make([]fetch_config.Option, 1, 8)
	sharedOptions[0] = option

	spare := sharedOptions[:cap(sharedOptions)]
	for i := 1; i < len(spare); i++ {
		spare[i] = fetch_config.WithMethod(sentinelMethod)
	}

	const numCalls = 16

	var waitGroup sync.WaitGroup
	for i := range numCalls {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			requestData := &whoisXmlTypes.ReverseWhoisRequest{
				ApiKey:     "secret",
				SearchType: SearchTypeCurrent,
				Mode:       ModePreview,
				AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
					{Field: "Email", Term: strings.Repeat("a", i+1) + "@example.com"},
				},
			}

			if _, err := QueryReverseWhois(context.Background(), requestData, sharedOptions...); err != nil {
				t.Errorf("QueryReverseWhois() = %v, want nil", err)
			}
		}()
	}

	waitGroup.Wait()

	// The caller's slice must be exactly as it was left.
	if len(sharedOptions) != 1 {
		t.Errorf("len(sharedOptions) = %d, want 1", len(sharedOptions))
	}

	for i := 1; i < len(spare); i++ {
		config := fetch_config.New(spare[i])
		if config.Method != sentinelMethod {
			t.Errorf(
				"spare capacity slot %d was overwritten (method = %q, want %q); "+
					"the queries are writing into the caller's option slice",
				i, config.Method, sentinelMethod,
			)
		}
	}

	// And every call must still have sent its own request intact.
	bodies := transport.sentBodies()
	if len(bodies) != numCalls {
		t.Fatalf("len(bodies) = %d, want %d", len(bodies), numCalls)
	}

	seenTerms := make(map[string]int, numCalls)
	for _, body := range bodies {
		var sent whoisXmlTypes.ReverseWhoisRequest
		if err := json.Unmarshal([]byte(body), &sent); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if len(sent.AdvancedSearchTerms) != 1 {
			t.Fatalf("len(AdvancedSearchTerms) = %d, want 1", len(sent.AdvancedSearchTerms))
		}
		seenTerms[sent.AdvancedSearchTerms[0].Term]++
	}

	if len(seenTerms) != numCalls {
		t.Errorf("distinct terms sent = %d, want %d", len(seenTerms), numCalls)
	}
}

// The method has to reach the request whether or not the caller supplied
// options of their own.
func TestQueryReverseWhois_MethodIsSetWithoutCallerOptions(t *testing.T) {
	t.Parallel()

	option, transport := newStubbedFetchOption(`{"domainsCount":0}`)

	requestData := &whoisXmlTypes.ReverseWhoisRequest{ApiKey: "secret", Mode: ModePreview}
	if _, err := QueryReverseWhois(context.Background(), requestData, option); err != nil {
		t.Fatalf("QueryReverseWhois() = %v, want nil", err)
	}

	transport.mutex.Lock()
	methods := slices.Clone(transport.methods)
	transport.mutex.Unlock()

	if len(methods) != 1 || methods[0] != http.MethodPost {
		t.Errorf("methods = %v, want one POST", methods)
	}
}
