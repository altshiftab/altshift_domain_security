package dmarc

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	altshiftDmarc "github.com/altshiftab/utils_go/pkg/dns/dmarc"
	"github.com/miekg/dns"
)

// fakeDns is an in-memory DmarcLookup. records maps name → record string
// (already filtered by the v=DMARC1 prefix); errs maps name → error to return.
type fakeDns struct {
	records map[string]string
	errs    map[string]error
}

func (f *fakeDns) GetDmarcRecordStringWithSubdomain(_ context.Context, name string) (string, error) {
	if err, ok := f.errs[name]; ok {
		return "", err
	}
	return f.records[name], nil
}

func TestAnalyzeRecordReturnsNilProblemsForCleanRecord(t *testing.T) {
	t.Parallel()

	problems, err := AnalyzeRecord(
		context.Background(),
		&altshiftDmarc.Record{
			Domain: "example.com",
			Raw:    "v=DMARC1; p=reject",
			P:      "reject",
		},
		&fakeDns{},
	)
	if err != nil {
		t.Fatalf("analyze record: %v", err)
	}

	if problems != nil {
		t.Fatalf("problems should be nil when empty, got %v", problems)
	}
}

func TestExtractMailToDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantDomains  []string
		wantProblems int
	}{
		{
			name:        "single mailto",
			input:       "mailto:a@example.com",
			wantDomains: []string{"example.com"},
		},
		{
			name:        "multiple mailtos with whitespace",
			input:       "mailto:a@Example.com , mailto:b@SUB.example.org",
			wantDomains: []string{"example.com", "sub.example.org"},
		},
		{
			name:        "size suffix is stripped before parsing",
			input:       "mailto:a@example.com!10m, mailto:b@example.org!100k",
			wantDomains: []string{"example.com", "example.org"},
		},
		{
			name:        "case-insensitive mailto scheme",
			input:       "MailTo:a@example.com",
			wantDomains: []string{"example.com"},
		},
		{
			name:         "invalid email surfaces a problem",
			input:        "mailto:not-an-email",
			wantProblems: 1,
		},
		{
			name:        "non-mailto URI is ignored",
			input:       "https://example.com/report",
			wantDomains: nil,
		},
		{
			name:         "mixed valid and invalid",
			input:        "mailto:ok@example.com, mailto:@bad",
			wantDomains:  []string{"example.com"},
			wantProblems: 1,
		},
		{
			name:        "empty input",
			input:       "",
			wantDomains: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotDomains, gotProblems := extractMailToDomains(tt.input)
			if !reflect.DeepEqual(gotDomains, tt.wantDomains) {
				t.Errorf("domains: got %v want %v", gotDomains, tt.wantDomains)
			}
			if len(gotProblems) != tt.wantProblems {
				t.Errorf("problems: got %d want %d", len(gotProblems), tt.wantProblems)
			}
		})
	}
}

func TestRuleIdMappingsAreComplete(t *testing.T) {
	t.Parallel()

	ids := []string{
		rule_id.SyntaxError,
		rule_id.MultipleRecords,
		rule_id.InsufficientP,
		rule_id.InvalidEmailAddress,
		rule_id.MissingExternalRecipientVerification,
		rule_id.Non100Pct,
		rule_id.InsufficientSP,
		rule_id.MissingRecord,
	}
	for _, id := range ids {
		if rule_id_mappings.RuleIdToTitle[id] == "" {
			t.Errorf("missing title for %q", id)
		}
		if rule_id_mappings.RuleIdToDescription[id] == "" {
			t.Errorf("missing description for %q", id)
		}
		if rule_id_mappings.RuleIdToSeverity[id] == "" {
			t.Errorf("missing severity for %q", id)
		}
	}
}

func TestMakeRuleIdProblem(t *testing.T) {
	t.Parallel()

	t.Run("known rule id is fully populated", func(t *testing.T) {
		t.Parallel()
		p := MakeRuleIdProblem(rule_id.InsufficientP)
		if p == nil {
			t.Fatal("nil problem")
		}
		if p.Id != rule_id.InsufficientP {
			t.Errorf("Id: got %q", p.Id)
		}
		if p.Title == "" || p.Description == "" || p.Severity == "" {
			t.Errorf("expected populated mappings, got %+v", p)
		}
	})

	t.Run("unknown rule id has only Id set", func(t *testing.T) {
		t.Parallel()
		p := MakeRuleIdProblem("does_not_exist")
		if p.Id != "does_not_exist" {
			t.Errorf("Id: got %q", p.Id)
		}
		if p.Title != "" || p.Description != "" || p.Severity != "" {
			t.Errorf("expected blank mappings, got %+v", p)
		}
	})
}

func problemIds(problems []*problemTypes.Problem) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.Id)
	}
	return out
}

func containsId(problems []*problemTypes.Problem, id string) bool {
	for _, p := range problems {
		if p.Id == id {
			return true
		}
	}
	return false
}

func TestAnalyzeRecord_NilDnsClient(t *testing.T) {
	t.Parallel()
	_, err := AnalyzeRecord(context.Background(), &altshiftDmarc.Record{P: "reject"}, nil)
	if err == nil {
		t.Fatal("expected error for nil dns client")
	}
}

func TestAnalyzeRecord_NilRecord(t *testing.T) {
	t.Parallel()
	problems, err := AnalyzeRecord(context.Background(), nil, &fakeDns{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if problems != nil {
		t.Fatalf("expected nil problems, got %v", problems)
	}
}

func TestAnalyzeRecord_CanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := AnalyzeRecord(ctx, &altshiftDmarc.Record{P: "reject"}, &fakeDns{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestAnalyzeRecord_PolicyAndPctProblems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		record      *altshiftDmarc.Record
		wantIds     []string
		forbiddenId []string
	}{
		{
			name:    "default p (empty) flags InsufficientP",
			record:  &altshiftDmarc.Record{Domain: "example.com"},
			wantIds: []string{rule_id.InsufficientP},
		},
		{
			name:    "p=none flags InsufficientP",
			record:  &altshiftDmarc.Record{Domain: "example.com", P: "none"},
			wantIds: []string{rule_id.InsufficientP},
		},
		{
			name:        "p=quarantine clean",
			record:      &altshiftDmarc.Record{Domain: "example.com", P: "quarantine"},
			forbiddenId: []string{rule_id.InsufficientP},
		},
		{
			name:    "sp=none flags InsufficientSP",
			record:  &altshiftDmarc.Record{Domain: "example.com", P: "reject", Sp: "none"},
			wantIds: []string{rule_id.InsufficientSP},
		},
		{
			name:        "sp=reject clean",
			record:      &altshiftDmarc.Record{Domain: "example.com", P: "reject", Sp: "reject"},
			forbiddenId: []string{rule_id.InsufficientSP},
		},
		{
			name:        "sp empty does not flag InsufficientSP",
			record:      &altshiftDmarc.Record{Domain: "example.com", P: "reject"},
			forbiddenId: []string{rule_id.InsufficientSP},
		},
		{
			name:    "pct=50 flags Non100Pct",
			record:  &altshiftDmarc.Record{Domain: "example.com", P: "reject", Pct: "50"},
			wantIds: []string{rule_id.Non100Pct},
		},
		{
			name:        "pct=100 clean",
			record:      &altshiftDmarc.Record{Domain: "example.com", P: "reject", Pct: "100"},
			forbiddenId: []string{rule_id.Non100Pct},
		},
		{
			name:        "pct empty clean",
			record:      &altshiftDmarc.Record{Domain: "example.com", P: "reject"},
			forbiddenId: []string{rule_id.Non100Pct},
		},
		{
			name: "weak everything fans out problems",
			record: &altshiftDmarc.Record{
				Domain: "example.com",
				P:      "none",
				Sp:     "none",
				Pct:    "10",
			},
			wantIds: []string{rule_id.InsufficientP, rule_id.InsufficientSP, rule_id.Non100Pct},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			problems, err := AnalyzeRecord(context.Background(), tt.record, &fakeDns{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, id := range tt.wantIds {
				if !containsId(problems, id) {
					t.Errorf("expected %q in %v", id, problemIds(problems))
				}
			}
			for _, id := range tt.forbiddenId {
				if containsId(problems, id) {
					t.Errorf("did not expect %q in %v", id, problemIds(problems))
				}
			}
		})
	}
}

func TestAnalyzeRecord_InvalidMailtoFlagsProblem(t *testing.T) {
	t.Parallel()

	record := &altshiftDmarc.Record{
		Domain: "example.com",
		P:      "reject",
		Rua:    "mailto:not-an-email",
	}
	problems, err := AnalyzeRecord(context.Background(), record, &fakeDns{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsId(problems, rule_id.InvalidEmailAddress) {
		t.Errorf("expected InvalidEmailAddress, got %v", problemIds(problems))
	}
}

func TestAnalyzeRecord_SameDomainRecipientSkipsExternalLookup(t *testing.T) {
	t.Parallel()

	record := &altshiftDmarc.Record{
		Domain: "Example.com",
		P:      "reject",
		Rua:    "mailto:reports@EXAMPLE.com",
	}
	problems, err := AnalyzeRecord(context.Background(), record, &fakeDns{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsId(problems, rule_id.MissingExternalRecipientVerification) {
		t.Errorf("did not expect external verification problem for same-domain recipient")
	}
}

func TestAnalyzeRecord_ExternalRecipientVerified(t *testing.T) {
	t.Parallel()

	fake := &fakeDns{records: map[string]string{
		"example.com._report._dmarc.reports.test": "v=DMARC1",
	}}
	record := &altshiftDmarc.Record{
		Domain: "example.com",
		P:      "reject",
		Rua:    "mailto:agg@reports.test",
	}
	problems, err := AnalyzeRecord(context.Background(), record, fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsId(problems, rule_id.MissingExternalRecipientVerification) {
		t.Errorf("did not expect verification problem when authorized; got %v", problemIds(problems))
	}
}

func TestAnalyzeRecord_ExternalRecipientUnverified(t *testing.T) {
	t.Parallel()

	record := &altshiftDmarc.Record{
		Domain: "example.com",
		P:      "reject",
		Rua:    "mailto:agg@reports.test",
	}
	problems, err := AnalyzeRecord(context.Background(), record, &fakeDns{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsId(problems, rule_id.MissingExternalRecipientVerification) {
		t.Errorf("expected verification problem; got %v", problemIds(problems))
	}
}

func TestAnalyzeRecord_ExternalRecipientLookupErrorIsLoggedNotReturned(t *testing.T) {
	t.Parallel()

	fake := &fakeDns{errs: map[string]error{
		"example.com._report._dmarc.reports.test": &dnsUtilsErrors.RcodeError{Rcode: dns.RcodeServerFailure},
	}}
	record := &altshiftDmarc.Record{
		Domain: "example.com",
		P:      "reject",
		Rua:    "mailto:agg@reports.test",
	}
	problems, err := AnalyzeRecord(context.Background(), record, fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if containsId(problems, rule_id.MissingExternalRecipientVerification) {
		t.Errorf("lookup error should not produce a verification problem; got %v", problemIds(problems))
	}
}

// startDnsServer runs a resolver that answers everything NXDOMAIN. What matters
// here is that a real exchange happens, since that is what writes the DNS
// context.
func startDnsServer(t *testing.T) *dnsUtilsClient.Client {
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
		message.Rcode = dns.RcodeNameError
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

// A record naming several external report domains verifies them concurrently.
// Each lookup must carry its own DNS context: dns_utils writes the exchange
// onto whichever one the context holds, without a lock, so sharing the caller's
// would have the goroutines race on one struct. Run under -race.
func TestAnalyzeRecord_ExternalRecipientsDoNotShareTheDnsContext(t *testing.T) {
	t.Parallel()

	client := startDnsServer(t)

	record := &altshiftDmarc.Record{
		Domain: "example.com",
		P:      "reject",
		Sp:     "reject",
		Rua:    "mailto:a@reporter-one.com,mailto:b@reporter-two.com,mailto:c@reporter-three.com",
		Ruf:    "mailto:d@reporter-four.com,mailto:e@reporter-five.com",
	}

	// The caller installs one DNS context, exactly as GetDomainSecurity does.
	ctx := dnsUtilsContext.WithDnsContext(t.Context())

	problems, err := AnalyzeRecord(ctx, record, client)
	if err != nil {
		t.Fatalf("AnalyzeRecord() = %v, want nil", err)
	}

	// Every external recipient is unverified against a resolver that answers
	// nothing, so each should be reported once.
	var unverified int
	for _, problem := range problems {
		if problem != nil && problem.Id == rule_id.MissingExternalRecipientVerification {
			unverified++
		}
	}
	if unverified != 5 {
		t.Errorf("unverified external recipients = %d, want 5", unverified)
	}
}
