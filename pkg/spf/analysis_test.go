package spf

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
	"github.com/miekg/dns"
)

var dummyClient dnsUtilsClient.Client

func sortedProblemIds(problems []*problemTypes.Problem) []string {
	ids := make([]string, 0, len(problems))
	for _, p := range problems {
		ids = append(ids, p.Id)
	}
	sort.Strings(ids)
	return ids
}

func TestAnalyzeRecordReturnsNilProblemsForCleanRecord(t *testing.T) {
	t.Parallel()

	problems, lookupCount := AnalyzeRecord(
		&altshiftSpf.Record{
			Raw: "v=spf1 -all",
			Terms: []any{
				&altshiftSpf.Directive{
					Index:     0,
					Qualifier: "-",
					Mechanism: &altshiftSpf.Mechanism{Label: "all"},
				},
			},
		},
	)

	if problems != nil {
		t.Fatalf("problems should be nil when empty, got %v", problems)
	}
	if lookupCount != 0 {
		t.Fatalf("lookup count: got %d want 0", lookupCount)
	}
}

func TestAnalyzeRecord_NilRecord(t *testing.T) {
	t.Parallel()

	problems, lookupCount := AnalyzeRecord(nil)
	if problems != nil {
		t.Fatalf("problems: got %v want nil", problems)
	}
	if lookupCount != 0 {
		t.Fatalf("lookup count: got %d want 0", lookupCount)
	}
}

func TestAnalyzeRecord_TableDriven(t *testing.T) {
	t.Parallel()

	mech := func(label string) *altshiftSpf.Mechanism {
		return &altshiftSpf.Mechanism{Label: label}
	}
	dir := func(idx int, qualifier, label string) *altshiftSpf.Directive {
		return &altshiftSpf.Directive{Index: idx, Qualifier: qualifier, Mechanism: mech(label)}
	}
	mod := func(idx int, label, value string) *altshiftSpf.Modifier {
		return &altshiftSpf.Modifier{Index: idx, Label: label, Value: value}
	}

	cases := []struct {
		name            string
		terms           []any
		wantProblemIds  []string
		wantLookupCount int
	}{
		{
			name:            "no all no redirect → InsufficientAll",
			terms:           []any{dir(0, "+", "mx")},
			wantProblemIds:  []string{rule_id.InsufficientAll},
			wantLookupCount: 1,
		},
		{
			name:           "softfail all is OK",
			terms:          []any{dir(0, "~", "all")},
			wantProblemIds: []string{},
		},
		{
			name:           "fail all is OK",
			terms:          []any{dir(0, "-", "all")},
			wantProblemIds: []string{},
		},
		{
			name:           "neutral all → InsufficientAll",
			terms:          []any{dir(0, "?", "all")},
			wantProblemIds: []string{rule_id.InsufficientAll},
		},
		{
			name:           "default qualifier all (empty) → InsufficientAll",
			terms:          []any{dir(0, "", "all")},
			wantProblemIds: []string{rule_id.InsufficientAll},
		},
		{
			name:           "explicit pass +all → InsufficientAll",
			terms:          []any{dir(0, "+", "all")},
			wantProblemIds: []string{rule_id.InsufficientAll},
		},
		{
			name: "multiple all directives",
			terms: []any{
				dir(0, "-", "all"),
				dir(1, "-", "all"),
			},
			wantProblemIds: []string{rule_id.AllNotLast, rule_id.MultipleAll},
		},
		{
			name: "all not last when followed by directive",
			terms: []any{
				dir(0, "-", "all"),
				dir(1, "+", "mx"),
			},
			wantProblemIds:  []string{rule_id.AllNotLast},
			wantLookupCount: 1,
		},
		{
			name: "all followed only by redirect → no AllNotLast",
			terms: []any{
				dir(0, "+", "mx"),
				dir(1, "-", "all"),
				mod(2, "redirect", "_spf.example.com"),
			},
			wantProblemIds:  []string{rule_id.RedirectPresentWithAll},
			wantLookupCount: 2,
		},
		{
			name: "all followed by directive after redirect → AllNotLast and RedirectNotLast",
			terms: []any{
				dir(0, "-", "all"),
				mod(1, "redirect", "_spf.example.com"),
				dir(2, "+", "mx"),
			},
			wantProblemIds:  []string{rule_id.AllNotLast, rule_id.RedirectNotLast, rule_id.RedirectPresentWithAll},
			wantLookupCount: 2,
		},
		{
			name: "redirect present with all (redirect first)",
			terms: []any{
				mod(0, "redirect", "_spf.example.com"),
				dir(1, "-", "all"),
			},
			wantProblemIds:  []string{rule_id.RedirectNotLast, rule_id.RedirectPresentWithAll},
			wantLookupCount: 1,
		},
		{
			name: "redirect not last",
			terms: []any{
				mod(0, "redirect", "_spf.example.com"),
				dir(1, "+", "mx"),
			},
			wantProblemIds:  []string{rule_id.RedirectNotLast},
			wantLookupCount: 2,
		},
		{
			name: "multiple redirect modifiers",
			terms: []any{
				mod(0, "redirect", "_spf1.example.com"),
				mod(1, "redirect", "_spf2.example.com"),
			},
			wantProblemIds:  []string{rule_id.MultipleRedirect, rule_id.RedirectNotLast},
			wantLookupCount: 2,
		},
		{
			name: "ptr mechanism flagged",
			terms: []any{
				dir(0, "+", "ptr"),
				dir(1, "-", "all"),
			},
			wantProblemIds:  []string{rule_id.PtrUsed},
			wantLookupCount: 1,
		},
		{
			name: "lookup-causing terms count once each",
			terms: []any{
				dir(0, "+", "a"),
				dir(1, "+", "mx"),
				dir(2, "+", "ptr"),
				dir(3, "+", "include"),
				dir(4, "+", "exists"),
				dir(5, "+", "ip4"),
				dir(6, "+", "ip6"),
				dir(7, "-", "all"),
			},
			wantProblemIds:  []string{rule_id.PtrUsed},
			wantLookupCount: 5,
		},
		{
			name: "redirect counts as a lookup",
			terms: []any{
				dir(0, "+", "a"),
				mod(1, "redirect", "_spf.example.com"),
			},
			wantProblemIds:  []string{},
			wantLookupCount: 2,
		},
		{
			name: "too many lookups (11) triggers TooManyLookups",
			terms: []any{
				dir(0, "+", "a"),
				dir(1, "+", "a"),
				dir(2, "+", "a"),
				dir(3, "+", "a"),
				dir(4, "+", "a"),
				dir(5, "+", "a"),
				dir(6, "+", "a"),
				dir(7, "+", "a"),
				dir(8, "+", "a"),
				dir(9, "+", "a"),
				dir(10, "+", "a"),
				dir(11, "-", "all"),
			},
			wantProblemIds:  []string{rule_id.TooManyLookups},
			wantLookupCount: 11,
		},
		{
			name: "exactly 10 lookups does not trigger",
			terms: []any{
				dir(0, "+", "a"), dir(1, "+", "a"), dir(2, "+", "a"),
				dir(3, "+", "a"), dir(4, "+", "a"), dir(5, "+", "a"),
				dir(6, "+", "a"), dir(7, "+", "a"), dir(8, "+", "a"),
				dir(9, "+", "a"), dir(10, "-", "all"),
			},
			wantProblemIds:  []string{},
			wantLookupCount: 10,
		},
		{
			name: "case-insensitive labels",
			terms: []any{
				dir(0, "+", "MX"),
				dir(1, "+", "PTR"),
				mod(2, "REDIRECT", "_spf.example.com"),
				dir(3, "-", "ALL"),
			},
			wantProblemIds:  []string{rule_id.PtrUsed, rule_id.RedirectPresentWithAll, rule_id.RedirectNotLast},
			wantLookupCount: 3,
		},
		{
			name: "nil directive is skipped",
			terms: []any{
				(*altshiftSpf.Directive)(nil),
				dir(1, "-", "all"),
			},
			wantProblemIds: []string{},
		},
		{
			name: "directive with nil mechanism is skipped",
			terms: []any{
				&altshiftSpf.Directive{Index: 0, Qualifier: "+", Mechanism: nil},
				dir(1, "-", "all"),
			},
			wantProblemIds: []string{},
		},
		{
			name: "nil modifier is skipped",
			terms: []any{
				(*altshiftSpf.Modifier)(nil),
				dir(1, "-", "all"),
			},
			wantProblemIds: []string{},
		},
		{
			name: "unknown modifier label is ignored",
			terms: []any{
				mod(0, "exp", "explain._spf.example.com"),
				dir(1, "-", "all"),
			},
			wantProblemIds: []string{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			record := &altshiftSpf.Record{Terms: tc.terms}
			problems, lookupCount := AnalyzeRecord(record)

			gotIds := sortedProblemIds(problems)
			wantIds := append([]string(nil), tc.wantProblemIds...)
			sort.Strings(wantIds)

			if diff := altshiftTestingCmp.Diff(wantIds, gotIds, altshiftTestingCmp.EquateEmpty()); diff != "" {
				t.Fatalf("problem ids mismatch (-want +got):\n%s", diff)
			}
			if lookupCount != tc.wantLookupCount {
				t.Fatalf("lookup count: got %d want %d", lookupCount, tc.wantLookupCount)
			}
		})
	}
}

func TestAnalyzeRecord_InsufficientAllProblemDetailsIncludeQualifier(t *testing.T) {
	t.Parallel()

	problems, _ := AnalyzeRecord(
		&altshiftSpf.Record{
			Terms: []any{
				&altshiftSpf.Directive{
					Index:     0,
					Qualifier: "?",
					Mechanism: &altshiftSpf.Mechanism{Label: "all"},
				},
			},
		},
	)

	var found *problemTypes.Problem
	for _, p := range problems {
		if p.Id == rule_id.InsufficientAll {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatalf("expected InsufficientAll problem; got %v", sortedProblemIds(problems))
	}
	if !strings.Contains(found.Details, "?") {
		t.Fatalf("details should contain qualifier %q; got %q", "?", found.Details)
	}
}

func TestAnalyzeRecord_NoAllNoRedirectDetailsMentionsNeutral(t *testing.T) {
	t.Parallel()

	problems, _ := AnalyzeRecord(&altshiftSpf.Record{Terms: []any{}})
	if len(problems) != 1 || problems[0].Id != rule_id.InsufficientAll {
		t.Fatalf("expected single InsufficientAll problem; got %v", sortedProblemIds(problems))
	}
	if !strings.Contains(problems[0].Details, altshiftSpf.NeutralQualifier) {
		t.Fatalf("details should mention neutral qualifier %q; got %q", altshiftSpf.NeutralQualifier, problems[0].Details)
	}
}

func TestAnalyzeRecord_TooManyLookupsDetailsIncludeCount(t *testing.T) {
	t.Parallel()

	terms := []any{}
	for i := range 11 {
		terms = append(terms, &altshiftSpf.Directive{
			Index:     i,
			Qualifier: "+",
			Mechanism: &altshiftSpf.Mechanism{Label: "a"},
		})
	}
	terms = append(terms, &altshiftSpf.Directive{
		Index:     11,
		Qualifier: "-",
		Mechanism: &altshiftSpf.Mechanism{Label: "all"},
	})

	problems, lookupCount := AnalyzeRecord(&altshiftSpf.Record{Terms: terms})
	if lookupCount != 11 {
		t.Fatalf("lookup count: got %d want 11", lookupCount)
	}

	var found *problemTypes.Problem
	for _, p := range problems {
		if p.Id == rule_id.TooManyLookups {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatalf("expected TooManyLookups problem")
	}
	if !strings.Contains(found.Details, "11") {
		t.Fatalf("details should mention count 11; got %q", found.Details)
	}
}

func TestMakeRuleIdProblem(t *testing.T) {
	t.Parallel()

	t.Run("known rule populates fields from mappings", func(t *testing.T) {
		t.Parallel()

		problem := MakeRuleIdProblem(rule_id.PtrUsed)
		if problem == nil {
			t.Fatal("problem is nil")
		}
		if problem.Id != rule_id.PtrUsed {
			t.Fatalf("id: got %q want %q", problem.Id, rule_id.PtrUsed)
		}
		if problem.Title != rule_id_mappings.RuleIdToTitle[rule_id.PtrUsed] {
			t.Fatalf("title mismatch")
		}
		if problem.Description != rule_id_mappings.RuleIdToDescription[rule_id.PtrUsed] {
			t.Fatalf("description mismatch")
		}
		if problem.Severity != rule_id_mappings.RuleIdToSeverity[rule_id.PtrUsed] {
			t.Fatalf("severity mismatch")
		}
	})

	t.Run("unknown rule yields empty fields", func(t *testing.T) {
		t.Parallel()

		problem := MakeRuleIdProblem("does_not_exist")
		if problem == nil {
			t.Fatal("problem is nil")
		}
		if problem.Id != "does_not_exist" {
			t.Fatalf("id: got %q", problem.Id)
		}
		if problem.Title != "" || problem.Description != "" || problem.Severity != "" {
			t.Fatalf("expected zero-value strings; got %+v", problem)
		}
	})
}

func TestRecursiveAnalyzeRecord_Guards(t *testing.T) {
	t.Parallel()

	t.Run("cancelled context returns ctx error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		records, err := RecursiveAnalyzeRecord(ctx, "example.com", nil)
		if records != nil {
			t.Fatalf("records: got %v want nil", records)
		}
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err: got %v want context.Canceled", err)
		}
	})

	t.Run("nil dns client returns error", func(t *testing.T) {
		t.Parallel()

		records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", nil)
		if records != nil {
			t.Fatalf("records: got %v want nil", records)
		}
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("empty main domain returns nil result", func(t *testing.T) {
		t.Parallel()

		records, err := RecursiveAnalyzeRecord(context.Background(), "", &dummyClient)
		if err != nil {
			t.Fatalf("err: got %v want nil", err)
		}
		if records != nil {
			t.Fatalf("records: got %v want nil", records)
		}
	})
}

// fakeDNS serves TXT records from an in-memory map.
type fakeDNS struct {
	records map[string][]string
	server  *dns.Server
	conn    net.PacketConn
	addr    string
	wg      sync.WaitGroup
}

func newFakeDNS(t *testing.T, records map[string][]string) *fakeDNS {
	t.Helper()

	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	started := make(chan struct{})
	mux := dns.NewServeMux()
	server := &dns.Server{
		PacketConn:        pc,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}

	f := &fakeDNS{
		records: records,
		server:  server,
		conn:    pc,
		addr:    localAddr(t, pc),
	}

	mux.HandleFunc(".", f.handle)

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
		f.wg.Wait()
	})

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dns server failed to start")
	}

	return f
}

func (f *fakeDNS) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		name := strings.TrimSuffix(q.Name, ".")
		entries, ok := f.records[name]
		if !ok {
			m.Rcode = dns.RcodeNameError
			continue
		}
		if q.Qtype != dns.TypeTXT {
			continue
		}
		for _, entry := range entries {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{entry},
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	_ = w.WriteMsg(m)
}

func newClient(t *testing.T, fake *fakeDNS) *dnsUtilsClient.Client {
	t.Helper()
	return dnsUtilsClient.New(dnsUtilsClientConfig.WithAddress(fake.addr))
}

func problemIdSet(records []*spfTypes.TracedRecordWithProblems) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for _, rec := range records {
		domain := ""
		if rec.Record != nil {
			domain = rec.Record.Domain
		}
		if domain == "" && len(rec.DomainTrace) > 0 {
			domain = rec.DomainTrace[len(rec.DomainTrace)-1]
		}
		ids, ok := out[domain]
		if !ok {
			ids = make(map[string]bool)
			out[domain] = ids
		}
		for _, p := range rec.Problems {
			ids[p.Id] = true
		}
	}
	return out
}

func TestRecursiveAnalyzeRecord_SingleClean(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com": {"v=spf1 -all"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if len(records[0].Problems) != 0 {
		t.Fatalf("expected no problems; got %v", records[0].Problems)
	}
	if records[0].Record == nil || records[0].Record.Domain != "example.com" {
		t.Fatalf("record domain: got %v", records[0].Record)
	}
}

func TestRecursiveAnalyzeRecord_MissingRecordRegisteredDomainHigh(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if len(records[0].Problems) != 1 || records[0].Problems[0].Id != rule_id.MissingRecord {
		t.Fatalf("expected MissingRecord; got %v", records[0].Problems)
	}
	if records[0].Problems[0].Severity != "high" {
		t.Fatalf("severity for registered domain: got %q want high", records[0].Problems[0].Severity)
	}
}

func TestRecursiveAnalyzeRecord_MultipleRecords(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com": {"v=spf1 -all", "v=spf1 ~all"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if len(records[0].Problems) != 1 || records[0].Problems[0].Id != rule_id.MultipleRecords {
		t.Fatalf("expected MultipleRecords; got %v", records[0].Problems)
	}
}

func TestRecursiveAnalyzeRecord_SyntaxError(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com": {"v=spf1 garbage~~"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if len(records[0].Problems) != 1 || records[0].Problems[0].Id != rule_id.SyntaxError {
		t.Fatalf("expected SyntaxError; got %v", records[0].Problems)
	}
	if records[0].Record == nil || records[0].Record.Raw == "" {
		t.Fatalf("expected raw record retained; got %v", records[0].Record)
	}
}

func TestRecursiveAnalyzeRecord_FollowsIncludeAndStripsAllProblems(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com":           {"v=spf1 include:_spf.included.example -all"},
		"_spf.included.example": {"v=spf1 +mx"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records: got %d want 2", len(records))
	}

	byDomain := problemIdSet(records)

	// main record: include adds 1 lookup, all is sufficient → no problems
	if got := byDomain["example.com"]; len(got) != 0 {
		t.Fatalf("main domain problems: got %v want none", got)
	}

	// included record would have InsufficientAll, but it is filtered for includes
	included := byDomain["_spf.included.example"]
	if included[rule_id.InsufficientAll] {
		t.Fatalf("InsufficientAll should be filtered out for included records; got %v", included)
	}
}

func TestRecursiveAnalyzeRecord_FollowsRedirect(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com":         {"v=spf1 redirect=_spf.target.example"},
		"_spf.target.example": {"v=spf1 ip4:192.0.2.0/24 -all"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records: got %d want 2", len(records))
	}
}

func TestRecursiveAnalyzeRecord_TooManyLookupsAccumulated(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com": {"v=spf1 include:i1.example include:i2.example include:i3.example include:i4.example include:i5.example include:i6.example -all"},
		"i1.example":  {"v=spf1 +a +mx -all"},
		"i2.example":  {"v=spf1 +a +mx -all"},
		"i3.example":  {"v=spf1 +a +mx -all"},
		"i4.example":  {"v=spf1 +a +mx -all"},
		"i5.example":  {"v=spf1 +a +mx -all"},
		"i6.example":  {"v=spf1 +a +mx -all"},
	})
	client := newClient(t, fake)

	records, err := RecursiveAnalyzeRecord(context.Background(), "example.com", client)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var sawTooMany bool
	if len(records) == 0 {
		t.Fatal("no records were produced")
	}

	for _, p := range records[0].Problems {
		if p.Id == rule_id.TooManyLookups {
			sawTooMany = true
			break
		}
	}
	if !sawTooMany {
		t.Fatalf("expected TooManyLookups on main record; got %+v", records[0].Problems)
	}
}

func TestRecursiveAnalyzeRecord_CancelledMidway(t *testing.T) {
	t.Parallel()

	fake := newFakeDNS(t, map[string][]string{
		"example.com": {"v=spf1 -all"},
	})
	client := newClient(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	records, err := RecursiveAnalyzeRecord(ctx, "example.com", client)
	if err == nil {
		t.Fatalf("expected error from cancelled context; records=%v", records)
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
