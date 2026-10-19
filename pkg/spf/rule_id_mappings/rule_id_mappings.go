package rule_id_mappings

import (
	"fmt"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"

	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
)

// RuleIdToTitle names each problem with the record it is about, because a title
// is read on its own - in a list of findings from every mechanism, or as the
// subject of an alert - where "Missing record" says nothing.
var RuleIdToTitle = map[string]string{
	rule_id.SyntaxError:            "The SPF record is not syntactically valid",
	rule_id.MultipleRecords:        "Multiple SPF records",
	rule_id.MultipleAll:            "The SPF record has multiple \"all\" directives",
	rule_id.InsufficientAll:        "The \"all\" directive of the SPF record is not using a sufficiently secure qualifier",
	rule_id.AllNotLast:             "The \"all\" directive is not the last term in the SPF record",
	rule_id.RedirectPresentWithAll: "The SPF record has both a \"redirect\" modifier and an \"all\" directive",
	rule_id.MultipleRedirect:       "The SPF record has multiple \"redirect\" modifiers",
	rule_id.RedirectNotLast:        "The \"redirect\" modifier is not the last term in the SPF record",
	rule_id.PtrUsed:                "The SPF record uses a \"ptr\" mechanism",
	rule_id.TooManyLookups:         "The DNS lookup limit is exceeded when evaluating the SPF record",
	rule_id.MissingRecord:          "The domain has no SPF record",
	rule_id.UnacknowledgedNetwork:  "The SPF record permits an unacknowledged network",
}

var RuleIdToDescription = map[string]string{
	rule_id.SyntaxError:            "The presented SPF record is not syntactically valid.",
	rule_id.MultipleRecords:        "Multiple SPF records were encountered for the domain. There should be only one.",
	rule_id.MultipleAll:            "Only a single \"all\" directive should be present, as the last term in a record.",
	rule_id.InsufficientAll:        "To effectively protect against abuse, an \"all\" directive should be using either the \"~\" (softfail) or \"-\" (fail) qualifiers.",
	rule_id.AllNotLast:             "The \"all\" directive matches every sender, so the terms after it are never evaluated and have no effect.",
	rule_id.RedirectPresentWithAll: "When both a \"redirect\" modifier and \"all\" directive are present, the \"redirect\" modifier is ignored.",
	rule_id.MultipleRedirect:       "A \"redirect\" modifier may appear at most once in an SPF record. A record with more than one is invalid, and evaluating it ends in a permanent error.",
	rule_id.RedirectNotLast:        "The SPF RFC advises that a \"redirect\" modifier appear as the very last term in a record, for clarity.",
	rule_id.PtrUsed:                "The SPF RFC advises against use of the PTR mechanism in records: \"This mechanism is slow, it is not as reliable as other mechanisms in cases of DNS errors, and it places a large burden on the .arpa name servers\".",
	rule_id.TooManyLookups:         fmt.Sprintf("To avoid unreasonable load on the DNS, a maximum of %d terms causing domain name lookups are permitted in the evaluation of a record.", altshiftSpf.MaximumLookupLimit),
	rule_id.MissingRecord:          "The domain does not have an SPF record.",
	rule_id.UnacknowledgedNetwork:  "An unacknowledged network was observed among the permitted networks.",
}

var RuleIdToSeverity = map[string]string{
	rule_id.SyntaxError:            problemTypes.SeverityHigh,
	rule_id.MultipleRecords:        problemTypes.SeverityHigh,
	rule_id.MultipleAll:            problemTypes.SeverityLow,
	rule_id.InsufficientAll:        problemTypes.SeverityHigh,
	rule_id.AllNotLast:             problemTypes.SeverityLow,
	rule_id.RedirectPresentWithAll: problemTypes.SeverityLow,
	rule_id.MultipleRedirect:       problemTypes.SeverityHigh,
	rule_id.RedirectNotLast:        problemTypes.SeverityLow,
	rule_id.PtrUsed:                problemTypes.SeverityInfo,
	rule_id.TooManyLookups:         problemTypes.SeverityHigh,
	rule_id.MissingRecord:          problemTypes.SeverityInfo,
	rule_id.UnacknowledgedNetwork:  problemTypes.SeverityMedium,
}
