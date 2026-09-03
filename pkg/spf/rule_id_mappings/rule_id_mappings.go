package rule_id_mappings

import (
	"fmt"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"

	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
)

var RuleIdToTitle = map[string]string{
	rule_id.SyntaxError:            "The data does not constitute a syntactically valid record",
	rule_id.MultipleRecords:        "Multiple SPF records",
	rule_id.MultipleAll:            "Multiple \"all\" directives",
	rule_id.InsufficientAll:        "The \"all\" directive is not using a sufficiently secure qualifier",
	rule_id.AllNotLast:             "The \"all\" directive is not the last term in the record",
	rule_id.RedirectPresentWithAll: "Both a \"redirect\" modifier and \"all\" directive are present",
	rule_id.RedirectNotLast:        "The \"redirect\" modifier is not the last term",
	rule_id.PtrUsed:                "A \"ptr\" mechanism is present",
	rule_id.TooManyLookups:         "The domain name lookup limit is exceeded when evaluating the record",
	rule_id.MissingRecord:          "Missing record",
	rule_id.UnacknowledgedNetwork:  "Unacknowledged network",
}

var RuleIdToDescription = map[string]string{
	rule_id.SyntaxError:            "The presented SPF record is not syntactically valid.",
	rule_id.MultipleRecords:        "Multiple SPF records were encountered for the domain. There should be only one.",
	rule_id.MultipleAll:            "Only a single \"all\" directive should be present, as the last term in a record.",
	rule_id.InsufficientAll:        "To effectively protect against abuse, an \"all\" directive should be using either the \"~\" (softfail) or \"-\" (fail) qualifiers.",
	rule_id.RedirectPresentWithAll: "When both a \"redirect\" modifier and \"all\" directive are present, the \"redirect\" modifier is ignored.",
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
	rule_id.PtrUsed:                problemTypes.SeverityInfo,
	rule_id.TooManyLookups:         problemTypes.SeverityHigh,
	rule_id.MissingRecord:          problemTypes.SeverityInfo,
	rule_id.UnacknowledgedNetwork:  problemTypes.SeverityMedium,
}
