package rule_id_mappings

import (
	"github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
)

var RuleIdToTitle = map[string]string{
	rule_id.SyntaxError:          "The data does not constitute a syntactically valid record",
	rule_id.MultipleRecords:      "Multiple DKIM records",
	rule_id.TestingDkimFlag:      "Use of testing flag",
	rule_id.TooSmallRsaKeyLength: "The length of the RSA public key is too small",
}

var RuleIdToDescription = map[string]string{
	rule_id.SyntaxError:          "The presented DKIM record is not syntactically valid.",
	rule_id.MultipleRecords:      "Multiple DKIM records were encountered for the selector. There should be only one.",
	rule_id.TestingDkimFlag:      "The testing flag \"y\" was encountered in the record. When using DKIM in production, this flag should not be set.",
	rule_id.TooSmallRsaKeyLength: "The length of the RSA public key is too small; it must be at least 1024 bits long in order to be considered sufficiently strong against brute-forcing attacks.",
}

var RuleIdToSeverity = map[string]string{
	rule_id.SyntaxError:          problemTypes.SeverityHigh,
	rule_id.MultipleRecords:      problemTypes.SeverityHigh,
	rule_id.TestingDkimFlag:      problemTypes.SeverityInfo,
	rule_id.TooSmallRsaKeyLength: problemTypes.SeverityHigh,
}
