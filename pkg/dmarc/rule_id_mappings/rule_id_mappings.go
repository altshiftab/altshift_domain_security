package rule_id_mappings

import (
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
)

// RuleIdToTitle names each problem with the record it is about; see the SPF
// table for why.
var RuleIdToTitle = map[string]string{
	rule_id.SyntaxError:                          "The DMARC record is not syntactically valid",
	rule_id.MultipleRecords:                      "Multiple DMARC records",
	rule_id.InsufficientP:                        "The p tag (Requested Mail Receiver policy) of the DMARC record is not using a sufficiently secure value",
	rule_id.InvalidEmailAddress:                  "The DMARC record has an invalid report recipient email address",
	rule_id.MissingExternalRecipientVerification: "A domain of an email address of a DMARC report recipient has not authorized the domain of the DMARC record",
	rule_id.Non100Pct:                            "The pct tag of the DMARC record is not set to \"100\"",
	rule_id.InsufficientSP:                       "The sp tag (Requested Mail Receiver policy for subdomains) of the DMARC record is not using a sufficiently secure value",
	rule_id.MissingRecord:                        "The domain has no DMARC record",
}

var RuleIdToDescription = map[string]string{
	rule_id.SyntaxError:                          "The presented DMARC record is not syntactically valid.",
	rule_id.MultipleRecords:                      "Multiple DMARC records were encountered for the domain. There should be only one.",
	rule_id.InsufficientP:                        "To effectively protect the domain against abuse, the p tag should be set to either the \"reject\" or \"quarantine\" values.",
	rule_id.InvalidEmailAddress:                  "A specified email address of a DMARC report recipient is not in a valid format",
	rule_id.MissingExternalRecipientVerification: "To send reports to an external domain, the external domain must authorize the record domain with a DNS TXT record either explicitly with a name like \"DOMAIN._report._dmarc.EXTERNAL_DOMAIN\" or with a wildcard name \"*._report._dmarc.EXTERNAL_DOMAIN\". The record must start with the DMARC prefix \"v=DMARC1\".",
	rule_id.Non100Pct:                            "The pct tag specifies the percentage of messages from the Domain Owner's mail stream to which the DMARC policy is to be applied. For security, the policy should apply to all messages, which is the case when the value is set to \"100\" or the tag is omitted.",
	rule_id.InsufficientSP:                       "To effectively protect subdomains against abuse, the sp tag should be set to either the \"reject\" or \"quarantine\" values.",
	rule_id.MissingRecord:                        "The domain does not have a DMARC record, so receivers are not told what to do with mail that fails authentication in its name.",
}

var RuleIdToSeverity = map[string]string{
	rule_id.SyntaxError:                          problemTypes.SeverityHigh,
	rule_id.MultipleRecords:                      problemTypes.SeverityHigh,
	rule_id.InsufficientP:                        problemTypes.SeverityHigh,
	rule_id.InvalidEmailAddress:                  problemTypes.SeverityLow,
	rule_id.MissingExternalRecipientVerification: problemTypes.SeverityLow,
	rule_id.Non100Pct:                            problemTypes.SeverityMedium,
	rule_id.InsufficientSP:                       problemTypes.SeverityHigh,
	rule_id.MissingRecord:                        problemTypes.SeverityInfo,
}
