package spf

import (
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	"github.com/altshiftab/utils_go/pkg/dns/spf"
)

// TracedRecordWithProblems is one record reached while following an SPF
// record's include: and redirect= terms. DomainTrace records the path taken to
// reach it from the domain the analysis started at.
type TracedRecordWithProblems struct {
	Record      *spf.Record             `json:"record,omitzero"`
	DomainTrace []string                `json:"domain_trace" jsonschema:"domain_trace,minitems:0"`
	Problems    []*problemTypes.Problem `json:"problems" jsonschema:"problems,minitems:0"`
}
