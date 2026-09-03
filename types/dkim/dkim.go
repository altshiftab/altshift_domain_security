package dkim

import (
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	"github.com/altshiftab/utils_go/pkg/dns/dkim"
)

type RecordWithProblems struct {
	Record   *dkim.Record            `json:"record,omitzero"`
	Problems []*problemTypes.Problem `json:"problems,omitzero" jsonschema:"problems,minitems:0"`
}
