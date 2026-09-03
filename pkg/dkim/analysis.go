package dkim

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	altshiftDkim "github.com/altshiftab/utils_go/pkg/dns/dkim"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

func MakeRuleIdProblem(ruleId string) *problemTypes.Problem {
	return &problemTypes.Problem{
		Id:          ruleId,
		Title:       rule_id_mappings.RuleIdToTitle[ruleId],
		Description: rule_id_mappings.RuleIdToDescription[ruleId],
		Severity:    rule_id_mappings.RuleIdToSeverity[ruleId],
	}
}

// minimumRsaKeyLength is the shortest RSA modulus a DKIM key may carry without
// being reported. RFC 8301 sets 1024 bits as the floor for a verifier.
const minimumRsaKeyLength = 1024

func Analyze(record *altshiftDkim.Record) ([]*problemTypes.Problem, error) {
	if record == nil {
		return nil, nil
	}

	var problems []*problemTypes.Problem

	for _, flag := range record.Flags {
		if strings.ToLower(flag) == "y" {
			problems = append(problems, MakeRuleIdProblem(rule_id.TestingDkimFlag))
			break
		}
	}

	publicKeyData := record.PublicKeyData
	keyType := record.GetKeyType()
	if publicKeyData != "" && strings.ToLower(keyType) == "rsa" {
		key, err := record.GetPublicKey()
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("get public key: %w", err), record)
		}

		// The record only claims the key is RSA - k= is self-reported, and
		// defaults to rsa when absent - while the key data is parsed as PKIX,
		// which yields whatever type was actually published. A record claiming
		// rsa and publishing an EC key is a record an assessed domain can
		// publish at will, so the assertion has to be the two-result form: the
		// one-result form would panic, inside a goroutine, taking the process
		// with it. There is no RSA modulus to measure on such a key, so the
		// length check simply does not apply.
		rsaPublicKey, ok := key.(*rsa.PublicKey)
		if ok && rsaPublicKey != nil {
			keyLength := rsaPublicKey.N.BitLen()
			if keyLength < minimumRsaKeyLength {
				problem := MakeRuleIdProblem(rule_id.TooSmallRsaKeyLength)
				problem.Details = fmt.Sprintf("Key length: %d bits.", keyLength)
				problems = append(problems, problem)
			}
		}
	}

	return problems, nil
}
