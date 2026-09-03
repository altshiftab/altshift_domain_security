package dmarc

import (
	"context"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"sync"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftDmarc "github.com/altshiftab/utils_go/pkg/dns/dmarc"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

func MakeRuleIdProblem(ruleId string) *problemTypes.Problem {
	return &problemTypes.Problem{
		Id:          ruleId,
		Title:       rule_id_mappings.RuleIdToTitle[ruleId],
		Description: rule_id_mappings.RuleIdToDescription[ruleId],
		Severity:    rule_id_mappings.RuleIdToSeverity[ruleId],
	}
}

// mailtoScheme is the only URI scheme DMARC report addresses are read from.
const mailtoScheme = "mailto:"

func extractMailToDomains(recordValue string) ([]string, []*problemTypes.Problem) {
	var domains []string
	var problems []*problemTypes.Problem

	for _, uri := range strings.Split(recordValue, ",") {
		trimmedUri := strings.TrimSpace(uri)
		if len(trimmedUri) >= len(mailtoScheme) && strings.EqualFold(trimmedUri[:len(mailtoScheme)], mailtoScheme) {
			mailToValue := trimmedUri[len(mailtoScheme):]
			if i := strings.LastIndex(mailToValue, "!"); i >= 0 {
				mailToValue = mailToValue[:i]
			}
			mailAddress, err := mail.ParseAddress(mailToValue)
			if err != nil {
				problem := MakeRuleIdProblem(rule_id.InvalidEmailAddress)
				problem.Details = "Observed email address: " + mailToValue
				problems = append(problems, problem)
				continue
			}

			domain := mailAddress.Address[strings.LastIndex(mailAddress.Address, "@")+1:]
			domains = append(domains, strings.ToLower(domain))
		}
	}

	return domains, problems
}

func AnalyzeRecord(
	ctx context.Context,
	record *altshiftDmarc.Record,
	dnsLookup dnsUtilsClient.DmarcLookup,
) ([]*problemTypes.Problem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if dnsLookup == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns lookup"))
	}

	if record == nil {
		return nil, nil
	}

	var problems []*problemTypes.Problem

	if record.P != "reject" && record.P != "quarantine" {
		var policyValue string
		if record.P == "" {
			policyValue = "(unset, defaults to \"none\")"
		} else {
			policyValue = record.P
		}

		problem := MakeRuleIdProblem(rule_id.InsufficientP)
		problem.Details = "Encountered policy: " + policyValue
		problems = append(problems, problem)
	}

	if record.Sp != "" && (record.Sp != "reject" && record.Sp != "quarantine") {
		problem := MakeRuleIdProblem(rule_id.InsufficientSP)
		problem.Details = "Encountered policy: " + record.Sp
		problems = append(problems, problem)
	}

	if record.Pct != "" && record.Pct != "100" {
		problem := MakeRuleIdProblem(rule_id.Non100Pct)
		problem.Details = "Observed value: " + record.Pct
		problems = append(problems, problem)
	}

	domainsSet := make(map[string]bool)

	for _, recipient := range []string{record.Ruf, record.Rua} {
		if recipient == "" {
			continue
		}
		recipientDomains, recipientProblems := extractMailToDomains(recipient)
		problems = append(problems, recipientProblems...)
		for _, recipientDomain := range recipientDomains {
			if !strings.EqualFold(recipientDomain, record.Domain) {
				domainsSet[recipientDomain] = true
			}
		}
	}

	var problemsMutex sync.Mutex
	var waitGroup sync.WaitGroup

	for reportDomain := range domainsSet {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			// Each lookup gets its own DNS context. They share the caller's
			// otherwise, and dns_utils writes the exchange onto it without a
			// lock, so a record naming two external report domains would have
			// the two goroutines race on the one struct.
			lookupCtx := dnsUtilsContext.WithDnsContext(ctx)

			lookupName := fmt.Sprintf("%s._report._dmarc.%s", record.Domain, reportDomain)
			reportRecordString, err := dnsLookup.GetDmarcRecordStringWithSubdomain(lookupCtx, lookupName)
			if err != nil {
				slog.ErrorContext(
					altshiftContext.WithError(
						lookupCtx,
						altshiftErrors.New(
							fmt.Errorf("get record string with subdomain: %w", err),
							lookupName,
						),
					),
					"An error occurred when retrieving a DMARC report record.",
				)
				return
			}
			if reportRecordString == "" {
				problemsMutex.Lock()
				problem := MakeRuleIdProblem(rule_id.MissingExternalRecipientVerification)
				problem.Details = "Affected domain: " + reportDomain
				problems = append(problems, problem)
				problemsMutex.Unlock()
			}
		}()
	}

	waitGroup.Wait()

	return problems, nil
}
