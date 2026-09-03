package spf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

func MakeRuleIdProblem(ruleId string) *problemTypes.Problem {
	return &problemTypes.Problem{
		Id:          ruleId,
		Title:       rule_id_mappings.RuleIdToTitle[ruleId],
		Description: rule_id_mappings.RuleIdToDescription[ruleId],
		Severity:    rule_id_mappings.RuleIdToSeverity[ruleId],
	}
}

func AnalyzeRecord(record *altshiftSpf.Record) ([]*problemTypes.Problem, int) {
	if record == nil {
		return nil, 0
	}

	var lookupCount int
	var problems []*problemTypes.Problem

	redirectPresent := false
	allPresent := false

	ruleIdSet := make(map[string]bool)

	for _, term := range record.Terms {
		switch typedTerm := term.(type) {
		case *altshiftSpf.Directive:
			directive := typedTerm
			if directive == nil {
				continue
			}

			if directive.Mechanism == nil {
				continue
			}

			switch strings.ToLower(directive.Mechanism.Label) {
			case "all":
				if allPresent {
					ruleIdSet[rule_id.MultipleAll] = true
				}

				allPresent = true

				trailingNonRedirect := false
				for _, laterTerm := range record.Terms[directive.Index+1:] {
					if mod, ok := laterTerm.(*altshiftSpf.Modifier); ok && mod != nil && strings.ToLower(mod.Label) == "redirect" {
						continue
					}
					trailingNonRedirect = true
					break
				}
				if trailingNonRedirect {
					ruleIdSet[rule_id.AllNotLast] = true
				}

				directiveQualifier := directive.Qualifier
				if directiveQualifier != altshiftSpf.SoftfailQualifier && directiveQualifier != altshiftSpf.FailQualifier {
					problem := MakeRuleIdProblem(rule_id.InsufficientAll)
					problem.Details = fmt.Sprintf("Encountered qualifier: %s", directiveQualifier)
					problems = append(problems, problem)
				}
			case "ptr":
				ruleIdSet[rule_id.PtrUsed] = true
				fallthrough
			case "include":
				fallthrough
			case "mx":
				fallthrough
			case "exists":
				fallthrough
			case "a":
				lookupCount += 1
			}
		case *altshiftSpf.Modifier:
			modifier := typedTerm
			if modifier == nil {
				continue
			}

			if strings.ToLower(modifier.Label) == "redirect" {
				if redirectPresent {
					ruleIdSet[rule_id.MultipleRedirect] = true
				}

				redirectPresent = true
				lookupCount += 1

				if modifier.Index != (len(record.Terms) - 1) {
					ruleIdSet[rule_id.RedirectNotLast] = true
				}
			}
		}
	}

	if allPresent && redirectPresent {
		ruleIdSet[rule_id.RedirectPresentWithAll] = true
	}

	for ruleId := range ruleIdSet {
		problems = append(problems, MakeRuleIdProblem(ruleId))
	}

	if !allPresent && !redirectPresent {
		problem := MakeRuleIdProblem(rule_id.InsufficientAll)
		problem.Details = fmt.Sprintf(
			"Encountered qualifier: (none, defaults to the %q qualifier i.e. neutral)",
			altshiftSpf.NeutralQualifier,
		)
		problems = append(problems, problem)
	}

	if lookupCount > altshiftSpf.MaximumLookupLimit {
		problem := MakeRuleIdProblem(rule_id.TooManyLookups)
		problem.Details = fmt.Sprintf("%d terms causing DNS lookups were observed.", lookupCount)
		problems = append(problems, problem)
	}

	return problems, lookupCount
}

func RecursiveAnalyzeRecord(
	ctx context.Context,
	mainDomain string,
	dnsClient *dnsUtilsClient.Client,
) ([]*spfTypes.TracedRecordWithProblems, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if dnsClient == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	if mainDomain == "" {
		return nil, nil
	}

	var records []*spfTypes.TracedRecordWithProblems

	accumulatedLookupCount := 0
	var recurseGetAndAnalyze func(context.Context, string, []string, bool) (bool, error)

	recurseGetAndAnalyze = func(ctx context.Context, domain string, domainTrace []string, isInclude bool) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		record, err := dnsClient.GetSpfRecord(ctx, domain)
		if err != nil {
			if errors.Is(err, dnsUtilsErrors.ErrMultipleRecords) {
				problem := MakeRuleIdProblem(rule_id.MultipleRecords)

				if multipleRecordsError, ok := errors.AsType[*dnsUtilsErrors.MultipleRecordsError](err); ok {
					var quotedTxtRecords []string
					for _, multipleRecord := range multipleRecordsError.Records {
						quotedTxtRecords = append(quotedTxtRecords, fmt.Sprintf("%q", multipleRecord))
					}
					problem.Details = fmt.Sprintf("Encountered records: %s", strings.Join(quotedTxtRecords, ", "))
				}

				records = append(
					records,
					&spfTypes.TracedRecordWithProblems{
						Record:      record,
						DomainTrace: domainTrace,
						Problems:    []*problemTypes.Problem{problem},
					},
				)

				return false, nil
			}

			if altshiftErrors.IsAny(err, altshiftErrors.ErrSyntaxError, altshiftErrors.ErrSemanticError) {
				if record == nil {
					return false, altshiftErrors.NewWithTrace(nil_error.New("record"))
				}

				problem := MakeRuleIdProblem(rule_id.SyntaxError)
				problem.Details = fmt.Sprintf("Encountered record: %q", record.Raw)

				records = append(
					records,
					&spfTypes.TracedRecordWithProblems{
						Record:      record,
						DomainTrace: domainTrace,
						Problems:    []*problemTypes.Problem{problem},
					},
				)

				return false, nil
			}

			return false, altshiftErrors.New(fmt.Errorf("get record: %w", err), domain, dnsClient)
		}
		if record == nil {
			missingRecordProblem := MakeRuleIdProblem(rule_id.MissingRecord)
			if missingRecordProblem == nil {
				return false, altshiftErrors.NewWithTrace(nil_error.New("problem"))
			}

			domainParts := domain_parts.New(domain)
			if domainParts == nil {
				return false, altshiftErrors.NewWithTrace(nil_error.New("domain breakdown"), domain)
			}

			if domain == domainParts.RegisteredDomain {
				missingRecordProblem.Severity = problemTypes.SeverityHigh
			}

			records = append(
				records,
				&spfTypes.TracedRecordWithProblems{
					DomainTrace: domainTrace,
					Problems:    []*problemTypes.Problem{missingRecordProblem},
				},
			)
			return false, nil
		}

		problems, lookupCount := AnalyzeRecord(record)

		if isInclude {
			var includeProblems []*problemTypes.Problem
			for _, problem := range problems {
				if !slices.Contains([]string{rule_id.InsufficientAll, rule_id.MultipleAll, rule_id.AllNotLast}, problem.Id) {
					includeProblems = append(includeProblems, problem)
				}
			}
			problems = includeProblems
		}

		records = append(
			records,
			&spfTypes.TracedRecordWithProblems{Record: record, DomainTrace: domainTrace, Problems: problems},
		)

		accumulatedLookupCount += lookupCount

		if accumulatedLookupCount > altshiftSpf.MaximumLookupLimit {
			if domain != mainDomain {
				problem := MakeRuleIdProblem(rule_id.TooManyLookups)
				problem.Details = fmt.Sprintf("%d terms causing DNS lookups were observed when evaluating the record recursively.", accumulatedLookupCount)
				records[0].Problems = append(records[0].Problems, problem)
			}
			return true, nil
		}

		for _, includeValue := range altshiftSpf.ExtractIncludeValues(record) {
			done, err := recurseGetAndAnalyze(ctx, includeValue, append(slices.Clone(domainTrace), includeValue), true)
			if err != nil {
				return done, altshiftErrors.New(
					fmt.Errorf("recurse get and analyze (include record): %w", err),
					includeValue,
				)
			}
			if done {
				return done, nil
			}
		}

		for _, redirectValue := range altshiftSpf.ExtractRedirectValues(record) {
			done, err := recurseGetAndAnalyze(ctx, redirectValue, append(slices.Clone(domainTrace), redirectValue), isInclude)
			if err != nil {
				return done, altshiftErrors.New(
					fmt.Errorf("recurse get and analyze (redirect record): %w", err),
					redirectValue,
				)
			}
			if done {
				return done, nil
			}
		}

		return false, nil
	}

	_, err := recurseGetAndAnalyze(ctx, mainDomain, []string{mainDomain}, false)
	if err != nil {
		return records, fmt.Errorf("recurse get and analyze (main record): %w", err)
	}

	return records, nil
}
