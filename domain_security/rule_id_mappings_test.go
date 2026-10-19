package domain_security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	dkimMappings "github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id_mappings"
	dmarcMappings "github.com/altshiftab/altshift_domain_security/pkg/dmarc/rule_id_mappings"
	spfMappings "github.com/altshiftab/altshift_domain_security/pkg/spf/rule_id_mappings"
)

// ruleIds reads the rule ids a rule_id package declares, from its source rather than from a list
// kept beside it, so that a rule added there without a title is caught here.
func ruleIds(t *testing.T, path string) []string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse file %s: %v", path, err)
	}

	var ids []string

	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}

		for _, spec := range general.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			for _, value := range valueSpec.Values {
				literal, ok := value.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}

				id, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", literal.Value, err)
				}

				ids = append(ids, id)
			}
		}
	}

	if len(ids) == 0 {
		t.Fatalf("no rule ids declared in %s", path)
	}

	return ids
}

// Every rule an analysis can raise has to be able to say what it is, and say it on its own: a
// finding is read in a list beside the other mechanisms', or as an alert's subject, where a title
// that does not name its record - "Missing record" - could be about any of them.
func TestEveryRuleIsTitledByItsRecord(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		ruleIdPath   string
		titles       map[string]string
		descriptions map[string]string
		severities   map[string]string
	}{
		{
			name:         "SPF",
			ruleIdPath:   filepath.Join("..", "pkg", "spf", "rule_id", "rule_id.go"),
			titles:       spfMappings.RuleIdToTitle,
			descriptions: spfMappings.RuleIdToDescription,
			severities:   spfMappings.RuleIdToSeverity,
		},
		{
			name:         "DMARC",
			ruleIdPath:   filepath.Join("..", "pkg", "dmarc", "rule_id", "rule_id.go"),
			titles:       dmarcMappings.RuleIdToTitle,
			descriptions: dmarcMappings.RuleIdToDescription,
			severities:   dmarcMappings.RuleIdToSeverity,
		},
		{
			name:         "DKIM",
			ruleIdPath:   filepath.Join("..", "pkg", "dkim", "rule_id", "rule_id.go"),
			titles:       dkimMappings.RuleIdToTitle,
			descriptions: dkimMappings.RuleIdToDescription,
			severities:   dkimMappings.RuleIdToSeverity,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for _, id := range ruleIds(t, testCase.ruleIdPath) {
				title := testCase.titles[id]
				if title == "" {
					t.Errorf("rule %q has no title", id)
				} else if !strings.Contains(title, testCase.name) {
					t.Errorf("the title of rule %q does not name the %s record: %q", id, testCase.name, title)
				}

				if testCase.descriptions[id] == "" {
					t.Errorf("rule %q has no description", id)
				}

				if testCase.severities[id] == "" {
					t.Errorf("rule %q has no severity", id)
				}
			}
		})
	}
}
