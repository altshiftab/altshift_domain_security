package problem

import "testing"

func TestProblem_String(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		problem  *Problem
		expected string
	}{
		{
			name:     "nil problem",
			problem:  nil,
			expected: "",
		},
		{
			name:     "title only",
			problem:  &Problem{Title: "Missing record"},
			expected: "Missing record",
		},
		{
			name:     "title and description",
			problem:  &Problem{Title: "Missing record", Description: "No record was published."},
			expected: "Missing record\n\nNo record was published.",
		},
		{
			name:     "title and details",
			problem:  &Problem{Title: "Multiple records", Details: "Encountered 2."},
			expected: "Multiple records\n\nEncountered 2.",
		},
		{
			name: "all three",
			problem: &Problem{
				Title:       "Multiple records",
				Description: "Only one is permitted.",
				Details:     "Encountered 2.",
			},
			expected: "Multiple records\n\nOnly one is permitted.\n\nEncountered 2.",
		},
		{
			name:     "empty problem",
			problem:  &Problem{},
			expected: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.problem.String(); got != testCase.expected {
				t.Errorf("String() = %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestSeveritiesAreDistinct(t *testing.T) {
	t.Parallel()

	severities := []string{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	seen := make(map[string]bool, len(severities))
	for _, severity := range severities {
		if severity == "" {
			t.Error("a severity is empty")
		}
		if seen[severity] {
			t.Errorf("severity %q is declared more than once", severity)
		}
		seen[severity] = true
	}
}
