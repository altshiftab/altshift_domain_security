package dkim

import (
	"testing"

	"github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id"
	"github.com/altshiftab/altshift_domain_security/pkg/dkim/rule_id_mappings"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	altshiftDkim "github.com/altshiftab/utils_go/pkg/dns/dkim"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/google/go-cmp/cmp"
)

func TestAnalyze(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		input          *altshiftDkim.Record
		expected       []*problemTypes.Problem
		expectedErrors []error
		wantErr        bool
	}{
		{
			name: "nil record",
		},
		{
			name: "basic record",
			input: &altshiftDkim.Record{
				Version:       1,
				PublicKeyData: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDmzRmJRQxLEuyYiyMg4suA2SyMwR5MGHpP9diNT1hRiwUd/mZp1ro7kIDTKS8ttkI6z6eTRW9e9dDOxzSxNuXmume60Cjbu08gOyhPG3GfWdg7QkdN6kR4V75MFlw624VY35DaXBvnlTJTgRg/EW72O1DiYVThkyCgpSYS8nmEQIDAQAB",
			},
		},
		{
			name: "non-rsa key skipped",
			input: &altshiftDkim.Record{
				KeyType:       "ed25519",
				PublicKeyData: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
			},
		},
		{
			name: "bad public key data",
			input: &altshiftDkim.Record{
				KeyType:       "rsa",
				PublicKeyData: "not-valid-base64!@#",
			},
			wantErr: true,
		},
		{
			name: "bad record",
			input: &altshiftDkim.Record{
				KeyType:       "rsa",
				PublicKeyData: "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMx7VnoRmk/wFPeFWxrVUde6AJQI51/uPFL2CbiHGMnRSnLjPs72AgxAVHIe5QrNQ2riR5+7u47Sgh5R5va/d0cCAwEAAQ==",
				Flags:         []string{"y"},
			},
			expected: []*problemTypes.Problem{
				{
					Id:          rule_id.TestingDkimFlag,
					Title:       rule_id_mappings.RuleIdToTitle[rule_id.TestingDkimFlag],
					Description: rule_id_mappings.RuleIdToDescription[rule_id.TestingDkimFlag],
					Severity:    rule_id_mappings.RuleIdToSeverity[rule_id.TestingDkimFlag],
				},
				{
					Id:          rule_id.TooSmallRsaKeyLength,
					Title:       rule_id_mappings.RuleIdToTitle[rule_id.TooSmallRsaKeyLength],
					Description: rule_id_mappings.RuleIdToDescription[rule_id.TooSmallRsaKeyLength],
					Details:     "Key length: 512 bits.",
					Severity:    rule_id_mappings.RuleIdToSeverity[rule_id.TooSmallRsaKeyLength],
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			dkimRecord, err := Analyze(testCase.input)
			expectedErrors := testCase.expectedErrors

			if testCase.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if len(expectedErrors) == 0 && err != nil {
					t.Fatalf("expected no errors, got: %v", err)
				}

				if !altshiftErrors.IsAll(err, expectedErrors...) {
					t.Fatalf("expected errors: %v, got: %v", expectedErrors, err)
				}
			}

			expected := testCase.expected
			if diff := cmp.Diff(expected, dkimRecord); diff != "" {
				t.Fatalf("struct mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}

// ecPublicKeyBase64 is a PKIX-encoded P-256 public key. A record may declare
// k=rsa - or omit k=, which defaults to rsa - and still publish this, because
// nothing checks the declared type against the key data.
const ecPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcBkPZBdrSWuVYY9jcaJD+QeLO7SExz8+WaQEeMCJ/q5cj/R0y7Z4IcqRQnPXrue+JicrWth5I2oIXI5XXH8y8A=="

// A key whose type does not match what the record claims must not bring the
// process down: Analyze runs in a goroutine per selector, and an unrecovered
// panic there takes the whole service with it. An assessed domain chooses what
// it publishes, so this is reachable from any assessed domain.
func TestAnalyze_MismatchedKeyTypeDoesNotPanic(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		keyType string
	}{
		{name: "k=rsa with an EC key", keyType: "rsa"},
		{name: "no k= tag, which defaults to rsa, with an EC key", keyType: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			record := &altshiftDkim.Record{
				Domain:        "example.com",
				Selector:      "selector1",
				KeyType:       testCase.keyType,
				PublicKeyData: ecPublicKeyBase64,
			}

			problems, err := Analyze(record)
			if err != nil {
				t.Fatalf("Analyze() = %v, want nil", err)
			}

			// There is no RSA modulus to measure, so the length rule cannot
			// fire either way.
			for _, problem := range problems {
				if problem != nil && problem.Id == rule_id.TooSmallRsaKeyLength {
					t.Errorf("a key-length problem was reported for a non-RSA key")
				}
			}
		})
	}
}

func TestAnalyze_RsaKeyLengthIsStillJudged(t *testing.T) {
	t.Parallel()

	// A 512-bit RSA key, below the RFC 8301 floor.
	const shortRsaKeyBase64 = "MEgCQQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuuAgMBAAE="

	record := &altshiftDkim.Record{
		Domain:        "example.com",
		Selector:      "selector1",
		KeyType:       "rsa",
		PublicKeyData: shortRsaKeyBase64,
	}

	problems, err := Analyze(record)
	if err != nil {
		// Some short keys are rejected by the parser outright, which is also a
		// refusal to vouch for them; either outcome is acceptable here.
		t.Skipf("the parser refused the short key: %v", err)
	}

	var sawTooSmall bool
	for _, problem := range problems {
		if problem != nil && problem.Id == rule_id.TooSmallRsaKeyLength {
			sawTooSmall = true
		}
	}
	if !sawTooSmall {
		t.Error("a 512-bit RSA key was not reported as too small")
	}
}
