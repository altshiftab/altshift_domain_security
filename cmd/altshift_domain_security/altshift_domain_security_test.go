package main

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
)

func TestParseNetworks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{name: "empty", input: "", expected: nil},
		{name: "one network", input: "192.0.2.0/24", expected: []string{"192.0.2.0/24"}},
		{
			name:     "surrounding space and empty entries are tolerated",
			input:    " 192.0.2.0/24 , ,198.51.100.0/24 ",
			expected: []string{"192.0.2.0/24", "198.51.100.0/24"},
		},
		{name: "an ipv6 network", input: "2001:db8::/32", expected: []string{"2001:db8::/32"}},
		{name: "a malformed entry is an error", input: "192.0.2.0/24,nonsense", wantErr: true},
		{name: "a bare address is not a network", input: "192.0.2.1", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			networks, err := parseNetworks(testCase.input)

			if testCase.wantErr {
				if err == nil {
					t.Fatalf("parseNetworks(%q) = nil error, want an error", testCase.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseNetworks(%q) = %v, want nil", testCase.input, err)
			}

			got := make([]string, 0, len(networks))
			for _, network := range networks {
				got = append(got, network.String())
			}

			expected := make([]string, 0, len(testCase.expected))
			for _, cidr := range testCase.expected {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatalf("net parse cidr: %v", err)
				}
				expected = append(expected, network.String())
			}

			if !slices.Equal(got, expected) {
				t.Errorf("parseNetworks(%q) = %v, want %v", testCase.input, got, expected)
			}
		})
	}
}

func TestParseList(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{name: "empty", input: "", expected: nil},
		{name: "only separators", input: ",,,", expected: nil},
		{name: "one value", input: "selector1", expected: []string{"selector1"}},
		{name: "several values", input: "k1,k2", expected: []string{"k1", "k2"}},
		{
			name:     "surrounding space and empty entries are dropped",
			input:    " k1 , , k2 ,",
			expected: []string{"k1", "k2"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := parseList(testCase.input); !slices.Equal(got, testCase.expected) {
				t.Errorf("parseList(%q) = %v, want %v", testCase.input, got, testCase.expected)
			}
		})
	}
}

func TestWriteJson(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value any
	}{
		{name: "a map", value: map[string]string{"domain": "example.com"}},
		{name: "a slice", value: []string{"one", "two"}},
		{name: "nil", value: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// writeJson writes to stdout; what matters here is that it accepts
			// the value and reports no error for anything marshallable.
			if err := writeJson(testCase.value); err != nil {
				t.Errorf("writeJson(%v) = %v, want nil", testCase.value, err)
			}
		})
	}
}

func TestWriteJson_UnmarshallableValue(t *testing.T) {
	t.Parallel()

	// A channel cannot be marshalled, and the failure must be reported rather
	// than written as a partial document.
	if err := writeJson(make(chan int)); err == nil {
		t.Error("writeJson(chan) = nil error, want an error")
	}
}

func TestCommandRecordsDispatch(t *testing.T) {
	t.Parallel()

	// The parser does not report which subcommand it dispatched to, so the
	// wrapper has to.
	var value string
	subcommand := newCommand(newTestParser(&value))

	if subcommand.invoked {
		t.Error("invoked = true before parsing")
	}

	if err := subcommand.ParseArgs([]string{"example.com"}); err != nil {
		t.Fatalf("ParseArgs() = %v, want nil", err)
	}

	if !subcommand.invoked {
		t.Error("invoked = false after parsing")
	}
	if value != "example.com" {
		t.Errorf("value = %q, want %q", value, "example.com")
	}
}

func TestJsonRoundTripsThroughWriteJsonEncoding(t *testing.T) {
	t.Parallel()

	// The CLI's output has to be readable by anything consuming its stdout.
	data, err := json.Marshal(map[string]any{"domain": "example.com"}, json.Deterministic(true))
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	if decoded["domain"] != "example.com" {
		t.Errorf("domain = %v, want example.com", decoded["domain"])
	}
}

// newTestParser is the smallest parser that can stand in as a subcommand: one
// required positional, bound to the caller's variable.
func newTestParser(value *string) *argument_parser.Parser {
	return &argument_parser.Parser{
		Command:     "test",
		Description: "A parser for the wrapper's own test.",
		Positionals: []option.Option{
			option.WithMetavar(
				option.NewStringOption(0, "", "A value.", true, value),
				"VALUE",
			),
		},
	}
}

// exitUsage ends the process, so it is exercised in one: the test binary
// re-invokes itself with a marker in the environment, runs the branch, and the
// parent checks what came out.
const exitUsageMarker = "MOTMEDEL_DOMAIN_SECURITY_TEST_EXIT_USAGE"

func TestExitUsage(t *testing.T) {
	if os.Getenv(exitUsageMarker) == "1" {
		exitUsage(
			&argument_parser.Parser{
				ProgramName: "mds",
				Description: "A parser for the exit path's own test.",
				Parsers:     []argument_parser.Subparser{newCommand(newTestParser(new(string)))},
			},
			errNoCommand,
		)

		return
	}

	t.Parallel()

	// os.Args[0] is this test binary, not anything a caller supplied; re-running
	// it is how a branch that ends the process is exercised at all.
	// #nosec G204 G702
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExitUsage$")
	command.Env = append(os.Environ(), exitUsageMarker+"=1")

	var stderr bytes.Buffer
	command.Stderr = &stderr

	err := command.Run()

	// A bad invocation leaves through status 2, as a command-line program
	// conventionally does - not 1, which would read as the run having failed,
	// and not 0.
	exitError, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("the process left through %v, want a non-zero exit", err)
	}
	if code := exitError.ExitCode(); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}

	output := stderr.String()

	// The usage line, then the program name and what went wrong. Anything
	// resembling a JSON log line means it was reported as a runtime failure
	// rather than as a bad invocation.
	for _, expected := range []string{"Usage: mds", "mds: error: ", errNoCommand.Error()} {
		if !strings.Contains(output, expected) {
			t.Errorf("stderr is missing %q\n---\n%s", expected, output)
		}
	}

	if strings.Contains(output, `"level":`) || strings.Contains(output, `"msg":`) {
		t.Errorf("a bad invocation was reported as a log entry\n---\n%s", output)
	}
}

func TestBadInvocationErrorsReadAsInstructions(t *testing.T) {
	t.Parallel()

	// These reach a person who mistyped a command, so they have to say what to
	// do rather than only what happened.
	testCases := []struct {
		name     string
		err      error
		contains string
	}{
		{name: "no command", err: errNoCommand, contains: "command"},
		{name: "no discovery source", err: errNoDiscoverySource, contains: "--whoisxml-key"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.err == nil {
				t.Fatal("the error is nil")
			}
			if !strings.Contains(testCase.err.Error(), testCase.contains) {
				t.Errorf("%q does not mention %q", testCase.err, testCase.contains)
			}
		})
	}
}

// The result goes to stdout and the log to stderr. They are separated in a
// subprocess because the logger writes through a package-level default, and
// because the invariant only means anything about the real file descriptors.
const streamsMarker = "MOTMEDEL_DOMAIN_SECURITY_TEST_STREAMS"

func TestResultAndLogUseSeparateStreams(t *testing.T) {
	if os.Getenv(streamsMarker) == "1" {
		logger := newLogger()
		slog.SetDefault(logger.Logger)

		// A run that logs a warning and still produces a result - which is what
		// an assessment does whenever an auxiliary check fails.
		slog.Warn("An auxiliary check failed. Continuing.")

		if err := writeJson(map[string]string{"domain": "example.com"}); err != nil {
			t.Fatalf("writeJson() = %v", err)
		}

		return
	}

	t.Parallel()

	// os.Args[0] is this test binary, not anything a caller supplied.
	// #nosec G204 G702
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestResultAndLogUseSeparateStreams$")
	command.Env = append(os.Environ(), streamsMarker+"=1")

	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("the subprocess failed: %v\nstderr:\n%s", err, stderr.String())
	}

	// Everything on stdout that is not the test framework's own chatter must
	// parse, on its own, as the single result document.
	var documents []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "{") {
			documents = append(documents, line)
		}
	}

	if len(documents) != 1 {
		t.Fatalf("stdout carries %d JSON documents, want 1\n%s", len(documents), stdout.String())
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(documents[0]), &result); err != nil {
		t.Fatalf("the result does not parse: %v", err)
	}
	if result["domain"] != "example.com" {
		t.Errorf("result = %v, want the written document", result)
	}

	// And the warning must have gone the other way.
	if !strings.Contains(stderr.String(), "An auxiliary check failed") {
		t.Errorf("the warning is not on stderr\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "An auxiliary check failed") {
		t.Errorf("the warning leaked onto stdout\n%s", stdout.String())
	}
}
