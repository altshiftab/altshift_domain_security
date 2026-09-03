// Command altshift_domain_security assesses a domain's email and DNS security
// posture, or discovers the domains that belong to the same owner.
package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	dnsUtilsClientConfig "github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/altshiftab/altshift_domain_security/domain_security"
	"github.com/altshiftab/altshift_domain_security/domain_security/domain_security_config"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery"
	"github.com/altshiftab/altshift_domain_security/pkg/discovery/discovery_config"
	domainTypes "github.com/altshiftab/altshift_domain_security/types/domain"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"
	"github.com/altshiftab/utils_go/pkg/log/http_logger"
	"github.com/altshiftab/utils_go/pkg/log/http_logger/http_logger_config"
)

// A bad invocation - as opposed to something going wrong during a run - is
// reported through the parser rather than the logger, so it reads the way every
// other command-line mistake does.
var (
	errNoCommand         = errors.New("a command is required")
	errNoDiscoverySource = errors.New(
		"no discovery source is available: give --whoisxml-key, --hackertarget-key, or both",
	)
)

// exitUsage reports a bad invocation the way the parser reports the ones it
// catches itself: the usage line, then the program name and what went wrong, on
// stderr, leaving through status 2. The parser cannot catch these two - it has
// no notion of a required subcommand, nor of options that are required only in
// combination - so they are raised here and rendered there.
func exitUsage(parser *argument_parser.Parser, err error) {
	fmt.Fprint(os.Stderr, parser.FormatError(err))
	os.Exit(2)
}

// command records which subcommand the parser dispatched to, which the parser
// itself does not report.
type command struct {
	*argument_parser.Parser
	invoked bool
}

func (c *command) ParseArgs(arguments []string) error {
	c.invoked = true
	return c.Parser.ParseArgs(arguments)
}

func newCommand(parser *argument_parser.Parser) *command {
	return &command{Parser: parser}
}

// defaultDnsPort is assumed when an address names no port, so --dns-server can
// be given as a bare address.
const defaultDnsPort = "53"

// newDnsClient builds the resolver a run queries through.
//
// With no address given, the host's own resolvers are read from its
// configuration. Note that passing the empty address through instead does not
// mean "use the default": WithAddress overwrites the configured default with
// the empty string, and every lookup then fails with "empty dns server".
//
// Reading the host's configuration is also the right default for a command-line
// tool. Falling back to the library's hardcoded public resolver would disclose
// every domain looked up to a third party, and answer from a view of DNS that
// is not the one the operator actually has.
func newDnsClient(ctx context.Context, address string) (*dnsUtilsClient.Client, error) {
	if address == "" {
		dnsServers, err := dns_utils.GetDnsServers(ctx)
		if err != nil {
			return nil, fmt.Errorf("get dns servers: %w", err)
		}
		if len(dnsServers) == 0 {
			return nil, altshiftErrors.NewWithTrace(empty_error.New("dns servers"))
		}

		address = dnsServers[0]
	}

	// SplitHostPort fails on an address carrying no port, and on a bare IPv6
	// address, both of which JoinHostPort then renders correctly.
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, defaultDnsPort)
	}

	return dnsUtilsClient.New(dnsUtilsClientConfig.WithAddress(address)), nil
}

// parseNetworks reads a comma-separated CIDR list.
func parseNetworks(networksString string) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	for _, networkString := range strings.Split(networksString, ",") {
		networkString = strings.TrimSpace(networkString)
		if networkString == "" {
			continue
		}

		_, network, err := net.ParseCIDR(networkString)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("net parse cidr: %w", err), networkString)
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// parseList reads a comma-separated list, dropping empty entries.
func parseList(listString string) []string {
	var values []string

	for _, value := range strings.Split(listString, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}

	return values
}

// writeJson writes the result to stdout, indented: the output is read by a
// person as often as it is piped into something.
func writeJson(value any) error {
	data, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), value)
	}

	if _, err := fmt.Fprintf(os.Stdout, "%s\n", data); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("fprintf: %w", err))
	}

	return nil
}

// newLogger builds the logger the command logs through.
//
// Entries go to stderr, not to the library's default of stdout: stdout carries
// the result, and a warning interleaved with it would leave the output
// unparseable by anything downstream. The backend keeps the default, since a
// service's stdout is exactly where its logs belong.
func newLogger() *altshiftErrorLogger.Logger {
	return http_logger.New(http_logger_config.WithWriter(os.Stderr))
}

func main() {
	logger := newLogger()
	slog.SetDefault(logger.Logger)

	var securityDomain string
	var securityDnsServer string
	var securityDkimSelectors string
	var securityAllowedNetworks string

	securityCommand := newCommand(
		&argument_parser.Parser{
			Command:     "security",
			Description: "Assess a domain's SPF, DKIM, DMARC, DNSSEC and registrar-lock posture.",
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(0, "", "The domain to assess.", true, &securityDomain),
					"DOMAIN",
				),
			},
			Options: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						0, "dns-server",
						"The DNS server to resolve through. Defaults to the system's.",
						false, &securityDnsServer,
					),
					"ADDRESS",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "dkim-selectors",
						"A comma-separated list of DKIM selectors to probe. DKIM offers no way to "+
							"enumerate them, so they can only be guessed at; defaults to a short "+
							"list covering the common providers.",
						false, &securityDkimSelectors,
					),
					"SELECTORS",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "allowed-networks",
						"A comma-separated list of CIDR blocks the domain is acknowledged to send "+
							"from. An SPF record authorising anything outside them is reported.",
						false, &securityAllowedNetworks,
					),
					"CIDRS",
				),
			},
		},
	)

	var discoveryDomain string
	var discoveryDnsServer string
	var discoveryWhoisXmlApiKey string
	var discoveryHackerTargetApiKey string
	var discoveryHistorical bool

	discoveryCommand := newCommand(
		&argument_parser.Parser{
			Command:     "discovery",
			Description: "Find the domains that belong to the same owner as a domain.",
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(0, "", "The domain to start from.", true, &discoveryDomain),
					"DOMAIN",
				),
			},
			Options: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						0, "dns-server",
						"The DNS server to resolve through. Defaults to the system's.",
						false, &discoveryDnsServer,
					),
					"ADDRESS",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "whoisxml-key",
						"A WhoisXML API key, enabling the reverse-whois source.",
						false, &discoveryWhoisXmlApiKey,
					),
					"KEY",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "hackertarget-key",
						"A HackerTarget API key, enabling the reverse-IP source.",
						false, &discoveryHackerTargetApiKey,
					),
					"KEY",
				),
				option.NewBoolOption(
					0, "historical",
					"Search registrations as they once were rather than as they stand now, which "+
						"finds domains the owner has since transferred away.",
					false, &discoveryHistorical,
				),
			},
		},
	)

	var auditDomain string
	var auditDnsServer string
	var auditWhoisXmlApiKey string
	var auditHackerTargetApiKey string
	var auditHistorical bool
	var auditDkimSelectors string
	var auditAllowedNetworks string
	var auditMinSeverity string
	var auditConcurrency int
	var auditJson bool

	auditCommand := newCommand(
		&argument_parser.Parser{
			Command: "audit",
			Description: "Discover the domains belonging to the same owner as a domain, assess every " +
				"one of them, and report what is wrong. Without an API key for a discovery source, " +
				"only the given domain is assessed.",
			Positionals: []option.Option{
				option.WithMetavar(
					option.NewStringOption(0, "", "The domain to start from.", true, &auditDomain),
					"DOMAIN",
				),
			},
			Options: []option.Option{
				option.WithMetavar(
					option.NewStringOption(
						0, "dns-server",
						"The DNS server to resolve through. Defaults to the system's.",
						false, &auditDnsServer,
					),
					"ADDRESS",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "whoisxml-key",
						"A WhoisXML API key, enabling the reverse-whois source.",
						false, &auditWhoisXmlApiKey,
					),
					"KEY",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "hackertarget-key",
						"A HackerTarget API key, enabling the reverse-IP source.",
						false, &auditHackerTargetApiKey,
					),
					"KEY",
				),
				option.NewBoolOption(
					0, "historical",
					"Search registrations as they once were rather than as they stand now.",
					false, &auditHistorical,
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "dkim-selectors",
						"A comma-separated list of DKIM selectors to probe.",
						false, &auditDkimSelectors,
					),
					"SELECTORS",
				),
				option.WithMetavar(
					option.NewStringOption(
						0, "allowed-networks",
						"A comma-separated list of CIDR blocks the domains are acknowledged to send "+
							"from. An SPF record authorising anything outside them is reported.",
						false, &auditAllowedNetworks,
					),
					"CIDRS",
				),
				option.WithChoices(
					option.WithDefault(
						option.WithMetavar(
							option.NewStringOption(
								's', "min-severity",
								"Report only problems at least this serious.",
								false, &auditMinSeverity,
							),
							"SEVERITY",
						),
						problemTypes.SeverityInfo,
					),
					problemTypes.SeverityHigh,
					problemTypes.SeverityMedium,
					problemTypes.SeverityLow,
					problemTypes.SeverityInfo,
				),
				option.WithDefault(
					option.WithMetavar(
						option.NewIntOption(
							'n', "concurrency",
							"How many domains to assess at once. Each assessment is many DNS lookups.",
							false, &auditConcurrency,
						),
						"N",
					),
					strconv.Itoa(defaultAuditConcurrency),
				),
				option.NewBoolOption(
					0, "json", "Emit the report as JSON rather than as text.", false, &auditJson,
				),
			},
		},
	)

	parser := &argument_parser.Parser{
		Description: "Assess domain security posture, discover related domains, or audit both together.",
		Parsers:     []argument_parser.Subparser{auditCommand, securityCommand, discoveryCommand},
	}

	// Validate surfaces a mistake in the parser's own declaration - a duplicated
	// name, an unreadable choice - at startup rather than on the parse that
	// happens to reach it.
	for _, validatable := range []*argument_parser.Parser{
		parser,
		auditCommand.Parser,
		securityCommand.Parser,
		discoveryCommand.Parser,
	} {
		if err := validatable.Validate(); err != nil {
			logger.FatalWithExitingMessage(
				"The argument parser is not valid.",
				fmt.Errorf("argument parser validate: %w", err),
			)
		}
	}

	// ParseOrExit, not Parse: a help request is an answer, already written to
	// stdout, and leaving through it as an error would log a failure and exit
	// non-zero for something the caller asked for.
	parser.ParseOrExit()

	ctx := context.Background()

	switch {
	case auditCommand.invoked:
		auditDnsServerClient, err := newDnsClient(ctx, auditDnsServer)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when preparing the resolver.",
				fmt.Errorf("new dns client: %w", err),
			)
		}

		allowedNetworks, err := parseNetworks(auditAllowedNetworks)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when parsing the allowed networks.",
				fmt.Errorf("parse networks: %w", err),
			)
		}

		auditResult, err := runAudit(
			ctx,
			&auditConfig{
				Domain:             auditDomain,
				DnsClient:          auditDnsServerClient,
				WhoisXmlApiKey:     auditWhoisXmlApiKey,
				HackerTargetApiKey: auditHackerTargetApiKey,
				Historical:         auditHistorical,
				DkimSelectors:      parseList(auditDkimSelectors),
				AllowedNetworks:    allowedNetworks,
				Concurrency:        auditConcurrency,
				MinSeverity:        auditMinSeverity,
			},
		)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when auditing.",
				fmt.Errorf("run audit: %w", err),
			)
		}

		if auditJson {
			if err := writeJson(auditResult); err != nil {
				logger.FatalWithExitingMessage(
					"An error occurred when writing the result.",
					fmt.Errorf("write json: %w", err),
				)
			}
		} else if err := writeAuditText(os.Stdout, auditResult); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when writing the report.",
				fmt.Errorf("write audit text: %w", err),
			)
		}
	case securityCommand.invoked:
		securityDnsServerClient, err := newDnsClient(ctx, securityDnsServer)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when preparing the resolver.",
				fmt.Errorf("new dns client: %w", err),
			)
		}

		allowedNetworks, err := parseNetworks(securityAllowedNetworks)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when parsing the allowed networks.",
				fmt.Errorf("parse networks: %w", err),
			)
		}

		options := []domain_security_config.Option{
			domain_security_config.WithDnsClient(
				securityDnsServerClient,
			),
			domain_security_config.WithAllowedNetworks(allowedNetworks...),
		}
		if dkimSelectors := parseList(securityDkimSelectors); len(dkimSelectors) > 0 {
			options = append(options, domain_security_config.WithDkimSelectors(dkimSelectors...))
		}

		metadata, err := domain_security.GetDomainSecurity(ctx, securityDomain, options...)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when assessing the domain.",
				fmt.Errorf("get domain security: %w", err),
			)
		}

		if err := writeJson(metadata); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when writing the result.",
				fmt.Errorf("write json: %w", err),
			)
		}
	case discoveryCommand.invoked:
		if discoveryWhoisXmlApiKey == "" && discoveryHackerTargetApiKey == "" {
			exitUsage(discoveryCommand.Parser, errNoDiscoverySource)
		}

		discoveryDnsServerClient, err := newDnsClient(ctx, discoveryDnsServer)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when preparing the resolver.",
				fmt.Errorf("new dns client: %w", err),
			)
		}

		domains, err := discovery.GetValidatedActiveDomainsWithMetadata(
			ctx,
			discoveryDomain,
			discovery_config.WithDnsClient(
				discoveryDnsServerClient,
			),
			discovery_config.WithWhoisXmlApiKey(discoveryWhoisXmlApiKey),
			discovery_config.WithHackerTargetApiKey(discoveryHackerTargetApiKey),
			discovery_config.WithHistoricalReverseWhois(discoveryHistorical),
		)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when discovering domains.",
				fmt.Errorf("get validated active domains with metadata: %w", err),
			)
		}

		if domains == nil {
			domains = []*domainTypes.Domain{}
		}

		if err := writeJson(domains); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when writing the result.",
				fmt.Errorf("write json: %w", err),
			)
		}
	default:
		exitUsage(parser, errNoCommand)
	}
}
