// Package domain holds the subject of this API: a domain name, and everything
// a discovery run or a security assessment has learned about it.
package domain

import (
	"fmt"
	"time"

	dkimTypes "github.com/altshiftab/altshift_domain_security/types/dkim"
	"github.com/altshiftab/altshift_domain_security/types/inference"
	problemTypes "github.com/altshiftab/altshift_domain_security/types/problem"
	spfTypes "github.com/altshiftab/altshift_domain_security/types/spf"
	"github.com/altshiftab/utils_go/pkg/dns/dmarc"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// timeLayout is RFC 3339 with a fixed nine-digit fraction.
//
// The fraction is zero-padded rather than trimmed so the rendered timestamps
// order correctly as plain strings: with a trimmed fraction, "…:00Z" sorts
// after "…:00.5Z", because "." precedes "Z". Padding is what lets this one
// field carry both the instant and its ordering, with nothing alongside it.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// Observation stamps when a piece of metadata was gathered. Every data block
// below embeds it, so a consumer can tell how stale any individual answer is
// without the whole Metadata sharing one timestamp - the blocks are gathered
// concurrently and do not complete together.
//
// The instant is carried as a string alone. It parses back to the exact
// nanosecond with time.RFC3339Nano, so a companion integer timestamp would
// restate what this already says.
type Observation struct {
	ObservedAt string `json:"observed_at"`
}

func NewObservation(observedAt time.Time) Observation {
	return Observation{ObservedAt: observedAt.UTC().Format(timeLayout)}
}

type Domain struct {
	Domain           string    `json:"domain" required:"true" minLength:"1"`
	RegisteredDomain string    `json:"registered_domain,omitzero"`
	Subdomain        string    `json:"subdomain,omitzero"`
	TopLevelDomain   string    `json:"top_level_domain,omitzero"`
	Metadata         *Metadata `json:"metadata,omitzero"`
	_                struct{}  `additionalProperties:"false"`
}

// Validate reports whether the domain names something that can be looked up.
// The failures are wrapped in ErrValidationError so an endpoint maps them to a
// 4xx rather than a 500 - a domain that does not parse is the client's input
// problem, not the service's.
func (d *Domain) Validate() error {
	if d == nil {
		return fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, nil_error.New("domain"))
	}

	domainName := d.Domain
	if domainName == "" {
		return fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("domain name"))
	}

	if parts := domain_parts.New(domainName); parts == nil {
		return fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, nil_error.New("domain parts"))
	}

	return nil
}

type Metadata struct {
	Description string                 `json:"description,omitzero"`
	Inferences  []*inference.Inference `json:"inferences,omitzero"`

	// MarkedNonSending is an operator's assertion that the domain sends no
	// mail; GuessedNonSending is what an MX lookup suggested. They are kept
	// apart so a guess never overwrites a decision.
	MarkedNonSending  *bool `json:"marked_non_sending,omitzero"`
	GuessedNonSending *bool `json:"guessed_non_sending,omitzero"`

	SpfData    *SpfData    `json:"spf_data,omitzero"`
	DmarcData  *DmarcData  `json:"dmarc_data,omitzero"`
	DkimData   *DkimData   `json:"dkim_data,omitzero"`
	DnssecData *DnssecData `json:"dnssec_data,omitzero"`
	WhoisData  *WhoisData  `json:"whois_data,omitzero"`
}

// The data blocks below deliberately do not use omitzero on the fields an
// assessment always establishes: a consumer refreshing a stored assessment
// needs an empty result to overwrite the previous one rather than leave it
// standing.

type SpfData struct {
	Observation
	RecordCollection []*spfTypes.TracedRecordWithProblems `json:"record_collection" jsonschema:"record_collection,minitems:0"`
}

type DmarcData struct {
	Observation
	Record   *dmarc.Record           `json:"record,omitzero"`
	Problems []*problemTypes.Problem `json:"problems" jsonschema:"problems,minitems:0"`
	// IsCovered reports whether DMARC applies to the domain at all, which is
	// not the same as the domain having a record: a subdomain with no record
	// of its own is covered by a valid record on its organizational domain.
	IsCovered *bool `json:"is_covered"`
}

type DkimData struct {
	Observation
	RecordCollection []*dkimTypes.RecordWithProblems `json:"record_collection,omitzero"`
}

type DnssecData struct {
	Observation
	Covered *bool `json:"covered"`
}

// WhoisData records the EPP status codes that lock a domain against being moved
// or removed. They come in pairs: the server* codes are set by the registry and
// are usually a paid service, while the client* codes are set by the registrar
// and are what most domains are actually protected by. Reading only one half
// would report a fully locked domain as unlocked.
type WhoisData struct {
	Observation
	ServerTransferProhibited *bool `json:"server_transfer_prohibited,omitzero"`
	ServerUpdateProhibited   *bool `json:"server_update_prohibited,omitzero"`
	ServerDeleteProhibited   *bool `json:"server_delete_prohibited,omitzero"`
	ClientTransferProhibited *bool `json:"client_transfer_prohibited,omitzero"`
	ClientUpdateProhibited   *bool `json:"client_update_prohibited,omitzero"`
	ClientDeleteProhibited   *bool `json:"client_delete_prohibited,omitzero"`
}

// AnyLockKnown reports whether the statuses were read at all. A WHOIS query
// that failed leaves every lock unset, which is not the same as a domain that
// holds none.
func (w *WhoisData) AnyLockKnown() bool {
	if w == nil {
		return false
	}

	for _, lock := range w.locks() {
		if lock != nil {
			return true
		}
	}

	return false
}

// AnyLockHeld reports whether any lock, from either party, is in place.
func (w *WhoisData) AnyLockHeld() bool {
	if w == nil {
		return false
	}

	for _, lock := range w.locks() {
		if lock != nil && *lock {
			return true
		}
	}

	return false
}

func (w *WhoisData) locks() []*bool {
	return []*bool{
		w.ServerTransferProhibited,
		w.ServerUpdateProhibited,
		w.ServerDeleteProhibited,
		w.ClientTransferProhibited,
		w.ClientUpdateProhibited,
		w.ClientDeleteProhibited,
	}
}

// NewValidated builds a Domain from a domain name, rejecting anything that
// does not parse, and fills in the registered-domain breakdown it had to
// compute to decide that.
func NewValidated(domainString string) (*Domain, error) {
	d := &Domain{Domain: domainString}
	if err := d.Validate(); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("domain validate: %w", err), d)
	}

	if parts := domain_parts.New(domainString); parts != nil {
		d.RegisteredDomain = parts.RegisteredDomain
		d.Subdomain = parts.Subdomain
		d.TopLevelDomain = parts.TopLevelDomain
	}

	return d, nil
}
