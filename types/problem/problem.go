// Package problem carries a single finding produced by analysing a DNS record.
//
// The SPF, DKIM and DMARC analyses each own their own rule-id namespace, but
// the shape of what they report is identical, so they report it with this one
// type rather than three structurally identical copies.
package problem

// The severities a Problem may carry, ordered from most to least serious.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

type Problem struct {
	Id          string `json:"id,omitzero"`
	Title       string `json:"title,omitzero"`
	Description string `json:"description,omitzero"`
	Details     string `json:"details,omitzero"`
	Severity    string `json:"severity,omitzero"`
}

// String renders the problem for human consumption: the title, then whichever
// of the description and the record-specific details are present.
func (p *Problem) String() string {
	if p == nil {
		return ""
	}

	s := p.Title
	if p.Description != "" {
		s += "\n\n" + p.Description
	}
	if p.Details != "" {
		s += "\n\n" + p.Details
	}

	return s
}
