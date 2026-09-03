// Package inference records why a domain was attributed to the subject of a
// discovery run, and how strongly.
package inference

// Inference is one reason a domain was attributed, with a confidence on a
// 1-to-5 scale and the chain of steps that produced it (for example
// "Reverse Whois" followed by the search term that matched).
type Inference struct {
	Confidence int      `json:"confidence" required:"true" minimum:"1" maximum:"5"`
	Chain      []string `json:"chain" required:"true"`
}
