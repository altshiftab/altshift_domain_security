# altshift_domain_security

How a domain's mail is exposed to whoever forges it.

The mail-layer counterpart to `altshift_web_security`, which asks the same kind of question of a
site's HTTP and TLS. It shares that repository's shape: a rule id per thing that can be wrong, a
curated severity and description behind each, so a run is something another tool can read rather
than only a person.

A library and a command, and nothing else. It serves nothing and stores nothing: a caller asks what
is wrong with a domain and is told, and what to do with the answer is the caller's business.

## What it asks

Everything a forged message would have to get past, and all of it from DNS:

| Package | What it answers |
| --- | --- |
| `domain_security` | All of the below at once, for one domain |
| `pkg/spf` | Does the domain say who may send for it, and is what it says sound? |
| `pkg/dkim` | Are the keys it signs with published, and are they strong enough to mean anything? |
| `pkg/dmarc` | What does it tell a receiver to do when the answer is no, and does anyone hear about it? |
| `pkg/report` | The above, collected into findings with a source, a severity and a description |
| `pkg/discovery` | Which other domains a registration record or a reverse lookup associates with this one |

Each analysis package has a `rule_id` package naming what it can find, and a `rule_id_mappings`
package holding the title, description and severity behind each. The curation is the point: a caller
that had to decide for itself how bad a missing DMARC policy is would be deciding it differently
from every other caller.

## What it does not ask

Whether the mail servers themselves negotiate TLS -- STARTTLS and DANE -- which needs an SMTP
conversation this does not hold. A domain can therefore answer well here and still hand its mail
over in the clear.

## Command

    go run ./cmd/altshift_domain_security <domain>
