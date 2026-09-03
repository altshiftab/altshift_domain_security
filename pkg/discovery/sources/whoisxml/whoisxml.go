// Package whoisxml queries WhoisXML's reverse-whois API, which finds domains
// whose registration records match a search term.
package whoisxml

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	whoisXmlTypes "github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/whoisxml/types"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const ReverseWhoisEndpoint = "https://reverse-whois.whoisxmlapi.com/api/v2"

// The API bills a search in two steps: a preview reports how many domains
// match, and a purchase returns them.
const (
	ModePreview  = "preview"
	ModePurchase = "purchase"
)

// The two search types the API distinguishes: registrations as they stand now,
// and registrations as they once were.
const (
	SearchTypeCurrent  = "current"
	SearchTypeHistoric = "historic"
)

func QueryReverseWhois(
	ctx context.Context,
	requestData *whoisXmlTypes.ReverseWhoisRequest,
	fetchOptions ...fetch_config.Option,
) (*whoisXmlTypes.ReverseWhoisResponse, error) {
	if requestData == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("request data"))
	}

	// slices.Concat, not append: a reverse-whois run issues these queries
	// concurrently from one shared option slice, and appending into that
	// slice's spare capacity would have the queries overwrite one another's
	// options.
	options := slices.Concat(fetchOptions, []fetch_config.Option{fetch_config.WithMethod(http.MethodPost)})

	_, reverseWhoisResponse, err := altshiftHttpUtils.FetchJsonWithBody[*whoisXmlTypes.ReverseWhoisResponse](
		ctx,
		ReverseWhoisEndpoint,
		requestData,
		options...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json with body: %w", err), ReverseWhoisEndpoint)
	}

	return reverseWhoisResponse, nil
}
