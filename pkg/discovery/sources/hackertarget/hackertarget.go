// Package hackertarget queries HackerTarget's reverse IP lookup, which maps an
// address back to the domain names known to resolve to it.
package hackertarget

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	hackerTargetErrors "github.com/altshiftab/altshift_domain_security/pkg/discovery/sources/hackertarget/errors"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const ReverseIpUrl = "https://api.hackertarget.com/reverseiplookup/"

// The API reports these two conditions as a plain-text body with a 200, so they
// have to be recognised by their text rather than by a status code.
var (
	quotaExceededBody      = []byte("API count exceeded - Increase Quota with Membership")
	badSearchParameterBody = []byte("error check your search parameter")
)

// QueryReverseIp returns the domain names HackerTarget associates with the
// address. Only IPv4 is supported by the endpoint.
func QueryReverseIp(
	ctx context.Context,
	ipAddress net.IP,
	apiKey string,
	fetchOptions ...fetch_config.Option,
) ([]string, error) {
	if len(ipAddress) == 0 {
		return nil, nil
	}

	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("api key"))
	}

	ipv4 := ipAddress.To4()
	if ipv4 == nil {
		return nil, altshiftErrors.NewWithTrace(&hackerTargetErrors.NotIpv4Error{IpAddress: ipAddress})
	}

	query := url.Values{}
	query.Set("q", ipv4.String())
	query.Set("apikey", apiKey)
	requestUrlString := ReverseIpUrl + "?" + query.Encode()

	_, responseBody, err := altshiftHttpUtils.Fetch(ctx, requestUrlString, fetchOptions...)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch: %w", err), ReverseIpUrl, ipv4)
	}

	switch {
	case bytes.Equal(responseBody, quotaExceededBody):
		return nil, altshiftErrors.NewWithTrace(hackerTargetErrors.ErrQuotaExceeded)
	case bytes.Equal(responseBody, badSearchParameterBody):
		return nil, altshiftErrors.NewWithTrace(hackerTargetErrors.ErrBadSearchParameter, ipv4)
	}

	return strings.Split(string(responseBody), "\n"), nil
}
