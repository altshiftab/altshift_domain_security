package errors

import (
	"errors"
	"net"
)

var (
	ErrNotIpv4            = errors.New("not an IPv4 address")
	ErrQuotaExceeded      = errors.New("quota exceeded")
	ErrBadSearchParameter = errors.New("bad search parameter")
)

// NotIpv4Error carries the address that was rejected, so a caller iterating
// over a set of addresses can report which one it was.
type NotIpv4Error struct {
	IpAddress net.IP
}

func (notIpv4Error *NotIpv4Error) GetInput() any {
	return notIpv4Error.IpAddress
}

func (notIpv4Error *NotIpv4Error) Is(target error) bool {
	return target == ErrNotIpv4
}

func (notIpv4Error *NotIpv4Error) Error() string {
	return ErrNotIpv4.Error()
}
