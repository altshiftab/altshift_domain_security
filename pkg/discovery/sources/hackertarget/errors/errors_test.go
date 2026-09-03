package errors

import (
	"errors"
	"net"
	"testing"
)

func TestNotIpv4Error(t *testing.T) {
	t.Parallel()

	ipAddress := net.ParseIP("2001:db8::1")
	notIpv4Error := &NotIpv4Error{IpAddress: ipAddress}

	testCases := []struct {
		name  string
		check func(*testing.T)
	}{
		{
			name: "carries the rejected address",
			check: func(t *testing.T) {
				input, ok := notIpv4Error.GetInput().(net.IP)
				if !ok {
					t.Fatalf("GetInput() = %T, want net.IP", notIpv4Error.GetInput())
				}
				if !input.Equal(ipAddress) {
					t.Errorf("GetInput() = %v, want %v", input, ipAddress)
				}
			},
		},
		{
			name: "matches the sentinel",
			check: func(t *testing.T) {
				if !errors.Is(notIpv4Error, ErrNotIpv4) {
					t.Error("errors.Is(notIpv4Error, ErrNotIpv4) = false, want true")
				}
			},
		},
		{
			name: "does not match an unrelated sentinel",
			check: func(t *testing.T) {
				if errors.Is(notIpv4Error, ErrQuotaExceeded) {
					t.Error("errors.Is(notIpv4Error, ErrQuotaExceeded) = true, want false")
				}
			},
		},
		{
			name: "reads as the sentinel",
			check: func(t *testing.T) {
				if notIpv4Error.Error() != ErrNotIpv4.Error() {
					t.Errorf("Error() = %q, want %q", notIpv4Error.Error(), ErrNotIpv4.Error())
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			testCase.check(t)
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []error{ErrNotIpv4, ErrQuotaExceeded, ErrBadSearchParameter}

	for i, first := range sentinels {
		for j, second := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(first, second) {
				t.Errorf("sentinel %v matches %v", first, second)
			}
		}
	}
}
