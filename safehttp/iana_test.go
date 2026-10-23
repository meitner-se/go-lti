package safehttp

import (
	"bytes"
	"encoding/csv"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refusedWhole are registry blocks that IsPublicAddr refuses whole, although the registry marks
// some entries inside them globally reachable.
var refusedWhole = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.0/24"), // IETF protocol assignments, including two anycast addresses
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64, which can embed a private IPv4 address
	netip.MustParsePrefix("2001::/23"),    // IETF protocol assignments, including AMT and ORCHIDv2
}

// TestIsPublicAddr_FollowsTheIANARegistries checks IsPublicAddr against copies of the IANA IPv4 and
// IPv6 special-purpose address registries, so a registry update shows up as a test change. Refresh
// testdata from https://www.iana.org/assignments/iana-ipv4-special-registry/ and
// https://www.iana.org/assignments/iana-ipv6-special-registry/ (the CSV downloads).
func TestIsPublicAddr_FollowsTheIANARegistries(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"iana-ipv4-special-registry.csv", "iana-ipv6-special-registry.csv"} {
		for _, entry := range readRegistry(t, file) {
			for _, prefix := range entry.prefixes {
				for _, addr := range []netip.Addr{prefix.Addr(), lastAddr(prefix)} {
					want := entry.globallyReachable && !inRefusedWhole(addr)
					assert.Equal(t, want, IsPublicAddr(addr), "%s (%s in %s)", addr, entry.name, file)
				}
			}
		}
	}
}

type registryEntry struct {
	name              string
	prefixes          []netip.Prefix
	globallyReachable bool
}

// footnote matches the registry's footnote markers, such as "[2]".
var footnote = regexp.MustCompile(`\s*\[\d+\]`)

func readRegistry(t *testing.T, file string) []registryEntry {
	t.Helper()

	body, err := fs.ReadFile(os.DirFS("testdata"), file)
	require.NoError(t, err)

	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	require.NoError(t, err)
	require.Equal(t, []string{"Address Block", "Name"}, rows[0][:2])
	require.Equal(t, "Globally Reachable", rows[0][8])

	entries := make([]registryEntry, 0, len(rows)-1)
	for _, row := range rows[1:] {
		entry := registryEntry{name: row[1], globallyReachable: footnote.ReplaceAllString(row[8], "") == "True"}

		for block := range strings.SplitSeq(footnote.ReplaceAllString(row[0], ""), ",") {
			entry.prefixes = append(entry.prefixes, netip.MustParsePrefix(strings.TrimSpace(block)))
		}

		entries = append(entries, entry)
	}

	return entries
}

// lastAddr returns the highest address in prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	octets := prefix.Masked().Addr().AsSlice()
	for i := prefix.Bits(); i < len(octets)*8; i++ {
		octets[i/8] |= 0x80 >> (i % 8)
	}

	addr, _ := netip.AddrFromSlice(octets)

	return addr
}

func inRefusedWhole(addr netip.Addr) bool {
	for _, prefix := range refusedWhole {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
