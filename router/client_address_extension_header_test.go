package router

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func TestClientAddrExtHdrData(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:511")
	hdr := ClientAddrExtHdrFromAddrPort(addr)
	_ = hdr
	assert.Equal(t, hdr.Bytes(), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 255, 1})
	assert.Equal(t, hdr.AddrPort(true), addr)
}
