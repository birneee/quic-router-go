package router

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

func TestConnIDProtector(t *testing.T) {
	var secret [32]byte
	_, err := rand.Read(secret[:])
	assert.NoError(t, err)
	p, err := NewConnIDProtector(secret)
	require.NoError(t, err)
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1)
	var nonce [6]byte
	_, err = rand.Read(nonce[:])
	assert.NoError(t, err)
	connID := p.ProtectAddr(addr, nonce)
	_ = connID
	var quicPacketShortHeaderPacket [1200]byte
	copy(quicPacketShortHeaderPacket[1:], connID[:])
	decodedAddr, err := p.DecodeServerIDFromProtectedQUICShortHeaderPacketAsAddr(quicPacketShortHeaderPacket[:])
	assert.NoError(t, err)
	assert.Equal(t, addr, decodedAddr)
}
