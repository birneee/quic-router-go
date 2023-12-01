package router

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func TestPacker(t *testing.T) {
	var secret [32]byte
	_, err := rand.Reader.Read(secret[:])
	assert.NoError(t, err)
	packer, err := NewNonQuicPrefixClientIDExtHdrPacker(secret)
	assert.NoError(t, err)
	quicPacket := []byte{1, 2, 3, 4}
	clientAddr := netip.MustParseAddrPort("127.0.0.1:8292")
	packedQuicPacket := packer.AddHdr(quicPacket, clientAddr)
	unpackedClientAddr, unpackedQuicPacked, err := packer.RemoveHdr(packedQuicPacket, true)
	assert.NoError(t, err)
	assert.Equal(t, clientAddr, unpackedClientAddr)
	assert.Equal(t, quicPacket, unpackedQuicPacked)
}
