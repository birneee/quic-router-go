package router

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

func TestConnIDGenerator(t *testing.T) {
	var secret [32]byte
	_, err := rand.Reader.Read(secret[:])
	assert.NoError(t, err)
	protector, err := NewConnIDProtector(secret)
	require.NoError(t, err)
	addr := netip.MustParseAddrPort("127.0.0.1:8292")
	connIDGen := NewConnIDGeneratorFromAddr(protector, addr)
	connID, err := connIDGen.GenerateConnectionID()
	assert.NoError(t, err)
	_, _, err = protector.Decode(connID.Bytes())
	assert.NoError(t, err)
}
