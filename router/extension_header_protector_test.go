package router

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExtensionHeaderProtector(t *testing.T) {
	secret := [ExtensionHeaderSecretSize]byte{}
	_, err := rand.Read(secret[:])
	assert.NoError(t, err)
	quicPacket := make([]byte, 1200)
	_, err = rand.Read(quicPacket)
	assert.NoError(t, err)
	extHdrProtector, err := NewExtensionHeaderProtector(secret)
	assert.NoError(t, err)
	extHdr := []byte("hello")
	protectedExtHdr, err := extHdrProtector.Protect(extHdr, quicPacket)
	assert.NoError(t, err)
	decodedExtHdr, err := extHdrProtector.Decode(protectedExtHdr, quicPacket)
	assert.NoError(t, err)
	assert.Equal(t, extHdr, decodedExtHdr)
}
