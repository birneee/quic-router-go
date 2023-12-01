package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

const AesMacLen = 16
const ExtensionHeaderSecretSize int = 32

type ExtensionHeaderProtector struct {
	secret    [ExtensionHeaderSecretSize]byte
	aead      cipher.AEAD
	aeadNonce []byte
}

func NewExtensionHeaderProtector(secret [ExtensionHeaderSecretSize]byte) (*ExtensionHeaderProtector, error) {
	p := &ExtensionHeaderProtector{
		secret: secret,
	}
	var err error
	p.aead, p.aeadNonce, err = p.createAEAD()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Protect uses encrypted the QUIC packet as nonce for AES.
// This also appends a 16 byte authentication tag
func (p *ExtensionHeaderProtector) Protect(extHdrData []byte, quicPacket []byte) ([]byte, error) {
	return p.aead.Seal(nil, p.aeadNonce, extHdrData, quicPacket), nil
}

// Decode uses the encrypted QUIC packet as nonce for AES
func (p *ExtensionHeaderProtector) Decode(protectedExtHdrData []byte, quicPacket []byte) ([]byte, error) {
	return p.aead.Open(nil, p.aeadNonce, protectedExtHdrData, quicPacket)
}

func (p *ExtensionHeaderProtector) createAEAD() (cipher.AEAD, []byte, error) {
	h := hkdf.New(sha256.New, p.secret[:], nil, []byte("quic-go token source"))
	key := make([]byte, 32) // use a 32 byte key, in order to select AES-256
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, nil, err
	}
	aeadNonce := make([]byte, 12)
	if _, err := io.ReadFull(h, aeadNonce); err != nil {
		return nil, nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}
	return aead, aeadNonce, nil
}

func ProtectedExtensionHeaderDataLen(extensionHeaderDataLen int) int {
	return extensionHeaderDataLen + AesMacLen
}

func (p *ExtensionHeaderProtector) Len(extensionHeaderDataLen int) int {
	return ProtectedExtensionHeaderDataLen(extensionHeaderDataLen)
}
