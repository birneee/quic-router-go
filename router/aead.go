package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/birneee/aes6"
	"golang.org/x/crypto/hkdf"
	"io"
)

// secret is the shared secret.
// info e.g. []byte("quic-go token source").
// tagSize for authentication.
func createAEAD(secret [32]byte, tagSize int, info []byte) (cipher.AEAD, []byte, error) {
	h := hkdf.New(sha256.New, secret[:], nil, info)
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
	aead, err := aes6.NewGCMWithTagSize(c, tagSize)
	if err != nil {
		return nil, nil, err
	}
	return aead, aeadNonce, nil
}
