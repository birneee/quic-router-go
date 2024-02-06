package router

import (
	"crypto/cipher"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"net/netip"
)

const (
	connIDKeyLen      = 32
	connIDServerIDLen = 6
	connIDMACLen      = 6
	connIDRandomLen   = 6
	connIDLen         = connIDServerIDLen + connIDMACLen + connIDRandomLen
)

var connIDHkdfInfo = []byte("quic lb")

type ConnIDProtector struct {
	secret    [connIDKeyLen]byte
	aead      cipher.AEAD
	aeadNonce []byte
}

func NewConnIDProtector(secret [connIDKeyLen]byte) (*ConnIDProtector, error) {
	p := &ConnIDProtector{
		secret: secret,
	}
	var err error
	p.aead, p.aeadNonce, err = createAEAD(secret, connIDMACLen, connIDHkdfInfo)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ConnIDProtector) Protect(serverID [6]byte, random [6]byte) [connIDLen]byte {
	var ciphertext [connIDLen]byte
	p.aead.Seal(ciphertext[:0], p.aeadNonce, serverID[:], random[:])
	copy(ciphertext[12:], random[:])
	return ciphertext
}

func addrToServerID(addr netip.AddrPort) [6]byte {
	var serverID [6]byte
	ipv4 := addr.Addr().As4()
	copy(serverID[:], ipv4[:])
	binary.LittleEndian.PutUint16(serverID[4:], addr.Port())
	return serverID
}

func serverIDToAddr(serverID [6]byte) netip.AddrPort {
	return netip.AddrPortFrom(
		netip.AddrFrom4([4]byte(serverID[:4])),
		binary.LittleEndian.Uint16(serverID[4:]),
	)
}

func (p *ConnIDProtector) ProtectAddr(addr netip.AddrPort, random [6]byte) [connIDLen]byte {
	return p.Protect(addrToServerID(addr), random)
}

// return serverID and random nonce
func (p *ConnIDProtector) Decode(connID []byte) ([6]byte, [6]byte, error) {
	ciphertext := connID[:12]
	var nonce [connIDRandomLen]byte
	copy(nonce[:], connID[12:])
	var serverID [connIDServerIDLen]byte
	_, err := p.aead.Open(serverID[:0], p.aeadNonce, ciphertext, nonce[:])
	if err != nil {
		return [6]byte{}, [6]byte{}, err
	}
	return serverID, nonce, nil
}

func (p *ConnIDProtector) DecodeAsAddr(connID quic.ConnectionID) (netip.AddrPort, error) {
	serverID, _, err := p.Decode(connID.Bytes())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return serverIDToAddr(serverID), nil
}

func (p *ConnIDProtector) DecodeServerIDFromProtectedQUICShortHeaderPacket(buf []byte) ([6]byte, error) {
	// destination connection id starts after 1 byte
	// and is always connIDLen bytes long
	serverID, _, err := p.Decode(buf[1 : 1+connIDLen])
	if err != nil {
		return [6]byte{}, err
	}
	return serverID, nil
}

func (p *ConnIDProtector) DecodeServerIDFromProtectedQUICShortHeaderPacketAsAddr(buf []byte) (netip.AddrPort, error) {
	serverID, err := p.DecodeServerIDFromProtectedQUICShortHeaderPacket(buf)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return serverIDToAddr(serverID), nil
}
