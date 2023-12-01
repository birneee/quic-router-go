package router

import (
	"crypto/rand"
	"github.com/quic-go/quic-go"
	"io"
	"net/netip"
)

type ConnIDGenerator struct {
	protector *ConnIDProtector
	rand      io.Reader
	serverID  [6]byte
}

func NewConnIDGenerator(protector *ConnIDProtector, serverID [6]byte) ConnIDGenerator {
	g := ConnIDGenerator{
		protector: protector,
		rand:      rand.Reader,
		serverID:  serverID,
	}
	return g
}

func NewConnIDGeneratorFromAddr(protector *ConnIDProtector, serverAddr netip.AddrPort) ConnIDGenerator {
	return NewConnIDGenerator(protector, addrToServerID(serverAddr))
}

func (c ConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	var random [6]byte
	_, err := c.rand.Read(random[:])
	if err != nil {
		return quic.ConnectionID{}, err
	}
	connID := c.protector.Protect(c.serverID, random)
	return quic.ConnectionIDFromBytes(connID[:]), nil
}

func (c ConnIDGenerator) ConnectionIDLen() int {
	return connIDLen
}
