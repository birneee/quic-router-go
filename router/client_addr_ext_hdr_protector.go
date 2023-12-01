package router

import (
	"net/netip"
)

type ClientAddrExtHdrProtector struct {
	extHdrProtector *ExtensionHeaderProtector
}

func NewClientAddrExtHdrProtector(secret [32]byte) (*ClientAddrExtHdrProtector, error) {
	p := &ClientAddrExtHdrProtector{}
	var err error
	p.extHdrProtector, err = NewExtensionHeaderProtector(secret)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ClientAddrExtHdrProtector) Len() int {
	return p.extHdrProtector.Len(18)
}

func (p *ClientAddrExtHdrProtector) Protect(protectedQUICPacket []byte, clientAddr netip.AddrPort) []byte {
	extHdr := ClientAddrExtHdrFromAddrPort(clientAddr)
	protectedExtHdr, err := p.extHdrProtector.Protect(extHdr.Bytes(), protectedQUICPacket)
	if err != nil {
		panic(err)
	}
	return protectedExtHdr
}

func (p *ClientAddrExtHdrProtector) Decode(protectedExtHdr []byte, protectedQuicPacket []byte, asIPv4 bool) (clientAddr netip.AddrPort, err error) {
	decoded, err := p.extHdrProtector.Decode(protectedExtHdr, protectedQuicPacket)
	if err != nil {
		return netip.AddrPort{}, err
	}
	clientAddr = ClientAddrExtHdrFromBytes(decoded).AddrPort(asIPv4)
	return clientAddr, nil
}
