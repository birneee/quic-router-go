package router

import (
	"fmt"
	"net/netip"
)

// NonQuicPrefixClientIDExtHdrPacker adds and removes extension headers as prefix inside the UDP datagram
type NonQuicPrefixClientIDExtHdrPacker struct {
	protector *ClientAddrExtHdrProtector
}

func NewNonQuicPrefixClientIDExtHdrPacker(secret [32]byte) (NonQuicPrefixClientIDExtHdrPacker, error) {
	p := NonQuicPrefixClientIDExtHdrPacker{}
	var err error
	p.protector, err = NewClientAddrExtHdrProtector(secret)
	if err != nil {
		return NonQuicPrefixClientIDExtHdrPacker{}, err
	}
	return p, nil
}

func (p NonQuicPrefixClientIDExtHdrPacker) AddHdr(protectedQuicPacket []byte, clientAddr netip.AddrPort) []byte {
	var writeBuf [MaxUDPPayloadLen]byte
	writeBuf[0] = ClientAddrExtHdrType
	protectedExtHdr := p.protector.Protect(protectedQuicPacket, clientAddr)
	copy(writeBuf[1:], protectedExtHdr)
	copy(writeBuf[1+len(protectedExtHdr):], protectedQuicPacket)
	return writeBuf[:1+len(protectedExtHdr)+len(protectedQuicPacket)]
}

func (p *NonQuicPrefixClientIDExtHdrPacker) RemoveHdr(udpPayload []byte, asIPv4 bool) (netip.AddrPort, []byte, error) {
	if udpPayload[0] != ClientAddrExtHdrType {
		return netip.AddrPort{}, nil, fmt.Errorf("unexpected type")
	}
	typeLen := 1
	extHdrLen := p.protector.Len()
	protectedExtHdr := udpPayload[typeLen : typeLen+extHdrLen]
	protectedQuicPacket := udpPayload[typeLen+extHdrLen:]
	clientAddr, err := p.protector.Decode(protectedExtHdr, protectedQuicPacket, asIPv4)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	return clientAddr, protectedQuicPacket, nil
}

func (p NonQuicPrefixClientIDExtHdrPacker) Len() int {
	return 1 + p.protector.Len()
}
