package router

import (
	"encoding/binary"
	"net/netip"
	"unsafe"
)

const (
	IPv6Len                 = 16
	UDPPortLen              = 2
	ClientAddrExtHdrDataLen = IPv6Len + UDPPortLen
)

type ClientAddrExtHdrData struct {
	ip   [IPv6Len]byte
	port [UDPPortLen]byte
}

func (d *ClientAddrExtHdrData) AddrPort(asIPv4 bool) netip.AddrPort {
	addr := netip.AddrFrom16(d.ip)
	if asIPv4 {
		if !addr.Is4In6() {
			panic("not IPv4")
		}
		addr = addr.Unmap()
	}
	return netip.AddrPortFrom(addr, binary.LittleEndian.Uint16(d.port[:]))
}

func (d *ClientAddrExtHdrData) Bytes() []byte {
	return (*[ClientAddrExtHdrDataLen]byte)(unsafe.Pointer(d))[:]
}

func ClientAddrExtHdrFromBytes(bytes []byte) *ClientAddrExtHdrData {
	if len(bytes) != ClientAddrExtHdrDataLen {
		panic("unexpected length")
	}
	return (*ClientAddrExtHdrData)(unsafe.Pointer(&bytes[0]))
}

func ClientAddrExtHdrFromAddrPort(addrPort netip.AddrPort) ClientAddrExtHdrData {
	d := ClientAddrExtHdrData{
		ip: addrPort.Addr().As16(),
	}
	binary.LittleEndian.PutUint16(d.port[:], addrPort.Port())
	return d
}
