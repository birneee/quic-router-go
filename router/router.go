package router

import (
	"context"
	"errors"
	"fmt"
	socketoob "github.com/birneee/go-socket-oob"
	"net"
	"net/netip"
	"sync"
)

const (
	MTU                         = 1500
	IPv6HeaderLen               = 40
	SupportedExtensionHeaderLen = 35
	UDPHeaderLen                = 8
	MaxUDPPayloadLen            = MTU - IPv6HeaderLen - UDPHeaderLen
	MaxQUICPacketLen            = MaxUDPPayloadLen - SupportedExtensionHeaderLen
)

// first two bits must be 0
const (
	ClientAddrExtHdrType byte = 0b00000001
)

var (
	ErrorZeroLengthUDP       = errors.New("zero length udp")
	ErrorUnexpectedHeaderLen = errors.New("unexpected header length")
)

type Config struct {
}

type Router struct {
	conn                 *net.UDPConn
	config               *Config
	connIDProtector      *ConnIDProtector
	defaultServerAddr    netip.AddrPort
	clientIDExtHdrPacker NonQuicPrefixClientIDExtHdrPacker
	gso                  bool
	gro                  bool
	writeBuf             [socketoob.MaxGSOBufSize]byte
	ctx                  context.Context
	cancelCtx            context.CancelFunc
	stopOnce             sync.Once
}

func NewRouter(conn *net.UDPConn, secret [32]byte, defaultServerAddr netip.AddrPort, config *Config) (Router, error) {
	r := Router{
		conn:              conn,
		defaultServerAddr: defaultServerAddr,
		config:            config,
	}
	r.ctx, r.cancelCtx = context.WithCancel(context.Background())
	var err error
	r.clientIDExtHdrPacker, err = NewNonQuicPrefixClientIDExtHdrPacker(secret)
	if err != nil {
		return Router{}, err
	}
	r.connIDProtector, err = NewConnIDProtector(secret)
	if err != nil {
		return Router{}, err
	}
	r.gso = socketoob.IsGSOSupported(conn)
	if socketoob.IsGROSupported(conn) {
		socketoob.EnableGRO(conn)
		r.gro = socketoob.IsGROEnabled(conn)
	}
	go func() {
		err := r.run()
		if err != nil {
			r.Stop(err)
		}
	}()
	return r, nil
}

func (r *Router) run() error {
	var buf [socketoob.MaxGSOBufSize]byte
loop:
	for {
		select {
		case <-r.ctx.Done():
			break loop
		default: // continue
		}
		if r.gro {
			segments, _, _, addr, err := socketoob.ReadGRO(r.conn, buf[:], nil)
			if err != nil {
				return err
			}
			err = r.handleUDPPackets(segments, addr)
			if err != nil {
				return err
			}
		} else {
			n, addr, err := r.conn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				return err
			}
			err = r.handleUDPPacket(buf[:n], addr)
			if err != nil {
				return err
			}
		}
	}
	r.conn.Close()
	return nil
}

func (r *Router) handleUDPPackets(segments socketoob.Segments, addr netip.AddrPort) error {
	segmentsIter := segments.Iterator()
	for segmentsIter.HasNext() {
		segBuf := segmentsIter.Next()
		err := r.handleUDPPacket(segBuf, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Router) handleUDPPacket(readBuf []byte, addr netip.AddrPort) error {
	if len(readBuf) == 0 {
		return ErrorZeroLengthUDP
	}
	if isQUICPacket(readBuf[0]) {
		if isLongHeaderPacket(readBuf[0]) {
			return r.handleLongHeaderPacket(readBuf, addr)
		} else {
			return r.handleShortHeaderPacket(readBuf, addr)
		}
	} else {
		return r.handleNonQUICPacket(readBuf, addr)
	}
}

func (r *Router) handleLongHeaderPacket(readBuf []byte, addr netip.AddrPort) error {
	quicPacketWithExtHdr := r.clientIDExtHdrPacker.AddHdr(readBuf, addr)
	_, err := r.conn.WriteToUDPAddrPort(quicPacketWithExtHdr, r.defaultServerAddr)
	if err != nil {
		return err
	}
	return nil
}

func (r *Router) handleShortHeaderPacket(readBuf []byte, addr netip.AddrPort) error {
	if len(readBuf) > MaxQUICPacketLen {
		return nil //drop
	}
	serverAddr, err := r.connIDProtector.DecodeServerIDFromProtectedQUICShortHeaderPacketAsAddr(readBuf)
	if err != nil {
		return err
	}
	quicPacketWithExtHdr := r.clientIDExtHdrPacker.AddHdr(readBuf, addr)
	_, err = r.conn.WriteToUDPAddrPort(quicPacketWithExtHdr, serverAddr)
	if err != nil {
		return err
	}
	return nil
}

func (r *Router) handleNonQUICPacket(buf []byte, addr netip.AddrPort) error {
	headerType := buf[0]
	switch headerType {
	case ClientAddrExtHdrType:
		serverAddr := addr
		//fmt.Printf("remove hdr from %d byte udp payload\n", len(buf))
		clientAddr, protectedQuicPacket, err := r.clientIDExtHdrPacker.RemoveHdr(buf, serverAddr.Addr().Is4())
		if err != nil {
			return fmt.Errorf("failed to remove header from %d byte udp datagram: %s: %v", len(buf), err, buf)
		}
		_, err = r.conn.WriteToUDPAddrPort(protectedQuicPacket, clientAddr)
		if err != nil {
			return err
		}
	default:
		// drop
	}
	return nil
}

func (r *Router) Context() context.Context {
	return r.ctx
}

func (r *Router) Stop(err error) {
	r.stopOnce.Do(func() {
		if err != nil {
			fmt.Printf("stopped with error: %s\n", err)
		} else {
			fmt.Printf("stopped\n")
		}
		r.cancelCtx()
	})
}
