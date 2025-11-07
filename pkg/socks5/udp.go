package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type UDPHeader struct {
	Rsv      uint16
	Frag     uint8
	AddrType uint8
	DstAddr  []byte
	DstPort  uint16
}

func ParseUDPHeader(data []byte) (*UDPHeader, []byte, error) {
	if len(data) < 10 {
		return nil, nil, fmt.Errorf("UDP packet too short")
	}

	header := &UDPHeader{
		Rsv:      binary.BigEndian.Uint16(data[0:2]),
		Frag:     data[2],
		AddrType: data[3],
	}

	offset := 4
	switch header.AddrType {
	case AddrTypeIPv4:
		if len(data) < offset+6 {
			return nil, nil, fmt.Errorf("invalid IPv4 UDP packet")
		}
		header.DstAddr = data[offset : offset+4]
		offset += 4
	case AddrTypeIPv6:
		if len(data) < offset+18 {
			return nil, nil, fmt.Errorf("invalid IPv6 UDP packet")
		}
		header.DstAddr = data[offset : offset+16]
		offset += 16
	case AddrTypeDomain:
		if len(data) < offset+1 {
			return nil, nil, fmt.Errorf("invalid domain UDP packet")
		}
		addrLen := int(data[offset])
		offset++
		if len(data) < offset+addrLen+2 {
			return nil, nil, fmt.Errorf("invalid domain UDP packet")
		}
		header.DstAddr = data[offset : offset+addrLen]
		offset += addrLen
	default:
		return nil, nil, fmt.Errorf("unsupported address type: %d", header.AddrType)
	}

	if len(data) < offset+2 {
		return nil, nil, fmt.Errorf("UDP packet missing port")
	}
	header.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return header, data[offset:], nil
}

func EncodeUDPHeader(addrType uint8, addr []byte, port uint16) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, 0, 0, 0)
	buf = append(buf, addrType)

	if addrType == AddrTypeDomain {
		buf = append(buf, uint8(len(addr)))
	}
	buf = append(buf, addr...)

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	buf = append(buf, portBuf...)

	return buf
}

func (h *UDPHeader) Address() string {
	if h.AddrType == AddrTypeDomain {
		return fmt.Sprintf("%s:%d", string(h.DstAddr), h.DstPort)
	}
	ip := net.IP(h.DstAddr)
	return fmt.Sprintf("%s:%d", ip.String(), h.DstPort)
}

func ReadUDPRequest(r io.Reader) (*UDPHeader, []byte, error) {
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	return ParseUDPHeader(buf[:n])
}

