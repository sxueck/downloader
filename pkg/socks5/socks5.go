package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	Version5 = 0x05

	AuthNone     = 0x00
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	RepSuccess              = 0x00
	RepServerFailure        = 0x01
	RepNotAllowed           = 0x02
	RepNetworkUnreachable   = 0x03
	RepHostUnreachable      = 0x04
	RepConnectionRefused    = 0x05
	RepTTLExpired           = 0x06
	RepCommandNotSupported  = 0x07
	RepAddrTypeNotSupported = 0x08
)

type Request struct {
	Version  uint8
	Command  uint8
	AddrType uint8
	DstAddr  []byte
	DstPort  uint16
}

func Handshake(conn net.Conn, username, password string) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != Version5 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	authMethod := AuthNone
	if username != "" && password != "" {
		authMethod = AuthPassword
		found := false
		for _, m := range methods {
			if m == AuthPassword {
				found = true
				break
			}
		}
		if !found {
			if _, err := conn.Write([]byte{Version5, AuthNoAccept}); err != nil {
				return err
			}
			return fmt.Errorf("client does not support password authentication")
		}
	}

	if _, err := conn.Write([]byte{Version5, byte(authMethod)}); err != nil {
		return err
	}

	if authMethod == AuthPassword {
		if err := authenticatePassword(conn, username, password); err != nil {
			return err
		}
	}

	return nil
}

func authenticatePassword(conn net.Conn, username, password string) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	uLen := int(buf[1])
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	pLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLen); err != nil {
		return err
	}

	passwd := make([]byte, pLen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	if string(uname) != username || string(passwd) != password {
		if _, err := conn.Write([]byte{0x01, 0x01}); err != nil {
			return err
		}
		return fmt.Errorf("invalid username or password")
	}

	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}

	return nil
}

func ReadRequest(conn net.Conn) (*Request, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	req := &Request{
		Version:  buf[0],
		Command:  buf[1],
		AddrType: buf[3],
	}

	if req.Version != Version5 {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", req.Version)
	}

	switch req.AddrType {
	case AddrTypeIPv4:
		req.DstAddr = make([]byte, 4)
		if _, err := io.ReadFull(conn, req.DstAddr); err != nil {
			return nil, err
		}
	case AddrTypeIPv6:
		req.DstAddr = make([]byte, 16)
		if _, err := io.ReadFull(conn, req.DstAddr); err != nil {
			return nil, err
		}
	case AddrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		req.DstAddr = make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, req.DstAddr); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported address type: %d", req.AddrType)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	req.DstPort = binary.BigEndian.Uint16(portBuf)

	return req, nil
}

func SendReply(conn net.Conn, rep uint8, bindAddr net.Addr) error {
	reply := []byte{Version5, rep, 0x00}

	if bindAddr == nil {
		reply = append(reply, AddrTypeIPv4)
		reply = append(reply, 0, 0, 0, 0)
		reply = append(reply, 0, 0)
	} else {
		switch addr := bindAddr.(type) {
		case *net.TCPAddr:
			if ip4 := addr.IP.To4(); ip4 != nil {
				reply = append(reply, AddrTypeIPv4)
				reply = append(reply, ip4...)
			} else {
				reply = append(reply, AddrTypeIPv6)
				reply = append(reply, addr.IP...)
			}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(addr.Port))
			reply = append(reply, portBuf...)
		case *net.UDPAddr:
			if ip4 := addr.IP.To4(); ip4 != nil {
				reply = append(reply, AddrTypeIPv4)
				reply = append(reply, ip4...)
			} else {
				reply = append(reply, AddrTypeIPv6)
				reply = append(reply, addr.IP...)
			}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(addr.Port))
			reply = append(reply, portBuf...)
		default:
			reply = append(reply, AddrTypeIPv4)
			reply = append(reply, 0, 0, 0, 0)
			reply = append(reply, 0, 0)
		}
	}

	_, err := conn.Write(reply)
	return err
}

func (r *Request) Address() string {
	if r.AddrType == AddrTypeDomain {
		return fmt.Sprintf("%s:%d", string(r.DstAddr), r.DstPort)
	}
	ip := net.IP(r.DstAddr)
	return fmt.Sprintf("%s:%d", ip.String(), r.DstPort)
}
