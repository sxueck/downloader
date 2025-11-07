package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	MagicNumber = 0x44574E4C
	Version     = 0x01
)

const (
	CmdTCPConnect   = 0x01
	CmdTCPData      = 0x02
	CmdTCPClose     = 0x03
	CmdUDPAssociate = 0x04
	CmdUDPData      = 0x05
	CmdHeartbeat    = 0x06
	CmdError        = 0xFF
)

const (
	AddrTypeIPv4   = 0x01
	AddrTypeIPv6   = 0x04
	AddrTypeDomain = 0x03
)

type Packet struct {
	Magic     uint32
	Version   uint8
	Command   uint8
	SessionID uint32
	AddrType  uint8
	Addr      []byte
	Port      uint16
	Data      []byte
}

func NewPacket(cmd uint8, sessionID uint32) *Packet {
	return &Packet{
		Magic:     MagicNumber,
		Version:   Version,
		Command:   cmd,
		SessionID: sessionID,
	}
}

func (p *Packet) Encode() ([]byte, error) {
	buf := make([]byte, 0, 1024)

	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, p.Magic)
	buf = append(buf, tmp...)

	buf = append(buf, p.Version)
	buf = append(buf, p.Command)

	binary.BigEndian.PutUint32(tmp, p.SessionID)
	buf = append(buf, tmp...)

	if p.Command == CmdTCPConnect || p.Command == CmdUDPAssociate {
		buf = append(buf, p.AddrType)
		buf = append(buf, uint8(len(p.Addr)))
		buf = append(buf, p.Addr...)

		tmp2 := make([]byte, 2)
		binary.BigEndian.PutUint16(tmp2, p.Port)
		buf = append(buf, tmp2...)
	}

	if len(p.Data) > 0 {
		tmp4 := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp4, uint32(len(p.Data)))
		buf = append(buf, tmp4...)
		buf = append(buf, p.Data...)
	} else {
		buf = append(buf, 0, 0, 0, 0)
	}

	return buf, nil
}

func DecodePacket(r io.Reader) (*Packet, error) {
	p := &Packet{}

	tmp := make([]byte, 4)
	if _, err := io.ReadFull(r, tmp); err != nil {
		return nil, err
	}
	p.Magic = binary.BigEndian.Uint32(tmp)
	if p.Magic != MagicNumber {
		return nil, fmt.Errorf("invalid magic number: %x", p.Magic)
	}

	tmp1 := make([]byte, 1)
	if _, err := io.ReadFull(r, tmp1); err != nil {
		return nil, err
	}
	p.Version = tmp1[0]

	if _, err := io.ReadFull(r, tmp1); err != nil {
		return nil, err
	}
	p.Command = tmp1[0]

	if _, err := io.ReadFull(r, tmp); err != nil {
		return nil, err
	}
	p.SessionID = binary.BigEndian.Uint32(tmp)

	if p.Command == CmdTCPConnect || p.Command == CmdUDPAssociate {
		if _, err := io.ReadFull(r, tmp1); err != nil {
			return nil, err
		}
		p.AddrType = tmp1[0]

		if _, err := io.ReadFull(r, tmp1); err != nil {
			return nil, err
		}
		addrLen := tmp1[0]

		p.Addr = make([]byte, addrLen)
		if _, err := io.ReadFull(r, p.Addr); err != nil {
			return nil, err
		}

		tmp2 := make([]byte, 2)
		if _, err := io.ReadFull(r, tmp2); err != nil {
			return nil, err
		}
		p.Port = binary.BigEndian.Uint16(tmp2)
	}

	if _, err := io.ReadFull(r, tmp); err != nil {
		return nil, err
	}
	dataLen := binary.BigEndian.Uint32(tmp)

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, p.Data); err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *Packet) SetAddress(addrType uint8, addr []byte, port uint16) {
	p.AddrType = addrType
	p.Addr = addr
	p.Port = port
}

func (p *Packet) SetData(data []byte) {
	p.Data = data
}

func (p *Packet) GetAddress() string {
	if p.AddrType == AddrTypeDomain {
		return fmt.Sprintf("%s:%d", string(p.Addr), p.Port)
	}
	return fmt.Sprintf("%s:%d", p.Addr, p.Port)
}

