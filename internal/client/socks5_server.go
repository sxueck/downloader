package client

import (
	"fmt"
	"log"
	"net"

	"github.com/sxueck/downloader/pkg/protocol"
	"github.com/sxueck/downloader/pkg/socks5"
)

type Socks5Server struct {
	port     int
	username string
	password string
	tunnel   *Tunnel
	listener net.Listener
}

func NewSocks5Server(port int, username, password string, tunnel *Tunnel) *Socks5Server {
	return &Socks5Server{
		port:     port,
		username: username,
		password: password,
		tunnel:   tunnel,
	}
}

func (s *Socks5Server) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	log.Printf("SOCKS5 server listening on %s", addr)

	go s.acceptLoop()
	return nil
}

func (s *Socks5Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Socks5Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			return
		}

		go s.handleConnection(conn)
	}
}

func (s *Socks5Server) handleConnection(conn net.Conn) {
	if err := socks5.Handshake(conn, s.username, s.password); err != nil {
		log.Printf("SOCKS5 handshake failed: %v", err)
		conn.Close()
		return
	}

	req, err := socks5.ReadRequest(conn)
	if err != nil {
		log.Printf("Failed to read SOCKS5 request: %v", err)
		conn.Close()
		return
	}

	switch req.Command {
	case socks5.CmdConnect:
		s.handleConnect(conn, req)
	case socks5.CmdUDPAssociate:
		s.handleUDPAssociate(conn, req)
	default:
		socks5.SendReply(conn, socks5.RepCommandNotSupported, nil)
		log.Printf("Unsupported SOCKS5 command: %d", req.Command)
		conn.Close()
	}
}

func (s *Socks5Server) handleConnect(conn net.Conn, req *socks5.Request) {
	defer conn.Close()

	if !s.tunnel.IsConnected() {
		log.Printf("Tunnel not connected, rejecting SOCKS5 connection")
		socks5.SendReply(conn, socks5.RepServerFailure, nil)
		return
	}

	if req.AddrType == socks5.AddrTypeIPv6 {
		log.Printf("IPv6 addresses are not supported, rejecting connection")
		socks5.SendReply(conn, socks5.RepAddrTypeNotSupported, nil)
		return
	}

	addrType := s.convertAddrType(req.AddrType)

	closeChan, err := s.tunnel.HandleTCPConnect(conn, addrType, req.DstAddr, req.DstPort)
	if err != nil {
		log.Printf("Failed to handle TCP connect: %v", err)
		socks5.SendReply(conn, socks5.RepServerFailure, nil)
		return
	}

	bindAddr := &net.TCPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 0,
	}
	if err := socks5.SendReply(conn, socks5.RepSuccess, bindAddr); err != nil {
		log.Printf("Failed to send SOCKS5 reply: %v", err)
		return
	}

	<-closeChan
}

func (s *Socks5Server) handleUDPAssociate(conn net.Conn, req *socks5.Request) {
	addrType := s.convertAddrType(req.AddrType)

	localAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	}

	udpConn, err := s.tunnel.HandleUDPAssociate(localAddr, addrType, req.DstAddr, req.DstPort)
	if err != nil {
		log.Printf("Failed to handle UDP associate: %v", err)
		socks5.SendReply(conn, socks5.RepServerFailure, nil)
		return
	}
	defer udpConn.Close()

	bindAddr := udpConn.LocalAddr().(*net.UDPAddr)
	if err := socks5.SendReply(conn, socks5.RepSuccess, bindAddr); err != nil {
		log.Printf("Failed to send SOCKS5 reply: %v", err)
		return
	}

	buf := make([]byte, 1)
	conn.Read(buf)
}

func (s *Socks5Server) convertAddrType(socksAddrType uint8) uint8 {
	switch socksAddrType {
	case socks5.AddrTypeIPv4:
		return protocol.AddrTypeIPv4
	case socks5.AddrTypeIPv6:
		return protocol.AddrTypeIPv6
	case socks5.AddrTypeDomain:
		return protocol.AddrTypeDomain
	default:
		return protocol.AddrTypeIPv4
	}
}
