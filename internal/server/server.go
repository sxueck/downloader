package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sxueck/downloader/pkg/protocol"
)

type Server struct {
	listen      string
	authToken   string
	tlsCert     string
	tlsKey      string
	maxConns    int
	idleTimeout int
	listener    net.Listener
	connCount   atomic.Int32
	sessions    sync.Map
}

type ClientSession struct {
	conn      net.Conn
	sessions  sync.Map
	closeChan chan struct{}
}

type TCPSession struct {
	ID         uint32
	RemoteConn net.Conn
	closeChan  chan struct{}
}

func NewServer(listen, authToken, tlsCert, tlsKey string, maxConns, idleTimeout int) *Server {
	return &Server{
		listen:      listen,
		authToken:   authToken,
		tlsCert:     tlsCert,
		tlsKey:      tlsKey,
		maxConns:    maxConns,
		idleTimeout: idleTimeout,
	}
}

func (s *Server) Start() error {
	cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	listener, err := tls.Listen("tcp", s.listen, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listen, err)
	}

	s.listener = listener
	log.Printf("Server started")

	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			return
		}

		if int(s.connCount.Load()) >= s.maxConns {
			log.Printf("Max connections reached, rejecting connection")
			conn.Close()
			continue
		}

		s.connCount.Add(1)
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer func() {
		conn.Close()
		s.connCount.Add(-1)
	}()

	reader := bufio.NewReader(conn)
	token, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read auth token: %v", err)
		return
	}

	token = token[:len(token)-1]
	if token != s.authToken {
		log.Printf("Invalid auth token")
		return
	}

	log.Printf("Client authenticated")

	session := &ClientSession{
		conn:      conn,
		closeChan: make(chan struct{}),
	}

	s.handleClientPackets(session)
}

func (s *Server) handleClientPackets(session *ClientSession) {
	defer func() {
		close(session.closeChan)
		session.sessions.Range(func(key, value interface{}) bool {
			if tcpSess, ok := value.(*TCPSession); ok {
				close(tcpSess.closeChan)
				if tcpSess.RemoteConn != nil {
					tcpSess.RemoteConn.Close()
				}
			}
			return true
		})
	}()

	for {
		pkt, err := protocol.DecodePacket(session.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to decode packet: %v", err)
			}
			return
		}

		switch pkt.Command {
		case protocol.CmdTCPConnect:
			s.handleTCPConnect(session, pkt)
		case protocol.CmdTCPData:
			s.handleTCPData(session, pkt)
		case protocol.CmdTCPClose:
			s.handleTCPClose(session, pkt)
		case protocol.CmdUDPAssociate:
			s.handleUDPAssociate(session, pkt)
		case protocol.CmdHeartbeat:
		default:
			log.Printf("Unknown command: %d", pkt.Command)
		}
	}
}

func (s *Server) handleTCPConnect(session *ClientSession, pkt *protocol.Packet) {
	addr := pkt.GetAddress()
	log.Printf("New TCP session %d to %s", pkt.SessionID, addr)

	targetAddr, err := s.resolveIPv4Address(pkt)
	if err != nil {
		log.Printf("Session %d address resolution failed: %v, addr=%s", pkt.SessionID, err, addr)
		s.sendError(session.conn, pkt.SessionID, err.Error())
		return
	}

	remoteConn, err := net.DialTimeout("tcp4", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Session %d connection failed: %v, addr=%s", pkt.SessionID, err, targetAddr)
		s.sendError(session.conn, pkt.SessionID, err.Error())
		return
	}

	tcpSess := &TCPSession{
		ID:         pkt.SessionID,
		RemoteConn: remoteConn,
		closeChan:  make(chan struct{}),
	}
	session.sessions.Store(pkt.SessionID, tcpSess)

	go s.handleRemoteRead(session, tcpSess)
}

func (s *Server) resolveIPv4Address(pkt *protocol.Packet) (string, error) {
	if pkt.AddrType == protocol.AddrTypeDomain {
		domain := string(pkt.Addr)
		return fmt.Sprintf("%s:%d", domain, pkt.Port), nil
	}

	if pkt.AddrType == protocol.AddrTypeIPv4 && len(pkt.Addr) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d:%d",
			pkt.Addr[0], pkt.Addr[1], pkt.Addr[2], pkt.Addr[3], pkt.Port), nil
	}

	if pkt.AddrType == protocol.AddrTypeIPv6 {
		return "", fmt.Errorf("IPv6 addresses are not supported, please use domain names or IPv4")
	}

	return "", fmt.Errorf("unsupported address type: %d", pkt.AddrType)
}

func (s *Server) handleTCPData(session *ClientSession, pkt *protocol.Packet) {
	value, ok := session.sessions.Load(pkt.SessionID)
	if !ok {
		return
	}

	tcpSess := value.(*TCPSession)
	if len(pkt.Data) > 0 {
		tcpSess.RemoteConn.Write(pkt.Data)
	}
}

func (s *Server) handleTCPClose(session *ClientSession, pkt *protocol.Packet) {
	value, ok := session.sessions.Load(pkt.SessionID)
	if !ok {
		return
	}

	tcpSess := value.(*TCPSession)
	session.sessions.Delete(pkt.SessionID)
	close(tcpSess.closeChan)
	tcpSess.RemoteConn.Close()
}

func (s *Server) handleRemoteRead(session *ClientSession, tcpSess *TCPSession) {
	defer func() {
		session.sessions.Delete(tcpSess.ID)
		tcpSess.RemoteConn.Close()

		closePkt := protocol.NewPacket(protocol.CmdTCPClose, tcpSess.ID)
		if data, err := closePkt.Encode(); err == nil {
			session.conn.Write(data)
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-tcpSess.closeChan:
			return
		case <-session.closeChan:
			return
		default:
		}

		tcpSess.RemoteConn.SetReadDeadline(time.Now().Add(time.Duration(s.idleTimeout) * time.Second))
		n, err := tcpSess.RemoteConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Session %d read error: %v", tcpSess.ID, err)
			}
			return
		}

		pkt := protocol.NewPacket(protocol.CmdTCPData, tcpSess.ID)
		pkt.SetData(buf[:n])

		data, err := pkt.Encode()
		if err != nil {
			log.Printf("Session %d encode error: %v", tcpSess.ID, err)
			return
		}

		if _, err := session.conn.Write(data); err != nil {
			log.Printf("Session %d write to client error: %v", tcpSess.ID, err)
			return
		}
	}
}

func (s *Server) handleUDPAssociate(session *ClientSession, pkt *protocol.Packet) {
	log.Printf("New UDP session %d", pkt.SessionID)
}

func (s *Server) sendError(conn net.Conn, sessionID uint32, reason string) {
	pkt := protocol.NewPacket(protocol.CmdError, sessionID)
	if reason != "" {
		pkt.SetData([]byte(reason))
	}
	if data, err := pkt.Encode(); err == nil {
		conn.Write(data)
	}
}
