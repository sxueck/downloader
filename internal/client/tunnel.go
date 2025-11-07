package client

import (
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

type Tunnel struct {
	serverAddr string
	authToken  string
	conn       net.Conn
	sessions   sync.Map
	sessionID  uint32
	mu         sync.Mutex
	closed     atomic.Bool
}

type Session struct {
	ID         uint32
	LocalConn  net.Conn
	RemoteAddr string
	closeChan  chan struct{}
}

func NewTunnel(serverAddr, authToken string) *Tunnel {
	return &Tunnel{
		serverAddr: serverAddr,
		authToken:  authToken,
	}
}

func (t *Tunnel) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		ServerName: "",
	}

	conn, err := tls.Dial("tcp", t.serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	if _, err := conn.Write([]byte(t.authToken + "\n")); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send auth token: %w", err)
	}

	t.conn = conn
	go t.handleServerPackets()

	return nil
}

func (t *Tunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	t.sessions.Range(func(key, value interface{}) bool {
		if sess, ok := value.(*Session); ok {
			close(sess.closeChan)
			if sess.LocalConn != nil {
				sess.LocalConn.Close()
			}
		}
		return true
	})

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}

	return nil
}

func (t *Tunnel) nextSessionID() uint32 {
	return atomic.AddUint32(&t.sessionID, 1)
}

func (t *Tunnel) HandleTCPConnect(localConn net.Conn, addrType uint8, addr []byte, port uint16) error {
	sessionID := t.nextSessionID()

	session := &Session{
		ID:        sessionID,
		LocalConn: localConn,
		closeChan: make(chan struct{}),
	}
	t.sessions.Store(sessionID, session)

	pkt := protocol.NewPacket(protocol.CmdTCPConnect, sessionID)
	pkt.SetAddress(addrType, addr, port)

	data, err := pkt.Encode()
	if err != nil {
		return err
	}

	t.mu.Lock()
	if t.conn == nil {
		t.mu.Unlock()
		return fmt.Errorf("tunnel not connected")
	}
	_, err = t.conn.Write(data)
	t.mu.Unlock()

	if err != nil {
		t.sessions.Delete(sessionID)
		return err
	}

	go t.handleLocalRead(session)

	return nil
}

func (t *Tunnel) handleLocalRead(session *Session) {
	defer func() {
		t.sessions.Delete(session.ID)
		session.LocalConn.Close()

		pkt := protocol.NewPacket(protocol.CmdTCPClose, session.ID)
		if data, err := pkt.Encode(); err == nil {
			t.mu.Lock()
			if t.conn != nil {
				t.conn.Write(data)
			}
			t.mu.Unlock()
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-session.closeChan:
			return
		default:
		}

		session.LocalConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := session.LocalConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Session %d read error: %v", session.ID, err)
			}
			return
		}

		pkt := protocol.NewPacket(protocol.CmdTCPData, session.ID)
		pkt.SetData(buf[:n])

		data, err := pkt.Encode()
		if err != nil {
			log.Printf("Session %d encode error: %v", session.ID, err)
			return
		}

		t.mu.Lock()
		if t.conn == nil {
			t.mu.Unlock()
			return
		}
		_, err = t.conn.Write(data)
		t.mu.Unlock()

		if err != nil {
			log.Printf("Session %d write to tunnel error: %v", session.ID, err)
			return
		}
	}
}

func (t *Tunnel) handleServerPackets() {
	defer func() {
		t.Close()
	}()

	for {
		if t.closed.Load() {
			return
		}

		t.mu.Lock()
		conn := t.conn
		t.mu.Unlock()

		if conn == nil {
			return
		}

		pkt, err := protocol.DecodePacket(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to decode packet: %v", err)
			}
			return
		}

		switch pkt.Command {
		case protocol.CmdTCPData:
			t.handleTCPData(pkt)
		case protocol.CmdTCPClose:
			t.handleTCPClose(pkt)
		case protocol.CmdHeartbeat:
		case protocol.CmdError:
			log.Printf("Server error for session %d", pkt.SessionID)
			t.handleTCPClose(pkt)
		}
	}
}

func (t *Tunnel) handleTCPData(pkt *protocol.Packet) {
	value, ok := t.sessions.Load(pkt.SessionID)
	if !ok {
		return
	}

	session := value.(*Session)
	if len(pkt.Data) > 0 {
		session.LocalConn.Write(pkt.Data)
	}
}

func (t *Tunnel) handleTCPClose(pkt *protocol.Packet) {
	value, ok := t.sessions.Load(pkt.SessionID)
	if !ok {
		return
	}

	session := value.(*Session)
	t.sessions.Delete(pkt.SessionID)
	close(session.closeChan)
	session.LocalConn.Close()
}

func (t *Tunnel) HandleUDPAssociate(localAddr *net.UDPAddr, addrType uint8, addr []byte, port uint16) (*net.UDPConn, error) {
	sessionID := t.nextSessionID()

	pkt := protocol.NewPacket(protocol.CmdUDPAssociate, sessionID)
	pkt.SetAddress(addrType, addr, port)

	data, err := pkt.Encode()
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	if t.conn == nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("tunnel not connected")
	}
	_, err = t.conn.Write(data)
	t.mu.Unlock()

	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, err
	}

	return udpConn, nil
}
