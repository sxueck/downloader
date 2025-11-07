package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sxueck/downloader/pkg/protocol"
)

type Tunnel struct {
	serverAddr        string
	authToken         string
	conn              net.Conn
	sessions          sync.Map
	sessionID         uint32
	mu                sync.Mutex
	closed            atomic.Bool
	reconnectChan     chan struct{}
	reconnectInterval time.Duration
	connected         atomic.Bool
}

type Session struct {
	ID         uint32
	LocalConn  net.Conn
	RemoteAddr string
	closeChan  chan struct{}
}

func NewTunnel(serverAddr, authToken string) *Tunnel {
	return &Tunnel{
		serverAddr:        serverAddr,
		authToken:         authToken,
		reconnectChan:     make(chan struct{}, 1),
		reconnectInterval: 5 * time.Second,
	}
}

func (t *Tunnel) IsConnected() bool {
	return t.connected.Load()
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
	t.connected.Store(true)
	go t.handleServerPackets()

	return nil
}

func (t *Tunnel) StartReconnectLoop() {
	go func() {
		for {
			if t.closed.Load() {
				return
			}

			<-t.reconnectChan
			if t.closed.Load() {
				return
			}

			log.Println("Attempting to reconnect to server...")
			for i := 0; i < 10; i++ {
				if t.closed.Load() {
					return
				}

				if err := t.Connect(); err != nil {
					log.Printf("Reconnection attempt %d failed: %v", i+1, err)
					time.Sleep(t.reconnectInterval)
					continue
				}

				log.Println("Reconnected to server successfully")
				break
			}
		}
	}()
}

func (t *Tunnel) triggerReconnect() {
	select {
	case t.reconnectChan <- struct{}{}:
	default:
	}
}

func (t *Tunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}

	t.sessions.Range(func(key, value any) bool {
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
	t.connected.Store(false)

	return nil
}

func (t *Tunnel) nextSessionID() uint32 {
	return atomic.AddUint32(&t.sessionID, 1)
}

func (t *Tunnel) HandleTCPConnect(localConn net.Conn, addrType uint8, addr []byte, port uint16) (<-chan struct{}, error) {
	if !t.IsConnected() {
		return nil, fmt.Errorf("tunnel not connected")
	}

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
		t.sessions.Delete(sessionID)
		return nil, err
	}

	t.mu.Lock()
	if t.conn == nil {
		t.mu.Unlock()
		t.sessions.Delete(sessionID)
		return nil, fmt.Errorf("tunnel not connected")
	}
	_, err = t.conn.Write(data)
	t.mu.Unlock()

	if err != nil {
		t.sessions.Delete(sessionID)
		return nil, err
	}

	go t.handleLocalRead(session)

	return session.closeChan, nil
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
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
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
		t.mu.Lock()
		if t.conn != nil {
			t.conn.Close()
			t.conn = nil
		}
		t.mu.Unlock()
		t.connected.Store(false)

		if !t.closed.Load() {
			log.Println("Connection lost, triggering reconnect...")
			t.triggerReconnect()
		}
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
			if len(pkt.Data) > 0 {
				log.Printf("Server error for session %d: %s", pkt.SessionID, string(pkt.Data))
			}
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

func (t *Tunnel) SendHeartbeat() error {
	if !t.IsConnected() {
		return fmt.Errorf("tunnel not connected")
	}

	pkt := protocol.NewPacket(protocol.CmdHeartbeat, 0)
	data, err := pkt.Encode()
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return fmt.Errorf("tunnel not connected")
	}

	_, err = t.conn.Write(data)
	return err
}
