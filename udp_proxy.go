package wireproxy

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// udpSession represents a UDP forwarding session, keyed by the local source address.
// remoteConn is the UDP connection to the remote endpoint (on the WireGuard side).
type udpSession struct {
	remoteConn    net.Conn
	lastActive    time.Time
	closeChan     chan struct{}
	inactivityDur time.Duration
}

// SpawnRoutine implements the RoutineSpawner interface.
// It starts listening on config.BindAddress, handling each unique source (client) address
// with its own udpSession. If InactivityTimeout > 0, sessions automatically close after inactivity
func (conf *UDPProxyTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	addr, err := net.ResolveUDPAddr("udp", conf.BindAddress)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not resolve bind address %s: %v", conf.BindAddress, err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not listen on %s: %v", conf.BindAddress, err)
	}
	log.Printf("UDPProxyTunnel listening on %s, forwarding to %s", conf.BindAddress, conf.Target)

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second
	sessions := make(map[string]*udpSession)
	var sessionMu sync.Mutex

	// Periodically clean up expired sessions if inactivity timeout is enabled
	if conf.InactivityTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				sessionMu.Lock()
				for key, sess := range sessions {
					if now.Sub(sess.lastActive) >= inactivityDur {
						log.Printf("UDPProxyTunnel: closing inactive session for %s", key)
						close(sess.closeChan)
						delete(sessions, key)
					}
				}
				sessionMu.Unlock()
			}
		}()
	}

	// Create or get a UDP session based on the local source address
	getOrCreateSession := func(srcAddr string) (*udpSession, error) {
		sessionMu.Lock()
		defer sessionMu.Unlock()

		// return if session already exists
		if s, ok := sessions[srcAddr]; ok {
			s.lastActive = time.Now()
			return s, nil
		}

		// Create a new session
		remoteConn, err := vt.Tnet.Dial("udp", conf.Target)
		if err != nil {
			return nil, fmt.Errorf("UDPProxyTunnel: could not Dial(%s): %w", conf.Target, err)
		}

		s := &udpSession{
			remoteConn:    remoteConn,
			lastActive:    time.Now(),
			closeChan:     make(chan struct{}),
			inactivityDur: inactivityDur,
		}
		sessions[srcAddr] = s

		// Spin up a goroutine to handle traffic from remote -> local
		go conf.handleRemoteToLocal(listener, srcAddr, s)
		return s, nil
	}

	// Main loop to read from local client and forward to remote
	go func() {
		buf := make([]byte, 64*1024) // typical max UDP size
		for {
			n, src, err := listener.ReadFromUDP(buf)
			if err != nil {
				log.Printf("UDPProxyTunnel: error reading from UDP: %v", err)
				continue
			}

			srcKey := src.String() // identify session by the local client's IP:port
			s, err := getOrCreateSession(srcKey)
			if err != nil {
				errorLogger.Printf("UDPProxyTunnel: getOrCreateSession failed for %s: %v", srcKey, err)
				continue
			}

			s.lastActive = time.Now()
			_, err = s.remoteConn.Write(buf[:n])
			if err != nil {
				errorLogger.Printf("UDPProxyTunnel: could not write to remote (%s): %v", conf.Target, err)
			}
		}
	}()
}

// handles data from the remote WireGuard side back to the local client
// this function blocks until the session is closed
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(listener *net.UDPConn, srcAddr string, s *udpSession) {
	defer func() {
		_ = s.remoteConn.Close()
	}()
	buf := make([]byte, 64*1024)

	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		_ = s.remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := s.remoteConn.Read(buf)
		if err != nil {
			// If a timeout or temporary error, continue to see if the session is closed
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-s.closeChan:
					return
				default:
					continue
				}
			}
			errorLogger.Printf("UDPProxyTunnel: read error from remote: %v", err)
			return
		}

		s.lastActive = time.Now()

		dstUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr)
		if err != nil {
			errorLogger.Printf("UDPProxyTunnel: cannot resolve local address %s: %v", srcAddr, err)
			return
		}

		_, err = listener.WriteToUDP(buf[:n], dstUDPAddr)
		if err != nil {
			errorLogger.Printf("UDPProxyTunnel: cannot write to local %s: %v", srcAddr, err)
			return
		}
	}
}
