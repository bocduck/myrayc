package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	userUUID   [16]byte
	serverAddr string
	serverName string
	serverPath string
	serverHost string
	enableTLS  bool
	serverALPN []string
)

func main() {
	listenAddr := flag.String("b", "127.0.0.1:10809", "Local socks5 listen address")
	serverURL := flag.String("c", "", "Server URL")
	flag.Parse()

	if *serverURL == "" {
		panic("Must run with -c Server URL")
	}

	u, err := url.Parse(*serverURL)
	if err != nil {
		panic("url parse fail")
	}
	serverAddr = net.JoinHostPort(u.Hostname(), u.Port())
	serverName = u.Query().Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	serverPath = u.Query().Get("path")
	enableTLS = u.Query().Get("security") == "tls"
	alpn := u.Query().Get("alpn")
	if alpn == "" {
		serverALPN = []string{"http/1.1"}
	} else {
		serverALPN = strings.Split(alpn, ",")
	}
	serverHost = u.Query().Get("host")

	fmt.Println(serverAddr, serverName, serverPath, enableTLS, serverALPN, serverHost)
	//panic("test")

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("SOCKS5 listening on", *listenAddr)

	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Println("accept:", err)
			continue
		}

		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()

	// SOCKS5 greeting
	if err := socks5Handshake(c); err != nil {
		return
	}

	host, port, err := socks5ReadRequest(c)
	if err != nil {
		return
	}

	// reply success early to get "earlydata"
	if err := socks5Reply(c, 0x00); err != nil {
		return
	}

	fmt.Printf("SOCKS5 CONNECT %s:%d\n", host, port)

	remote, err := dialVLESSHU(host, port)
	if err != nil {
		fmt.Println("dial:", err)
		//success replied early, fail should never trigger, just abort
		//socks5Reply(c, 0x01) // general failure
		return
	}
	defer remote.Close()

	// relay
	//	go io.Copy(remote, c)
	//	io.Copy(c, remote)
	// 双向转发。
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(remote, c)
		errCh <- err
	}()

	go func() {
		err := unpackVLESSHUResponse(c, remote)
		if err != nil {
			errCh <- err
			return
		}
		_, err = io.Copy(c, remote)
		errCh <- err
	}()

	err = <-errCh
	if err != nil {
		fmt.Println(err)
	}
}

func socks5Handshake(c net.Conn) error {
	// VER, NMETHODS
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}

	if h[0] != 0x05 {
		return errors.New("not SOCKS5")
	}

	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	// 0x00 = NO AUTHENTICATION REQUIRED
	_, err := c.Write([]byte{0x05, 0x00})
	return err
}

func socks5ReadRequest(c net.Conn) (string, uint16, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return "", 0, err
	}

	if h[0] != 0x05 {
		return "", 0, errors.New("bad SOCKS version")
	}

	if h[1] != 0x01 {
		return "", 0, errors.New("only CONNECT supported")
	}

	var host string

	switch h[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()

	case 0x03: // domain
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return "", 0, err
		}

		b := make([]byte, n[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}

		host = string(b)

	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()

	default:
		return "", 0, errors.New("unknown address type")
	}

	p := make([]byte, 2)
	if _, err := io.ReadFull(c, p); err != nil {
		return "", 0, err
	}

	port := binary.BigEndian.Uint16(p)
	return host, port, nil
}

func socks5Reply(c net.Conn, rep byte) error {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	_, err := c.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,
		0, 0, 0, 0,
		0, 0,
	})
	return err
}

func dialVLESSHU(host string, port uint16) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	var conn net.Conn = raw

	if enableTLS {
		conn = tls.Client(raw, &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS13,
			NextProtos: serverALPN,
		})

		if err := conn.(*tls.Conn).Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Host:   serverAddr,
			Path:   serverPath,
		},
		Host: serverHost,
		Header: http.Header{
			"User-Agent": []string{""},
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
	}

	// Optional normal HTTP headers.
	//req.Header.Set("User-Agent", "")

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Send VLESS request before HTTPUpgrade Response.
	if err := writeVLESSRequest(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func unpackVLESSHUResponse(dst, src net.Conn) error {
	br := bufio.NewReader(src)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("HTTPUpgrade: server returned %s", resp.Status)
	}

	if strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" {
		return errors.New("HTTPUpgrade: missing Upgrade: websocket")
	}

	if strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
		return errors.New("HTTPUpgrade: missing Connection: Upgrade")
	}

	//VLESS Response
	// Version
	var version [1]byte
	if _, err := io.ReadFull(br, version[:]); err != nil {
		return err
	}

	// Addon length
	var addonLen [1]byte
	if _, err := io.ReadFull(br, addonLen[:]); err != nil {
		return err
	}

	// Addon
	if _, err := io.CopyN(io.Discard, br, int64(addonLen[0])); err != nil {
		return err
	}

	io.CopyN(dst, br, int64(br.Buffered()))
	fmt.Printf("br ahead:%d\n", br.Buffered())

	return nil

}

func writeVLESSRequest(w io.Writer, host string, port uint16) error {
	var b []byte

	// Version
	b = append(b, 0x01)

	// UUID
	b = append(b, userUUID[:]...)

	// Addons length = 0
	b = append(b, 0x00)

	// Command = TCP
	b = append(b, 0x01)

	// Port
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	b = append(b, p...)

	// Address
	ip := net.ParseIP(host)

	if ip4 := ip.To4(); ip4 != nil {
		b = append(b, 0x01)
		b = append(b, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		b = append(b, 0x03)
		b = append(b, ip6...)
	} else {
		if len(host) > 255 {
			return errors.New("domain name too long")
		}

		b = append(b, 0x02)
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}

	_, err := w.Write(b)
	return err
}
