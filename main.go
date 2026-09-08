package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type serverInfo struct {
	serverAddr string
	serverName string
	serverPath string
	serverHost string
	enableTLS  bool
	serverALPN []string
}

type serverURLs []string

func (s *serverURLs) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *serverURLs) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	listenAddr := flag.String("b", "127.0.0.1:10809", "Local socks5 listen address")
	//serverURL := flag.String("c", "", "Server URL")
	var serverURL serverURLs
	flag.Var(&serverURL, "c", "Server URL (can be specified multiple times)")
	flag.Parse()

	//	if *serverURL == "" {
	//		panic("Must run with -c Server URL")
	//	}
	//	si := parseServerURL(*serverURL)
	//	fmt.Println(si)
	if len(serverURL) == 0 {
		panic("Must run with -c Server URL")
	}
	servers := make([]*serverInfo, 0, len(serverURL))
	for _, url := range serverURL {
		si := parseServerURL(url)
		fmt.Println(si)
		servers = append(servers, si)
	}

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

		//go handle(c,si)
		//fmt.Println(servers[rand.IntN(len(servers))])
		go handle(c, servers[rand.IntN(len(servers))])
	}
}

func parseServerURL(serverURL string) *serverInfo {
	var si serverInfo
	u, err := url.Parse(serverURL)
	if err != nil {
		panic("url parse fail")
	}
	si.serverAddr = net.JoinHostPort(u.Hostname(), u.Port())
	si.serverName = u.Query().Get("sni")
	if si.serverName == "" {
		si.serverName = u.Hostname()
	}
	si.serverPath = u.Query().Get("path")
	si.enableTLS = u.Query().Get("security") == "tls"
	alpn := u.Query().Get("alpn")
	if alpn == "" {
		si.serverALPN = []string{"http/1.1"}
	} else {
		si.serverALPN = strings.Split(alpn, ",")
	}
	si.serverHost = u.Query().Get("host")
	return &si
}

func handle(c net.Conn, si *serverInfo) {
	defer c.Close()

	// SOCKS5 greeting
	if err := socks5Handshake(c); err != nil {
		return
	}

	host, port, err := socks5ReadRequest(c)
	if err != nil {
		return
	}

	// Reply Success 0
	if err := socks5Reply(c, 0x00); err != nil {
		return
	}

	fmt.Printf("SOCKS5 CONNECT %s:%d\n", host, port)

	remote, err := dialRemote(si)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer remote.Close()

	// relay
	//	go io.Copy(remote, c)
	//	io.Copy(c, remote)
	// 双向转发。
	errCh := make(chan error, 2)

	go func() {
		//Wrap here but not in dialRemote() for pack first stream together
		bw := bufio.NewWriter(remote)
		err := writeHTTPUpgradeRequest(bw, si)
		if err != nil {
			errCh <- err
			return
		}
		err = writeVLESSRequest(bw, host, port)
		if err != nil {
			errCh <- err
			return
		}
		buf := bw.AvailableBuffer()
		n, err := c.Read(buf[:cap(buf)])
		if err != nil {
			errCh <- err
			return
		}
		_, err = bw.Write(buf[:n])
		if err != nil {
			errCh <- err
			return
		}
		//fmt.Printf("%d\n", n)
		//Safely drain bufio.Writer
		err = bw.Flush()
		if err != nil {
			errCh <- err
			return
		}

		_, err = io.Copy(remote, c)
		errCh <- err
	}()

	go func() {
		//Unwrap here but not in diaRemote() for "0-rtt"
		br := bufio.NewReader(remote)
		err := readHTTPUpgradeResponse(br)
		if err != nil {
			errCh <- err
			return
		}
		err = readVLESSResponse(br)
		if err != nil {
			errCh <- err
			return
		}
		//Safely drain bufio.Reader
		_, err = io.CopyN(c, br, int64(br.Buffered()))
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

func dialRemote(si *serverInfo) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", si.serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	var conn net.Conn = raw

	if si.enableTLS {
		conn = tls.Client(raw, &tls.Config{
			ServerName: si.serverName,
			MinVersion: tls.VersionTLS13,
			NextProtos: si.serverALPN,
		})

		if err := conn.(*tls.Conn).Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
	}

	return conn, nil
}

func writeHTTPUpgradeRequest(bw *bufio.Writer, si *serverInfo) error {
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Host:   si.serverAddr,
			Path:   si.serverPath,
		},
		Host: si.serverHost,
		Header: http.Header{
			"User-Agent": []string{""},
			"Connection": []string{"Upgrade"},
			"Upgrade":    []string{"websocket"},
		},
	}
	return req.Write(bw)
}

func readHTTPUpgradeResponse(br *bufio.Reader) error {
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols ||
		strings.ToLower(resp.Header.Get("Upgrade")) != "websocket" ||
		strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
		return errors.New("HTTPUpgrade failed")
	}
	return nil
}

func readVLESSResponse(c *bufio.Reader) error {
	//VLESS Response
	//Version, Addon Length, Addon
	//expect 0,0
	var b [2]byte
	_, err := io.ReadFull(c, b[:])
	if err != nil {
		return err
	}
	if b != [2]byte{} {
		return errors.New("not VLESS")
	}
	return nil
}

func writeVLESSRequest(bw *bufio.Writer, host string, port uint16) error {
	//var b []byte
	b := make([]byte, 0, 278)

	// Version 1
	// UUID 16
	// AddonLen 1, [Addon]
	// Command 1
	// Port 2
	// AddrType 1, [DomainLen], IP/Domain

	b = append(b, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,
		0x01,
		byte(port>>8), byte(port))

	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		b = append(b, 0x02)
		b = append(b, byte(len(host)))
		b = append(b, host...)
	} else if ip6 := ip.To16(); ip6 != nil {
		b = append(b, 0x03)
		b = append(b, ip6...)
	} else if ip4 := ip.To4(); ip4 != nil {
		b = append(b, 0x01)
		b = append(b, ip4...)
	}

	_, err := bw.Write(b)
	return err
}
