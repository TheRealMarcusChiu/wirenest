// A real WireGuard peer on a userspace network stack, used only by smoke-two-tunnels.sh.
//
// Two utun interfaces on one Mac cannot exercise each other: the kernel delivers traffic
// between local addresses over lo0 and bypasses WireGuard. Netstack addresses are not
// local to the kernel, so a reply can only arrive through the tunnel under test.
//
// Keys arrive on stdin, one base64 value per line (private, then client public), so they
// never appear in argv.
//
// --bind-ip is for smoke-full-route.sh only. Stock wg-quick deletes a full tunnel's endpoint
// host route on the way down, so that peer must reply from a leased alias and never teach
// the client 127.0.0.1. Without the flag, the binding is the original default one.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// loopbackBind sends and receives on one socket bound to one IPv4 loopback address, so the
// kernel cannot choose another source address for replies.
type loopbackBind struct {
	addr   netip.Addr
	mu     sync.Mutex
	socket *net.UDPConn
}

var _ conn.Bind = (*loopbackBind)(nil)

type loopbackEndpoint netip.AddrPort

func (e loopbackEndpoint) ClearSrc()           {}
func (e loopbackEndpoint) SrcToString() string { return "" }
func (e loopbackEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e loopbackEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e loopbackEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e loopbackEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, errors.New("bind is already open")
	}
	socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.addr, port)))
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	receive := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, from, err := socket.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = loopbackEndpoint(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}

func (b *loopbackBind) SetMark(uint32) error { return nil }
func (b *loopbackBind) BatchSize() int       { return 1 }

func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	target, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !target.Addr().Is4() || !target.Addr().IsLoopback() {
		return nil, errors.New("endpoint must be an IPv4 loopback address")
	}
	return loopbackEndpoint(target), nil
}

func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	target, ok := ep.(loopbackEndpoint)
	if !ok {
		return errors.New("endpoint does not belong to this bind")
	}
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := socket.WriteToUDPAddrPort(buf, netip.AddrPort(target)); err != nil {
			return err
		}
	}
	return nil
}

func newBind(bindIP string) (conn.Bind, error) {
	if bindIP == "" {
		return conn.NewDefaultBind(), nil
	}
	addr, err := netip.ParseAddr(bindIP)
	if err != nil {
		return nil, err
	}
	if !addr.Is4() || !addr.IsLoopback() {
		return nil, errors.New("--bind-ip must be an IPv4 loopback address")
	}
	return &loopbackBind{addr: addr}, nil
}

// checkBindSource does a real round trip through the bind the peer would use, from an unbound
// client socket like the one WireGuard's client uses, and checks where the reply came from.
func checkBindSource(bindIP string) error {
	bind, err := newBind(bindIP)
	if err != nil {
		return err
	}
	if bindIP == "" {
		return errors.New("--check-bind-source needs --bind-ip")
	}
	fns, port, err := bind.Open(0)
	if err != nil {
		return err
	}
	defer bind.Close()
	client, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	go func() {
		packets, sizes, eps := [][]byte{make([]byte, 64)}, []int{0}, []conn.Endpoint{nil}
		if n, err := fns[0](packets, sizes, eps); err == nil && n == 1 {
			_ = bind.Send([][]byte{packets[0][:sizes[0]]}, eps[0])
		}
	}()

	want := netip.AddrPortFrom(netip.MustParseAddr(bindIP), port)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if _, err := client.WriteToUDPAddrPort(nonce, want); err != nil {
		return err
	}
	reply := make([]byte, 64)
	n, from, err := client.ReadFromUDPAddrPort(reply)
	if err != nil {
		return err
	}
	if got := netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); got != want {
		return fmt.Errorf("reply came from %s, expected %s", got, want)
	}
	if !bytes.Equal(reply[:n], nonce) {
		return errors.New("reply did not match the request")
	}
	return nil
}

func readKey(in *bufio.Scanner) string {
	if !in.Scan() {
		log.Fatal("missing key on stdin")
	}
	key, err := base64.StdEncoding.DecodeString(in.Text())
	if err != nil || len(key) != 32 {
		log.Fatal("invalid key on stdin")
	}
	return hex.EncodeToString(key)
}

func main() {
	addr := flag.String("addr", "", "address of this peer inside the tunnel")
	client := flag.String("client", "", "tunnel address of the client")
	udpPort := flag.Int("udp-port", 0, "WireGuard UDP listen port")
	httpPort := flag.Int("http-port", 0, "TCP port served inside the tunnel")
	token := flag.String("token", "", "response body identifying this peer")
	bindIP := flag.String("bind-ip", "", "IPv4 loopback address to bind and reply from; default binds the wildcard")
	checkSource := flag.Bool("check-bind-source", false, "check that --bind-ip replies come from that address, then exit")
	flag.Parse()

	if *checkSource {
		if err := checkBindSource(*bindIP); err != nil {
			log.Fatal(err)
		}
		fmt.Println("BIND_SOURCE_OK", *bindIP)
		return
	}
	bind, err := newBind(*bindIP)
	if err != nil {
		log.Fatal(err)
	}

	in := bufio.NewScanner(os.Stdin)
	privateKey := readKey(in)
	clientKey := readKey(in)

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(*addr)}, nil, 1280)
	if err != nil {
		log.Fatal(err)
	}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, "peer: "))
	err = dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=%s/32\n",
		privateKey, *udpPort, clientKey, netip.MustParseAddr(*client)))
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: *httpPort})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, *token)
	})))
}
