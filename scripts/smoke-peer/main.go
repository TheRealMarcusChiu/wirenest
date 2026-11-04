// A real WireGuard peer on a userspace network stack, used only by smoke-two-tunnels.sh.
//
// Two utun interfaces on one Mac cannot exercise each other: the kernel delivers traffic
// between local addresses over lo0 and bypasses WireGuard. Netstack addresses are not
// local to the kernel, so a reply can only arrive through the tunnel under test.
//
// Keys arrive on stdin, one base64 value per line (private, then client public), so they
// never appear in argv.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

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
	flag.Parse()

	in := bufio.NewScanner(os.Stdin)
	privateKey := readKey(in)
	clientKey := readKey(in)

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(*addr)}, nil, 1280)
	if err != nil {
		log.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "peer: "))
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
