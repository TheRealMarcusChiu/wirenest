// Tests for the test-only loopback bind. Build needs the pinned wireguard-go module, so run from
// its source tree the way build-tools.sh builds the peer: copy both files into smokepeer/, then
// `go test ./smokepeer`. These use 127.0.0.1 only; real aliases are checked by --check-bind-source.
package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func openLoopback(t *testing.T) (*loopbackBind, []conn.ReceiveFunc, uint16) {
	t.Helper()
	bind, err := newBind("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fns) != 1 || port == 0 {
		t.Fatalf("Open returned %d functions and port %d", len(fns), port)
	}
	t.Cleanup(func() { bind.Close() })
	return bind.(*loopbackBind), fns, port
}

func TestNewBindKeepsDefaultWithoutFlag(t *testing.T) {
	bind, err := newBind("")
	if err != nil {
		t.Fatal(err)
	}
	if _, loopback := bind.(*loopbackBind); loopback {
		t.Fatal("no --bind-ip must keep the default bind")
	}
}

func TestNewBindRefusesAnythingButIPv4Loopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0", "192.0.2.1", "::1", "::ffff:127.0.0.1", "localhost", "127.0.0.1:80"} {
		if _, err := newBind(bad); err == nil {
			t.Errorf("newBind(%q) succeeded", bad)
		}
	}
}

func TestCheckBindSource(t *testing.T) {
	if err := checkBindSource("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := checkBindSource(""); err == nil {
		t.Fatal("check without --bind-ip succeeded")
	}
}

func TestOpenTwiceFailsAndCloseAllowsReopenOnSamePort(t *testing.T) {
	bind, _, port := openLoopback(t)
	if _, _, err := bind.Open(0); err == nil {
		t.Fatal("second Open succeeded")
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, reopened, err := bind.Open(port); err != nil || reopened != port {
		t.Fatalf("reopen on %d returned %d, %v", port, reopened, err)
	}
}

func TestCloseEndsReceive(t *testing.T) {
	bind, fns, _ := openLoopback(t)
	done := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 16)}, []int{0}, []conn.Endpoint{nil})
		done <- err
	}()
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive ended with %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return after Close")
	}
}

func TestSendRepliesFromBoundAddressAndSendsWholeBatch(t *testing.T) {
	bind, fns, port := openLoopback(t)
	client, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), target); err != nil {
		t.Fatal(err)
	}

	packets, sizes, eps := [][]byte{make([]byte, 16)}, []int{0}, []conn.Endpoint{nil}
	n, err := fns[0](packets, sizes, eps)
	if err != nil || n != 1 || !bytes.Equal(packets[0][:sizes[0]], []byte("ping")) {
		t.Fatalf("receive: n=%d err=%v packet=%q", n, err, packets[0][:sizes[0]])
	}
	if !eps[0].DstIP().IsLoopback() || !eps[0].DstIP().Is4() {
		t.Fatalf("endpoint address %s", eps[0].DstIP())
	}
	if eps[0].SrcIP().IsValid() || eps[0].SrcToString() != "" {
		t.Fatal("this bind has no sticky source to report")
	}
	if len(eps[0].DstToBytes()) == 0 || eps[0].DstToString() == "" {
		t.Fatal("cookies and logging need the destination")
	}

	if err := bind.Send([][]byte{[]byte("one"), []byte("two")}, eps[0]); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		reply := make([]byte, 16)
		n, from, err := client.ReadFromUDPAddrPort(reply)
		if err != nil {
			t.Fatal(err)
		}
		if got := netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); got != target {
			t.Fatalf("reply from %s, want %s", got, target)
		}
		if string(reply[:n]) != want {
			t.Fatalf("reply %q, want %q", reply[:n], want)
		}
	}
}

type otherEndpoint struct{ conn.Endpoint }

func TestSendRefusesForeignEndpointAndClosedBind(t *testing.T) {
	bind, _, port := openLoopback(t)
	if err := bind.Send([][]byte{[]byte("x")}, otherEndpoint{}); err == nil {
		t.Fatal("Send accepted another bind's endpoint")
	}
	ep, err := bind.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("x")}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestParseEndpointAcceptsOnlyIPv4Loopback(t *testing.T) {
	bind, _, _ := openLoopback(t)
	if _, err := bind.ParseEndpoint("127.77.0.2:51820"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"192.0.2.1:51820", "[::1]:51820", "127.0.0.1", "nonsense"} {
		if _, err := bind.ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) succeeded", bad)
		}
	}
}
