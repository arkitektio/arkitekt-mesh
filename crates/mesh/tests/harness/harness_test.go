// A tailnet for the Rust client's end-to-end tests: tailscale's test
// coordination server, a DERP and STUN server, and a tsnet peer, all on
// 127.0.0.1.
//
//	MESH_HARNESS=1 go test -run TestHarness -count=1 .
//
// It prints one JSON line on stdout (see Ready) and serves until stdin closes.
// The peer answers HTTP on :80 ("hello from peer") and echoes TCP and UDP
// on :7.
//
// With MESH_HARNESS_OPEN=1 registrations need no auth key, as a joined node
// restarting against ionscale needs none. MESH_HARNESS_FAKE_PEERS=N adds N
// offline peers that look like real ones in the netmap (for memory tests).
// MESH_HARNESS_TWO_REGIONS=1 serves two DERP regions, where region 1's STUN
// answers nothing (as if far away or filtered): a node homing by measured
// latency picks region 2, one picking the lowest id picks 1.
// MESH_HARNESS_LOCK=1 locks the tailnet (tailnet lock) with a key the peer
// holds, after the peer is up; each "sign nodekey:<hex>" line on stdin then
// signs that node's key (it must have registered first).
// MESH_HARNESS_ADDR binds everything to that address instead of 127.0.0.1,
// so devices on the network (an ESP32 on Wi-Fi or PPP) can join.
package harness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const authKey = "tskey-arkitekt-harness"

// Ready is the line the Rust tests read.
type Ready struct {
	ControlURL string `json:"control_url"`
	AuthKey    string `json:"auth_key"`
	PeerName   string `json:"peer_name"`
	PeerIP     string `json:"peer_ip"`
	Domain     string `json:"domain"`
}

func TestHarness(t *testing.T) {
	if os.Getenv("MESH_HARNESS") == "" {
		t.Skip("run by the Rust tests (MESH_HARNESS=1)")
	}
	logf := logger.Discard
	if os.Getenv("MESH_HARNESS_VERBOSE") != "" {
		logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
	}

	netns.SetEnabled(false)
	const domain = "tail-scale.ts.net"
	addr := os.Getenv("MESH_HARNESS_ADDR")
	if addr == "" {
		addr = "127.0.0.1"
	}
	derpMap := integration.RunDERPAndSTUN(t, logf, addr)
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Is6() {
		// RunDERPAndSTUN puts the address in IPv4, which Go's DERP client
		// only dials if it is IPv4: move it to IPv6.
		// Its STUN server is IPv4 only: answer STUN on the IPv6 address too.
		stun6 := serveSTUN6(t, addr)
		for _, region := range derpMap.Regions {
			for _, n := range region.Nodes {
				n.IPv4, n.IPv6 = "none", addr
				n.STUNPort = stun6
			}
		}
	}
	if os.Getenv("MESH_HARNESS_TWO_REGIONS") != "" {
		second := integration.RunDERPAndSTUN(t, logf, addr).Regions[1]
		second.RegionID = 2
		second.RegionCode = "second"
		for _, n := range second.Nodes {
			n.RegionID = 2
			n.Name = "2a"
		}
		derpMap.Regions[2] = second
		// Region 1's STUN goes to a port nothing answers on.
		dead, err := net.ListenPacket("udp", net.JoinHostPort(addr, "0"))
		if err != nil {
			t.Fatal(err)
		}
		deadPort := dead.LocalAddr().(*net.UDPAddr).Port
		dead.Close()
		for _, n := range derpMap.Regions[1].Nodes {
			n.STUNPort = deadPort
		}
	}
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: domain,
		Logf:           logf,
	}
	if os.Getenv("MESH_HARNESS_OPEN") == "" {
		control.RequireAuthKey = authKey
	}
	if n, _ := strconv.Atoi(os.Getenv("MESH_HARNESS_FAKE_PEERS")); n > 0 {
		addFakePeers(control, n)
	}
	locked := os.Getenv("MESH_HARNESS_LOCK") != ""
	if locked {
		// As tailscale's tsnet test does: nodes may initialize the lock.
		control.DefaultNodeCapabilities = &tailcfg.NodeCapMap{tailcfg.CapabilityTailnetLock: nil}
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	// MESH_HARNESS_CONTROL_PORT pins the control port, so a device can keep
	// its baked-in control URL across harness restarts.
	controlPort := os.Getenv("MESH_HARNESS_CONTROL_PORT")
	if controlPort == "" {
		controlPort = "0"
	}
	if addr != "127.0.0.1" || controlPort != "0" {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, controlPort))
		if err != nil {
			t.Fatal(err)
		}
		control.HTTPTestServer.Listener.Close()
		control.HTTPTestServer.Listener = ln
	}
	control.HTTPTestServer.Start()
	defer control.HTTPTestServer.Close()
	controlURL := control.HTTPTestServer.URL

	ctx := context.Background()
	peer := &tsnet.Server{
		Dir:        t.TempDir(),
		Hostname:   "peer",
		ControlURL: controlURL,
		AuthKey:    authKey,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logf,
	}
	defer peer.Close()
	status, err := peer.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}

	web, err := peer.Listen("tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from peer")
	}))
	echo, err := peer.Listen("tcp", ":7")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	udpEcho, err := peer.ListenPacket("udp", net.JoinHostPort(status.TailscaleIPs[0].String(), "7"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			udpEcho.WriteTo(buf[:n], from)
		}
	}()

	var lc *local.Client
	if locked {
		lc, err = peer.LocalClient()
		if err != nil {
			t.Fatal(err)
		}
		st, err := lc.TailnetLockStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		trusted := []tka.Key{{Kind: tka.Key25519, Public: st.PublicKey.Verifier(), Votes: 2}}
		disablement := bytes.Repeat([]byte{0xa5}, 32)
		if _, err := lc.TailnetLockInit(ctx, trusted, [][]byte{tka.DisablementKDF(disablement)}, nil); err != nil {
			t.Fatal(err)
		}
		// Push a map update, so the peer learns the tailnet is now locked.
		if st.NodeKey != nil {
			control.UpdateNode(control.Node(*st.NodeKey))
		}
		for i := 0; ; i++ {
			st, err := lc.TailnetLockStatus(ctx)
			if err == nil && st.Enabled && st.NodeKeySigned {
				break
			}
			if i > 200 {
				t.Fatalf("tailnet lock did not come up: %+v %v", st, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	line, _ := json.Marshal(Ready{
		ControlURL: controlURL,
		AuthKey:    authKey,
		PeerName:   "peer",
		PeerIP:     status.TailscaleIPs[0].String(),
		Domain:     domain,
	})
	fmt.Fprintf(os.Stdout, "%s\n", line)

	// Serve until stdin closes; "sign nodekey:<hex>" lines sign node keys.
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cmd, arg, _ := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if cmd != "sign" || lc == nil {
			continue
		}
		var nk key.NodePublic
		if err := nk.UnmarshalText([]byte(arg)); err != nil {
			fmt.Fprintf(os.Stderr, "sign: %v\n", err)
			continue
		}
		if err := lc.TailnetLockSign(ctx, nk, nil); err != nil {
			fmt.Fprintf(os.Stderr, "sign: %v\n", err)
			continue
		}
		fmt.Fprintf(os.Stdout, "{\"event\":\"signed\",\"key\":%q}\n", arg)
	}
}

// addFakePeers adds n peers carrying what real peers carry in a netmap:
// a name, endpoints, a home DERP, Hostinfo with services, tags and caps.
func addFakePeers(control *testcontrol.Server, n int) {
	for range n {
		control.AddFakeNode()
	}
	for i, node := range control.AllNodes() {
		host := fmt.Sprintf("fake-peer-%04d", i)
		node.Name = host + ".tail-scale.ts.net."
		node.HomeDERP = 1
		node.Tags = []string{"tag:arkitekt", "tag:worker"}
		node.Endpoints = []netip.AddrPort{
			netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:41641", i%250+1)),
			netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:41641", i%250+1)),
			netip.MustParseAddrPort("[2001:db8::1]:41641"),
		}
		node.Hostinfo = (&tailcfg.Hostinfo{
			Hostname:     host,
			OS:           "linux",
			OSVersion:    "6.8.0-45-generic",
			IPNVersion:   "1.102.5-t0000000-g0000000",
			GoArch:       "amd64",
			BackendLogID: fmt.Sprintf("%064x", i),
			Services: []tailcfg.Service{
				{Proto: tailcfg.TCP, Port: 22, Description: "sshd"},
				{Proto: tailcfg.TCP, Port: 8080, Description: "arkitekt-agent"},
				{Proto: tailcfg.PeerAPI4, Port: 41000},
			},
			NetInfo: &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: "true"},
		}).View()
		node.CapMap = tailcfg.NodeCapMap{"https://tailscale.com/cap/is-admin": nil, "funnel": nil}
		control.UpdateNode(node)
	}
}

// serveSTUN6 answers STUN binding requests on addr (IPv6) and returns the port.
func serveSTUN6(t *testing.T, addr string) int {
	pc, err := net.ListenPacket("udp6", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			pc.WriteTo(stun.Response(tx, from.(*net.UDPAddr).AddrPort()), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
