// lab-peer joins the lab's tailnet as a tsnet node and serves what the
// integration tests reach: HTTP on :80 ("hello from peer"), and a TCP and a
// UDP echo on :7. It prints one JSON line once it is up. For the benchmarks
// its HTTP also serves /bytes?n=N and drains POSTs to /sink.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"tailscale.com/tsnet"
)

func main() {
	srv := &tsnet.Server{
		Dir:        envOr("PEER_STATE", "/var/lib/lab-peer"),
		Hostname:   envOr("PEER_HOSTNAME", "lab-peer"),
		ControlURL: os.Getenv("PEER_CONTROL_URL"),
		AuthKey:    os.Getenv("PEER_AUTH_KEY"),
		Logf:       func(string, ...any) {},
	}
	status, err := srv.Up(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	ip := status.TailscaleIPs[0].String()

	web, err := srv.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(web, http.HandlerFunc(peerHandler))

	echo, err := srv.Listen("tcp", ":7")
	if err != nil {
		log.Fatal(err)
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

	udp, err := srv.ListenPacket("udp", net.JoinHostPort(ip, "7"))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], from)
		}
	}()

	line, _ := json.Marshal(map[string]string{"event": "ready", "name": srv.Hostname, "ip": ip})
	fmt.Println(string(line))
	select {}
}

// peerHandler answers "hello from peer", and for the benchmarks
// (tests/bench.rs) serves /bytes?n=N (N zero bytes) and drains a POST to
// /sink, answering how many bytes arrived.
func peerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/bytes":
		n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		chunk := make([]byte, 64<<10)
		for n > 0 {
			m := min(n, int64(len(chunk)))
			if _, err := w.Write(chunk[:m]); err != nil {
				return
			}
			n -= m
		}
	case "/sink":
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, n)
	default:
		fmt.Fprint(w, "hello from peer")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
