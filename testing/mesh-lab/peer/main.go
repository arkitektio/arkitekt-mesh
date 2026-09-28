// lab-peer joins the lab's tailnet as a tsnet node and serves what the
// integration tests reach: HTTP on :80 ("hello from peer"), and a TCP and a
// UDP echo on :7. It prints one JSON line once it is up.
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
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from peer")
	}))

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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
