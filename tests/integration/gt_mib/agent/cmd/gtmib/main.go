// Command gtmib runs one GT-MIB agent for one case, for V-M1's runner (D6,
// P4-3-C6). It listens on a loopback UDP port only (D2-10), prints
// "listening <addr>" on stdout, and serves until it is sent SIGTERM or
// SIGINT, or its stdin closes.
//
//	gtmib -case I1 -engine-id 80007c4f03020000273101 -user gt-mib \
//	      -auth hmac-sha-256 [-listen 127.0.0.1:0] [-log agent.jsonl]
//	gtmib -secret -engine-id ... -auth hmac-sha-256
//
// The USM password comes from GTMIB_PASSWORD, never argv. It is a test
// value (D2-5). -secret prints, in hex, the credential secret the
// collector's snmpv3 credential holds for that engine: the localized
// authentication key followed by the first 16 octets of the localized
// privacy key, computed with the agent's own code (RFC 3414 section 2.6,
// RFC 7860 section 5, RFC 3826 section 1.2).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"otsec.local/otsec/tests/integration/gt_mib/agent"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gtmib:", err)
		os.Exit(1)
	}
}

func run() error {
	id := flag.String("case", "", "the case ID in tests/integration/gt_mib/cases.json, or H<n>/outer or H<n>/scoped")
	listen := flag.String("listen", "127.0.0.1:0", "the loopback UDP address to listen on")
	logPath := flag.String("log", "", "the JSON-lines log of every datagram received")
	engineHex := flag.String("engine-id", "", "the engine ID the asset record pins, in hex")
	user := flag.String("user", "gt-mib", "the USM user name")
	auth := flag.String("auth", string(agent.AuthSHA256), "hmac-sha-256 or hmac-sha-512")
	secret := flag.Bool("secret", false, "print the credential secret in hex and exit")
	list := flag.Bool("list", false, "print every case ID, one a line, and exit")
	flag.Parse()

	if *list {
		for _, c := range agent.Cases() {
			fmt.Println(c)
		}
		return nil
	}

	password := os.Getenv("GTMIB_PASSWORD")
	if password == "" {
		return fmt.Errorf("GTMIB_PASSWORD is not set")
	}
	engine, err := hex.DecodeString(*engineHex)
	if err != nil || len(engine) < 5 || len(engine) > 32 {
		return fmt.Errorf("-engine-id %q: 5 to 32 octets in hex (RFC 3411 SnmpEngineID)", *engineHex)
	}
	a := agent.Auth(*auth)
	if a != agent.AuthSHA256 && a != agent.AuthSHA512 {
		return fmt.Errorf("-auth %q: hmac-sha-256 or hmac-sha-512", *auth)
	}
	if *secret {
		u := agent.NewUser(*user, a, true, password, engine)
		fmt.Println(hex.EncodeToString(append(append([]byte(nil), u.AuthKey...), u.PrivKey[:16]...)))
		return nil
	}
	// agent.Start refuses any address that is not a loopback IP literal.
	cfg, err := agent.NewCase(*id, agent.Spec{EngineID: engine, User: *user, Auth: a, Password: password, LogPath: *logPath})
	if err != nil {
		return err
	}
	ag, err := agent.Start(*listen, cfg)
	if err != nil {
		return err
	}
	fmt.Println("listening", ag.Addr())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); stop <- syscall.SIGTERM }()
	<-stop
	return ag.Close()
}
