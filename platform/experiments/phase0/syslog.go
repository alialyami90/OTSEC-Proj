package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The syslog-loss experiment asks: when the platform forwards events over
// plain TCP syslog (RFC 6587 octet counting, as RFC 5425 uses inside TLS),
// and the collector dies, how many events did the forwarder believe it sent
// that the collector never recorded? It then repeats the run with an
// application-level acknowledgement (RELP-like) to show what that changes.
//
// The receiver is a separate process that records each message's sequence
// number to a file before doing anything else, so "received" means "the
// collector's process got it", the most generous possible definition.

func syslogMsg(seq int) string {
	// RFC 5424 with the platform sequence carried in structured data.
	// 32473 is the documentation enterprise number from RFC 5612.
	return fmt.Sprintf(`<134>1 2026-10-23T15:00:00.123456Z site1 otsec - SER [otsec@32473 seq="%d"] 51P1T Asserted`, seq)
}

func frame(msg string) []byte { return []byte(strconv.Itoa(len(msg)) + " " + msg) }

// readFrame reads one octet-counted frame.
func readFrame(r *bufio.Reader) (string, error) {
	lenStr, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenStr))
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(r, buf)
	return string(buf), err
}

func seqOf(msg string) int {
	i := strings.Index(msg, `seq="`)
	if i < 0 {
		return -1
	}
	rest := msg[i+5:]
	n, _ := strconv.Atoi(rest[:strings.IndexByte(rest, '"')])
	return n
}

// runPlainReceiver accepts one connection and records every sequence it
// reads. -delay simulates a collector that is slower than the sender.
func runPlainReceiver(args []string) error {
	fs := flag.NewFlagSet("plain-receiver", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "listen address")
	out := fs.String("out", "", "file to append received sequences to")
	delay := fs.Duration("delay", 0, "processing delay per message")
	fs.Parse(args)
	return receive(*addr, *out, *delay, false, 0)
}

// runAckedReceiver is the same, but writes "ACK <seq>\n" back after recording
// each message. It serves connections until killed.
func runAckedReceiver(args []string) error {
	fs := flag.NewFlagSet("acked-receiver", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "listen address")
	out := fs.String("out", "", "file to append received sequences to")
	delay := fs.Duration("delay", 0, "processing delay per message")
	crashAfter := fs.Int("crash-after", 0, "exit after recording this many messages, before acking the last")
	fs.Parse(args)
	return receive(*addr, *out, *delay, true, *crashAfter)
}

func receive(addr, out string, delay time.Duration, ack bool, crashAfter int) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Println(ln.Addr().String()) // tells the harness where to connect
	recorded := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		r := bufio.NewReader(c)
		for {
			msg, err := readFrame(r)
			if err != nil {
				c.Close()
				break
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			seq := seqOf(msg)
			fmt.Fprintf(f, "%d\n", seq) // unbuffered write: survives SIGKILL
			recorded++
			if crashAfter > 0 && recorded == crashAfter {
				os.Exit(3) // recorded but never acked: the sender must resend it
			}
			if ack {
				fmt.Fprintf(c, "ACK %d\n", seq)
			}
		}
	}
}

type receiverProc struct {
	cmd  *exec.Cmd
	addr string
}

func startReceiver(self, role, addr, out string, delay time.Duration, extra ...string) (*receiverProc, error) {
	cmd := exec.Command(self, append([]string{role, "-addr", addr, "-out", out, "-delay", delay.String()}, extra...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		cmd.Process.Kill()
		return nil, err
	}
	return &receiverProc{cmd: cmd, addr: strings.TrimSpace(line)}, nil
}

func (p *receiverProc) kill() {
	p.cmd.Process.Signal(syscall.SIGKILL)
	p.cmd.Wait()
}

// receivedSeqs returns total lines and distinct sequences in a receiver file.
func receivedSeqs(path string) (total int, distinct map[int]bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	distinct = map[int]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n, err := strconv.Atoi(sc.Text())
		if err != nil {
			continue
		}
		total++
		distinct[n] = true
	}
	return total, distinct, sc.Err()
}

func runSyslogLoss(args []string) error {
	fs := flag.NewFlagSet("syslog-loss", flag.ExitOnError)
	runs := fs.Int("runs", 10, "runs per plain-TCP scenario")
	dir := fs.String("dir", os.TempDir(), "scratch directory")
	fs.Parse(args)
	self, err := os.Executable()
	if err != nil {
		return err
	}

	fmt.Println("syslog-loss, part 1: plain TCP (RFC 6587 octet counting), collector SIGKILLed mid-stream")
	fmt.Println("A message counts as 'sent' when conn.Write returned nil, which is all a")
	fmt.Println("plain TCP syslog sender can know.")
	fmt.Println("scenario                       runs  sent-ok(min/max)  received(min/max)  lost(min/max)  runs-with-loss")
	for _, sc := range []struct {
		name     string
		pace     time.Duration // sender delay between messages
		delay    time.Duration // collector processing time per message
		killWait time.Duration
	}{
		{"paced 1/ms, fast collector", time.Millisecond, 0, 300 * time.Millisecond},
		{"burst, fast collector", 0, 0, 100 * time.Millisecond},
		{"burst, slow collector 1ms/msg", 0, time.Millisecond, 300 * time.Millisecond},
	} {
		var sMin, sMax, rMin, rMax, lMin, lMax, withLoss int = 1 << 30, 0, 1 << 30, 0, 1 << 30, 0, 0
		for i := 0; i < *runs; i++ {
			out := fmt.Sprintf("%s/plain-%d.txt", *dir, i)
			os.Remove(out)
			sent, err := plainRun(self, out, sc.pace, sc.delay, sc.killWait)
			if err != nil {
				return err
			}
			got, _, err := receivedSeqs(out)
			if err != nil {
				return err
			}
			os.Remove(out)
			lost := sent - got
			sMin, sMax = min(sMin, sent), max(sMax, sent)
			rMin, rMax = min(rMin, got), max(rMax, got)
			lMin, lMax = min(lMin, lost), max(lMax, lost)
			if lost > 0 {
				withLoss++
			}
		}
		fmt.Printf("%-30s %4d  %7d/%-8d  %8d/%-8d  %6d/%-6d  %d/%d\n",
			sc.name, *runs, sMin, sMax, rMin, rMax, lMin, lMax, withLoss, *runs)
	}

	fmt.Println("\nsyslog-loss, part 2: acked transport (collector acks after recording), collector")
	fmt.Println("SIGKILLed and restarted 3 times while 20000 events are forwarded; sender resends")
	fmt.Println("everything not yet acked after each reconnect. The first collector instance also")
	fmt.Println("crashes right after recording event 2500, before acking it.")
	return ackedRun(self, *dir, 20000, 3)
}

// plainRun sends until a write fails (after the collector is killed) and
// returns how many writes succeeded.
func plainRun(self, out string, pace, delay, killWait time.Duration) (int, error) {
	rp, err := startReceiver(self, "plain-receiver", "127.0.0.1:0", out, delay)
	if err != nil {
		return 0, err
	}
	conn, err := net.Dial("tcp", rp.addr)
	if err != nil {
		rp.kill()
		return 0, err
	}
	defer conn.Close()
	go func() { time.Sleep(killWait); rp.kill() }()

	sent := 0
	deadline := time.Now().Add(killWait + 2*time.Second)
	for seq := 1; time.Now().Before(deadline); seq++ {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(frame(syslogMsg(seq))); err != nil {
			break
		}
		sent++
		if pace > 0 {
			time.Sleep(pace)
		}
	}
	time.Sleep(50 * time.Millisecond) // let the killed receiver's last file writes land
	return sent, nil
}

// ackedRun forwards total events with a sliding window, treating an event as
// delivered only when its ACK arrives, and kills the collector `kills` times.
func ackedRun(self, dir string, total, kills int) error {
	out := dir + "/acked.txt"
	os.Remove(out)
	defer os.Remove(out)
	rp, err := startReceiver(self, "acked-receiver", "127.0.0.1:0", out, 0, "-crash-after", "2500")
	if err != nil {
		return err
	}
	addr := rp.addr
	const window = 200

	acked := 0 // every seq <= acked is confirmed by the collector
	reconnects := 0
	killsDone := 0
	start := time.Now()
	for acked < total {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			// Collector down: restart it on the same address.
			if rp, err = startReceiver(self, "acked-receiver", addr, out, 0); err != nil {
				time.Sleep(20 * time.Millisecond)
			}
			continue
		}
		reconnects++
		r := bufio.NewReader(conn)
		next := acked + 1 // resend everything not acked
		for acked < total {
			for next <= total && next-acked <= window {
				if _, err := conn.Write(frame(syslogMsg(next))); err != nil {
					break
				}
				next++
			}
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "ACK "))); err == nil && n > acked {
				acked = n // receiver acks in order on one connection
			}
			// Kill the collector at evenly spaced points.
			if killsDone < kills && acked >= (killsDone+1)*total/(kills+1) {
				rp.kill()
				killsDone++
			}
		}
		conn.Close()
	}
	rp.kill()
	got, distinct, err := receivedSeqs(out)
	if err != nil {
		return err
	}
	missing := 0
	for s := 1; s <= total; s++ {
		if !distinct[s] {
			missing++
		}
	}
	fmt.Printf("  events=%d collector-kills=%d connections=%d elapsed=%s\n", total, killsDone, reconnects, time.Since(start).Round(time.Millisecond))
	fmt.Printf("  recorded=%d distinct=%d missing=%d duplicates=%d\n", got, len(distinct), missing, got-len(distinct))
	if missing > 0 {
		return fmt.Errorf("acked transport lost %d events", missing)
	}
	fmt.Println("  result: no loss; duplicates are expected and must be removed downstream by event id")
	return nil
}
