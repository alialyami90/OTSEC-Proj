package store

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
)

// The kill test: a child process commits, saves cursors and prunes, and
// prints every receipt it is given. It exits at the n-th time it reaches
// one named point of a transaction, without closing anything. The parent
// then runs startup on the same files and checks that every acknowledged
// event is there, byte for byte, unless a persisted cursor allowed it to be
// pruned. Evidence class: simulated. A killed process leaves the OS page
// cache intact, so this tests SQLite's transaction boundaries, not power
// loss (H-11).

const crashExit = 9

// crashPoints are the points of every transaction of a running store, each
// reached many times. startPoints are those of the first open, each reached
// once: creating the database and registering its streams.
var (
	crashPoints = []string{
		"commit:begin", "commit:commit", "commit:done",
		"cursor:begin", "cursor:commit", "cursor:done",
		"prune:begin", "prune:commit", "prune:done",
	}
	startPoints = []string{
		"create:begin", "create:commit", "create:done", "create:rename",
		"streams:begin", "streams:commit", "streams:done",
	}
)

func TestKillAtEveryCommitPoint(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	runs := map[string][]int{}
	for _, p := range crashPoints {
		runs[p] = []int{1, 4}
	}
	for _, p := range startPoints {
		runs[p] = []int{1}
	}
	for _, point := range append(crashPoints, startPoints...) {
		for _, nth := range runs[point] {
			t.Run(fmt.Sprintf("%s#%d", point, nth), func(t *testing.T) {
				dir := storeDir(t)
				cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.v")
				cmd.Env = append(os.Environ(), "OTSEC_CRASH_DIR="+dir, "OTSEC_CRASH_POINT="+point, fmt.Sprintf("OTSEC_CRASH_NTH=%d", nth))
				out, err := cmd.Output()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != crashExit {
					t.Fatalf("child did not stop at %s: %v\n%s", point, err, out)
				}
				checkAfterCrash(t, dir, out)
			})
		}
	}
}

type ack struct {
	seq c5.Seq
	n   int
}

func checkAfterCrash(t *testing.T, dir string, out []byte) {
	t.Helper()
	var acks []ack
	var cursor c5.Seq
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 3 && f[0] == "ACK":
			seq, _ := strconv.ParseUint(f[1], 10, 64)
			n, _ := strconv.Atoi(f[2])
			acks = append(acks, ack{c5.Seq(seq), n})
		case len(f) == 2 && f[0] == "CURSOR":
			seq, _ := strconv.ParseUint(f[1], 10, 64)
			cursor = c5.Seq(seq)
		}
	}
	db, _ := testStore(t, Options{Dir: dir, Node: testNode, Database: evidenceDB}, policy(evidenceDB), c5.ModeCollecting)
	got, err := db.Read(bg, "relay1/ser", 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	last, _ := db.LastCommitted(bg, "relay1/ser")
	persisted, _ := db.LoadCursors(bg, "relay1/ser")
	var through c5.Seq
	for _, c := range persisted {
		through = c.Through
	}
	if through < cursor {
		t.Fatalf("cursor %d was saved, %d is persisted", cursor, through)
	}
	stored := map[c5.Seq][]byte{}
	for i, s := range got {
		if i > 0 && s.Key.Seq != got[i-1].Key.Seq+1 {
			t.Fatalf("gap after seq %d", got[i-1].Key.Seq)
		}
		stored[s.Key.Seq] = s.Event
	}
	if len(got) > 0 && got[len(got)-1].Key.Seq != last {
		t.Fatalf("last committed %d, last stored %d", last, got[len(got)-1].Key.Seq)
	}
	for _, a := range acks {
		b, ok := stored[a.seq]
		if !ok {
			if a.seq <= through {
				continue // confirmed by the persisted cursor, then pruned
			}
			t.Fatalf("acknowledged seq %d lost (last %d, cursor %d)", a.seq, last, through)
		}
		e, err := event.Decode(b)
		if err != nil || e.Health.Details["n"] != strconv.Itoa(a.n) {
			t.Fatalf("seq %d holds the wrong event: %v %s", a.seq, err, b)
		}
	}
	if len(acks) > 0 && last < acks[len(acks)-1].seq {
		t.Fatalf("last committed %d below the last receipt %d", last, acks[len(acks)-1].seq)
	}
}

// TestCrashChild is the child of TestKillAtEveryCommitPoint. It does
// nothing in a normal run.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv("OTSEC_CRASH_DIR")
	if dir == "" {
		t.Skip("child of TestKillAtEveryCommitPoint")
	}
	point := os.Getenv("OTSEC_CRASH_POINT")
	nth, _ := strconv.Atoi(os.Getenv("OTSEC_CRASH_NTH"))
	seen := 0
	opt := Options{Dir: dir, Node: testNode, Database: evidenceDB, hook: func(p string) {
		if p == point {
			if seen++; seen == nth {
				os.Exit(crashExit)
			}
		}
	}}
	db, _ := testStore(t, opt, policy(evidenceDB), c5.ModeCollecting)
	l := testLog(t, db)
	central := c5.Consumer{ID: "central", Stream: "relay1/ser", Delivery: c5.Required}
	n := 0
	for round := 0; round < 20; round++ {
		rs, err := l.AppendBatch(bg, recs("relay1/ser", c5.ClassAdapterEvidence, n, 3))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			fmt.Printf("ACK %d %d\n", r.Key().Seq, n)
			n++
		}
		r, err := l.Append(bg, rec("relay1/ser", c5.ClassAdapterEvidence, n))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("ACK %d %d\n", r.Key().Seq, n)
		n++
		// Confirm all but the newest two, then prune one small step.
		through := r.Key().Seq - 2
		if err := db.SaveCursor(bg, c5.Cursor{Consumer: "central", Stream: "relay1/ser", Through: through}); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("CURSOR %d\n", through)
		b, err := c5.ComputeBoundary(bg, db, db, []c5.Consumer{central}, "relay1/ser", c5.ClassAdapterEvidence, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.PruneStep(bg, b, 2); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("never reached %s #%d (%d times)", point, nth, seen)
}
