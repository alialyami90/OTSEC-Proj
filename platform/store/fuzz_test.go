package store

import (
	"bytes"
	"sync"
	"testing"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
)

// assignSeq reads producer JSON. Whatever it accepts decodes as a full C4
// event with the assigned ID, and only the id member changed.
func FuzzAssignSeq(f *testing.F) {
	f.Add(pending("relay1/ser", 1))
	f.Add([]byte(`{"id":1}`))
	f.Add([]byte(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":"relay1/ser","seq":0},"id":{}}`))
	id := event.EventID{NodeID: testNode, Stream: "relay1/ser", Seq: 42}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := assignSeq(b, id)
		if err != nil {
			return
		}
		e, err := event.Decode(out)
		if err != nil || e.ID != id {
			t.Fatalf("accepted %q gives %q: %v", b, out, err)
		}
		x, err1 := replaceMember(b, "id", []byte("null"))
		y, err2 := replaceMember(out, "id", []byte("null"))
		if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
			t.Fatalf("bytes outside id changed: %q -> %q", b, out)
		}
	})
}

// Appends to several streams from many goroutines, with reads and cursor
// saves alongside, keep each stream's seqs contiguous (run with -race).
func TestConcurrentUse(t *testing.T) {
	db := open1(t, storeDir(t), evidenceDB, nil)
	l := testLog(t, db)
	streams := []c5.StreamSpec{evidenceDB.Streams[0], evidenceDB.Streams[1]}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s := streams[g%2]
			for i := 0; i < 25; i++ {
				if _, err := l.Append(bg, rec(s.ID, s.Class, g*100+i)); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			got, err := db.Read(bg, "relay1/ser", 0, 1000)
			if err != nil {
				t.Error(err)
				return
			}
			for j := range got {
				if got[j].Key.Seq != c5.Seq(j+1) {
					t.Errorf("read sees seq %d at %d", got[j].Key.Seq, j)
					return
				}
			}
			if len(got) > 0 {
				if err := db.SaveCursor(bg, c5.Cursor{Consumer: "c", Stream: "relay1/ser", Through: got[len(got)-1].Key.Seq}); err != nil {
					t.Error(err)
				}
			}
		}
	}()
	wg.Wait()
	<-done
	for _, s := range streams {
		if n, _ := db.LastCommitted(bg, s.ID); n != 100 {
			t.Errorf("%s at %d, want 100", s.ID, n)
		}
	}
}
