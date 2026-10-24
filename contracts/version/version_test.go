package version

import "testing"

func TestParseValid(t *testing.T) {
	cases := map[string]ID{
		"otsec.event/0.1":         {"event", 0, 1},
		"otsec.syslog/1.0":        {"syslog", 1, 0},
		"otsec.adapter-call/2.13": {"adapter-call", 2, 13},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %+v, want %+v", in, got, want)
		}
		if got.String() != in {
			t.Fatalf("String() = %q, want %q", got.String(), in)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		"", "otsec.event", "otsec.event/1", "otsec.event/01.0", "otsec.event/1.01",
		"OTSEC.event/0.1", "otsec.Event/0.1", "otsec.event/0.1 ", " otsec.event/0.1",
		"otsec./0.1", "otsec.1event/0.1", "other.event/0.1", "otsec.event/0.1\n",
		"otsec.event/10000.0",
	} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("Parse(%q) accepted", in)
		}
	}
}

func TestAccepts(t *testing.T) {
	reader, _ := Parse("otsec.event/0.2")
	for in, want := range map[string]bool{
		"otsec.event/0.1": true,
		"otsec.event/0.9": true,
		"otsec.event/1.0": false,
		"otsec.audit/0.2": false,
	} {
		got, _ := Parse(in)
		if reader.Accepts(got) != want {
			t.Fatalf("Accepts(%s) = %v, want %v", in, !want, want)
		}
	}
}
