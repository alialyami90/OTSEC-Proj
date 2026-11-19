package sensorlink

import (
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// C13 0.3 §15.2 and §15.3 (P4-4-C13-ABS): the node object's class and SA
// flags for sa unknown and objects_unread. sa unknown on a write, control
// or session-setup sets dnp3_sa_unknown and never dnp3_no_sa; on a read it
// sets neither. A function 2 of g50v1 whose headers were not shown read to
// the end is write, so it is judged as one. Control: the mutant that reads
// unknown as none sets dnp3_no_sa, which "operate, unknown" refuses
// (run by hand and recorded in the PR); objects_unread false gives
// time-sync.
func TestNodeObjectSA15(t *testing.T) {
	l := newLink(t, openNet(t, 64<<20), &clock{}, 64<<20)
	fn := func(code int, sa string, unread *bool, objects ...string) *netobs.Observation {
		o := firstSight(1, "192.0.2.10", "192.0.2.20", sa)
		o.Function.Code, o.Function.Objects, o.Function.ObjectsUnread = code, objects, unread
		return o
	}
	for name, tc := range map[string]struct {
		o             *netobs.Observation
		class         string
		noSA, unknown bool
	}{
		"operate, unknown":         {fn(5, netobs.SAUnknown, ptr(false), "g12v1"), netobs.ClassControl, false, true},
		"read, unknown":            {fn(1, netobs.SAUnknown, ptr(false), "g60v1"), netobs.ClassRead, false, false},
		"operate, none":            {fn(5, netobs.SANone, ptr(false), "g12v1"), netobs.ClassControl, true, false},
		"time sync, unread":        {fn(2, netobs.SAUnknown, ptr(true), "g50v1"), netobs.ClassWrite, false, true},
		"time sync, absent":        {fn(2, netobs.SAUnknown, nil, "g50v1"), netobs.ClassWrite, false, true},
		"control, time sync, read": {fn(2, netobs.SANone, ptr(false), "g50v1"), netobs.ClassTimeSync, false, false},
	} {
		nd, _ := l.nodeObject(tc.o)
		if nd.FunctionClass != tc.class || (nd.DNP3NoSA != nil) != tc.noSA || (nd.DNP3SAUnknown != nil) != tc.unknown {
			t.Errorf("%s: class %s, dnp3_no_sa %v, dnp3_sa_unknown %v; want %s, %v, %v", name, nd.FunctionClass,
				nd.DNP3NoSA != nil, nd.DNP3SAUnknown != nil, tc.class, tc.noSA, tc.unknown)
		}
	}
}
