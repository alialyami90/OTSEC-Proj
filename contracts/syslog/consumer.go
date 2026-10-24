package syslog

import (
	"time"

	"otsec.local/otsec/contracts/store"
)

// Consumers returns the C5 consumers of target t (C6-A5-2): one for each
// event stream it forwards, plus audit when t.Audit is set. ConsumerID is
// the target name, Delivery its class and ReplayWindow its replay_seconds,
// so renaming a target makes new consumers with new cursors. The target is
// validated first; every result passes store.Consumer.Validate.
func Consumers(t *Target, events []store.StreamID, audit store.StreamID) ([]store.Consumer, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	delivery := store.BestEffort
	if t.Class == ClassRequired {
		delivery = store.Required
	}
	window := time.Duration(t.ReplaySeconds) * time.Second
	streams := append([]store.StreamID{}, events...)
	if t.Audit {
		if audit == "" {
			return nil, &Error{Code: CodeAudit, Field: "audit", Detail: "the node has no audit stream"}
		}
		streams = append(streams, audit)
	}
	out := make([]store.Consumer, 0, len(streams))
	for _, s := range streams {
		c := store.Consumer{ID: store.ConsumerID(t.Name), Stream: s, Delivery: delivery, ReplayWindow: window}
		if err := c.Validate(); err != nil {
			return nil, &Error{Code: CodeDelivery, Field: "consumer", Detail: err.Error()}
		}
		out = append(out, c)
	}
	return out, nil
}
