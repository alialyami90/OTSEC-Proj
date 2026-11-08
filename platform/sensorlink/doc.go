// Package sensorlink is the node's side of the channel from the passive
// network sensor (P4-4-B5 deliverable 2, docs/phase4/D5-sensor-node.md
// section 2). It reads C13 records from a byte stream, checks them, adds
// the node object (C13 section 5) and commits each observation to the
// sensor's network-observation stream. It is its own package so that its
// tests stay out of platform/node's Windows test step (section 8).
//
// Every record is hostile input: the sensor parses attacker-controlled
// packets. A record that fails a check is dropped and counted by reason,
// and the channel stays up. Only a frame longer than C13's MaxChannelFrame
// closes it, because the stream can't be resynchronized after one.
//
// The intake hold (hold.go) ties the records of the node's own collection
// sessions to them by platform_session (D4-72, baseline note section 5). It
// holds a run's flows to its endpoint until the run's result, then commits
// them tied or untied, and keeps each tied flow's key open until its end.
// Its state is written through HoldConfig.Save before each effect; the node
// stores it as netcheckpoint.intake (C5 0.9 section 8).
//
// Not here yet: the transport (it waits for ADR-0009), the node's wiring of
// the hold (its scheduler hooks, store and start repair), the heartbeat's
// health events and the status section. They follow in the next B5 steps.
package sensorlink
