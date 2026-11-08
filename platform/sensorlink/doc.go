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
// Not here yet: the transport (it waits for ADR-0009), the platform_session
// tie, the heartbeat's health events and the status section. They follow
// in the next B5 step.
package sensorlink
