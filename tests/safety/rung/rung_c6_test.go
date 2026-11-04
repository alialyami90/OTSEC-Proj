// Package rung holds C6's V-M3 cases for the SEL-751 (R3.7; D4-40 point 3).
//
// Rung 3 (SHO over Telnet) is the SEL-751's only built rung, so V-M3's
// "a configuration naming a lower rung is refused at start" is vacuous for
// it (D4-40). What is not vacuous is that a node configuration cannot choose
// another configuration method. These cases pin each way one could try:
//   - a field naming a method: the node's strict decode refuses it at start;
//   - an endpoint on an FTP transport: C1's closed transport set refuses it
//     at start;
//   - an operation that names an FTP read: the node checks only the
//     operation's form at start, so the guard is the signed register, which
//     holds no FTP operation and no FTP command line, and the collector
//     refuses an operation the register does not hold (authz
//     RefuseUnknownOperation) before any byte reaches the device.
//
// Ground truth: V-M3's text in docs/verification.md, D4-40, and the FTP
// command list V-M3 names. Evidence class: desk (the configuration and the
// register are read; no binary runs and no device is contacted).
package rung

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// config is a valid node configuration with one simulated SEL-751 on
// rung 3, as the slice runs it, decoded to generic JSON so a case can add
// to it.
func config(t *testing.T) map[string]any {
	t.Helper()
	nc := nodeconfigtest.New("node-c6", filepath.Join(t.TempDir(), "store"))
	nc.AddSEL751("2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "127.0.0.1", 2323, 60)
	var m map[string]any
	if err := json.Unmarshal(nc.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := node.ParseConfig(nc.Bytes()); err != nil {
		t.Fatalf("the base configuration does not parse: %v", err)
	}
	return m
}

func parse(t *testing.T, m map[string]any) error {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = node.ParseConfig(b)
	return err
}

func first(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	l, ok := m[key].([]any)
	if !ok || len(l) == 0 {
		t.Fatalf("the base configuration has no %s", key)
	}
	return l[0].(map[string]any)
}

// A field that would choose the method is refused at start, wherever it is
// put: the configuration has no such field.
func TestC6MethodFieldIsRefusedAtStart(t *testing.T) {
	for _, place := range []string{"top level", "schedule entry", "endpoint"} {
		for _, field := range []string{"method", "config_method", "rung"} {
			t.Run(place+"/"+field, func(t *testing.T) {
				m := config(t)
				switch place {
				case "top level":
					m[field] = "ftp"
				case "schedule entry":
					first(t, m, "schedule")[field] = "ftp"
				case "endpoint":
					first(t, first(t, m, "assets"), "endpoints")[field] = "ftp"
				}
				if err := parse(t, m); err == nil || !strings.Contains(err.Error(), `"`+field+`"`) {
					t.Fatalf("a configuration with %s %q = ftp: %v, want a refusal naming the field", place, field, err)
				}
			})
		}
	}
}

// An endpoint on an FTP transport is refused at start: C1's transport set is
// closed and has no FTP.
func TestC6FTPEndpointIsRefusedAtStart(t *testing.T) {
	m := config(t)
	ep := first(t, first(t, m, "assets"), "endpoints")
	ep["transport"], ep["port"] = "ftp", 21
	if err := parse(t, m); err == nil || !strings.Contains(err.Error(), `transport "ftp"`) {
		t.Fatalf("an endpoint on transport ftp: %v, want a refusal of the transport", err)
	}
}

// The operation is the one field that names how a read is made, and the node
// checks only its form at start. The guard is the signed register: it holds
// no FTP operation and no line that is an FTP command, so the collector
// refuses any FTP operation the configuration names before it connects.
// That refusal is pinned elsewhere, and this test does not repeat it:
// TestRunNamesARegisterRun in contracts/authz (an operation the register
// does not name is unknown_operation) and the "unknown operation" case of
// TestRunRefusals in modules/security/collector (Pipeline.Handle refuses it
// unknown_operation).
func TestC6FTPOperationHasNoRegisterEntry(t *testing.T) {
	m := config(t)
	first(t, m, "schedule")["operation"] = "sel.config.ftp_read"
	if err := parse(t, m); err != nil {
		t.Logf("the node now refuses an FTP operation at start (%v): V-M3's start case is then shown by the node too", err)
	} else {
		t.Log("the node accepts the operation's form at start; the register and the collector are the guard")
	}

	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	// V-M3's FTP commands, read and write: none is a register line.
	ftp := []string{"USER", "PASS", "TYPE", "PASV", "EPSV", "CWD", "LIST", "NLST", "SIZE", "RETR", "QUIT",
		"STOR", "STOU", "APPE", "DELE", "RNFR", "RNTO", "MKD", "RMD", "SITE"}
	for _, op := range p.Operations {
		if strings.Contains(strings.ToLower(op.ID), "ftp") {
			t.Errorf("register operation %s names FTP", op.ID)
		}
		verb := strings.ToUpper(strings.Fields(op.Line + " ")[0])
		for _, c := range ftp {
			// QUI is the relay's quit, a register session line; QUIT is FTP's.
			if verb == c {
				t.Errorf("register operation %s's line %q is the FTP command %s", op.ID, op.Line, c)
			}
		}
	}
	for _, r := range p.Runs {
		if strings.Contains(strings.ToLower(r.ID), "ftp") {
			t.Errorf("register run %s names FTP", r.ID)
		}
	}
	if p.Run("sel.config.read_all") == nil {
		t.Fatal("the register has no sel.config.read_all: the rung 3 read is not the register's")
	}
}
