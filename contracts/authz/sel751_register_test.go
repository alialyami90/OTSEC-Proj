package authz

import (
	"crypto/sha256"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
)

// SEL-751 register revision 3 (A2): every documented command word is a
// command mnemonic, so ValidateSecret refuses a password the relay could
// read as a command (C7-A6-3). The word table with pages is in
// contracts/register/content_sel751_test.go; this file checks what authz
// derives from the package.

func readSEL751Content(t *testing.T, name string) ([]byte, *register.Package) {
	t.Helper()
	data, err := os.ReadFile("../register/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := register.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, pkg
}

// sel751Mnemonics is the exact set revision 3 must give, each cut to the
// three characters the relay reads. "89" comes from sel.disconnect, whose
// 89(C|O|A) has no three-letter literal; it was already in revision 2.
var sel751Mnemonics = strings.Fields(`
	2AC 89 89A 89C 89O AAC ABR ACC AFT AJU ANA AYU BAC BAN BNA BRE CAL CAS CBR CER
	CEV CHI CLD CLO CME COM CON COP COU CSE CST CSU DAT DNA EST ETH EVE FEC FGS FIL
	GOO GRO GRU HEL HIS HOR HSG HSR ID INI INT IRI LDP LOG LOO L_D MAC MED MET MOS
	OAC OPE PAC PAR PAS PIN POR PRO PRP PUL QUI RST R_S SAL SER SET SHO SNS STA SUM
	TAR TES THE TIM TRI VEC`)

// TestSEL751MnemonicsExact pins the derived set. A regexp alternation whose
// neighbours share a first letter would add a shorter mnemonic here (Go
// factors (CEV|COU) into C(?:EV|OU)) and refuse far more secrets than the
// relay could read as commands.
func TestSEL751MnemonicsExact(t *testing.T) {
	_, pkg := readSEL751Content(t, "sel-751.json")
	set := map[string]bool{}
	for _, mn := range mnemonics(pkg) {
		if len(mn) > SecretPolicies["sel-751"].MnemonicLen {
			mn = mn[:SecretPolicies["sel-751"].MnemonicLen]
		}
		set[mn] = true
	}
	var got []string
	for mn := range set {
		got = append(got, mn)
	}
	sort.Strings(got)
	want := append([]string(nil), sel751Mnemonics...)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("mnemonics\n got %v\nwant %v", got, want)
	}
}

// TestSEL751SecretsThatReadAsCommands: a secret that starts with any
// documented word, in either case, is refused; secrets that start with no
// word are still accepted.
func TestSEL751SecretsThatReadAsCommands(t *testing.T) {
	_, pkg := readSEL751Content(t, "sel-751.json")
	p := SecretPolicies["sel-751"]
	for _, mn := range sel751Mnemonics {
		for _, s := range []string{mn + "1", strings.ToLower(mn) + "!x"} {
			if err := ValidateSecret([]byte(s), p, pkg); !errors.Is(err, ErrSecretRejected) {
				t.Errorf("%q: %v", s, err)
			}
		}
	}
	// Words revision 2 let through (A2's review of #90), and the Spanish
	// QUIT, HELP and SHO.
	for _, s := range []string{"Help2026", "evelyn!", "Ethan#1", "logon9", "macro7", "vector!", "sal#1", "mostly",
		"ayuda1", "abrir!", "cerrar1", "ajuste", "hora1234", "fecha!", "banana", "interno", "grupo5", "medida", "estado",
		"89A1", "cstatus", "snsx"} {
		if err := ValidateSecret([]byte(s), p, pkg); !errors.Is(err, ErrSecretRejected) {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"Otter#2026", "Wq7!mZ2p", "xyz-9", "CZ9!", "ME!x", "GR#5", "8x!", "Q7x", "Zeta#12"} {
		if err := ValidateSecret([]byte(s), p, pkg); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

// TestSEL751Rev3SupersedesRev2: revision 3 activates over the floor that
// revision 2 left, and once revision 3 is the floor, revision 2 is a
// rollback. Signed with the test release key only.
func TestSEL751Rev3SupersedesRev2(t *testing.T) {
	rev2, _ := readSEL751Content(t, "sel-751-rev2.json")
	rev3, _ := readSEL751Content(t, "sel-751.json")
	rel := newSigner(t, "release-2026-1", 1)
	anchors := []TrustAnchor{{KeyID: rel.id, PublicKey: rel.pub, Status: KeyActive}}

	_, floor2, err := VerifyRegisterPackage(rel.seal(rev2), anchors, map[string]FamilyFloor{})
	if err != nil || floor2.Revision != 2 {
		t.Fatalf("revision 2: %v %+v", err, floor2)
	}
	pkg, floor3, err := VerifyRegisterPackage(rel.seal(rev3), anchors, map[string]FamilyFloor{"sel-751": floor2})
	if err != nil {
		t.Fatalf("revision 3 over the revision 2 floor: %v", err)
	}
	if pkg.Revision != 3 || floor3.Revision != 3 || floor3.PayloadSHA256 != sha256.Sum256(rev3) {
		t.Fatalf("floor %+v", floor3)
	}
	floors := map[string]FamilyFloor{"sel-751": floor3}
	if _, _, err := VerifyRegisterPackage(rel.seal(rev2), anchors, floors); !errors.Is(err, ErrRegisterRejected) {
		t.Fatalf("revision 2 after revision 3: %v", err)
	}
	if _, _, err := VerifyRegisterPackage(rel.seal(rev3), anchors, floors); err != nil {
		t.Fatalf("revision 3 again: %v", err)
	}
	other := []byte(strings.Replace(string(rev3), `"issued": "2026-10-25"`, `"issued": "2026-10-26"`, 1))
	if string(other) == string(rev3) {
		t.Fatal("test edit did not apply")
	}
	if _, _, err := VerifyRegisterPackage(rel.seal(other), anchors, floors); !errors.Is(err, ErrRegisterRejected) {
		t.Fatalf("other bytes as revision 3: %v", err)
	}
}
