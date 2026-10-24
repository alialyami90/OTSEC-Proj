package collectorwire

import (
	"regexp"
	"testing"
)

// Ground truth: Windows publishes the SID of the TrustedInstaller service,
// NT SERVICE\TrustedInstaller, as
// S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464; it appears
// as the owner of protected system files on every current Windows release.
func TestServiceSIDKnownValue(t *testing.T) {
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, name := range []string{"TrustedInstaller", "trustedinstaller", "TRUSTEDINSTALLER"} {
		if got := ServiceSID(name); got != want {
			t.Errorf("ServiceSID(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestServiceSIDsDiffer(t *testing.T) {
	shape := regexp.MustCompile(`^S-1-5-80(-[0-9]+){5}$`)
	n, c := ServiceSID(NodeService), ServiceSID(CollectorService)
	if n == c || !shape.MatchString(n) || !shape.MatchString(c) {
		t.Fatalf("node %s, collector %s", n, c)
	}
	t.Logf("NT SERVICE\\%s = %s", NodeService, n)
	t.Logf("NT SERVICE\\%s = %s", CollectorService, c)
}
