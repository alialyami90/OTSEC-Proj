package main

import (
	"fmt"
	"os"
	"strings"
)

// checkTraceback refuses GOTRACEBACK settings that make the Go runtime
// crash the process deliberately on a fatal error (crash), or hand it to
// Windows Error Reporting (wer): both can write a dump of memory that holds
// a secret (T-5). The runtime ignores a lower debug.SetTraceback level than
// the environment's, so the setting is refused rather than overridden.
func checkTraceback() error {
	v := strings.ToLower(os.Getenv("GOTRACEBACK"))
	if strings.Contains(v, "crash") || strings.Contains(v, "wer") {
		return fmt.Errorf("GOTRACEBACK=%s would write a crash dump", v)
	}
	return nil
}
