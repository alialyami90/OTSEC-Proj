package store

import "fmt"

// Code is the closed list of C5 error codes. A reader that meets a code it
// does not know treats it as CodeInvalid, which is a failure.
type Code string

const (
	// CodeInvalid: a value broke the contract (validation, a malformed call).
	CodeInvalid Code = "invalid"
	// CodeCommitFailed: the Committer returned an error. Whether the batch
	// is durable is unknown, so no receipt is released and the Log stops.
	CodeCommitFailed Code = "commit-failed"
	// CodeCommitNotDurable: the Committer reported a commit below
	// synchronous=FULL. No receipt is released and the Log stops.
	CodeCommitNotDurable Code = "commit-not-durable"
	// CodeCommitMismatch: the Commit does not describe the batch that was
	// handed over (stream, count, or a seq that leaves a gap or overlaps).
	CodeCommitMismatch Code = "commit-mismatch"
	// CodeLogStopped: the Log stopped after an earlier commit failure. Only
	// a restart, which runs startup recovery, clears it.
	CodeLogStopped Code = "log-stopped"
	// CodeCursorRegress: a cursor would move backwards.
	CodeCursorRegress Code = "cursor-regress"
	// CodeCursorAhead: a cursor names a seq the stream has not committed.
	CodeCursorAhead Code = "cursor-ahead"
	// CodeNoConsumers: a stream has no consumer, so nothing confirms its
	// events and none may be pruned (the site is the system of record).
	CodeNoConsumers Code = "no-consumers"
	// CodeQuotaReached: the record's class is at its quota and its storage-
	// full action refuses it (refuse-new, fail-closed). Nothing was written,
	// so the Log keeps running.
	CodeQuotaReached Code = "quota-reached"
	// CodeAuditUnavailable: a privileged operation or credential-bearing
	// collection was refused because its audit record holds no Receipt.
	CodeAuditUnavailable Code = "audit-unavailable"
	// CodeStartupFailed: a startup step failed and startup stopped.
	CodeStartupFailed Code = "startup-failed"
	// CodeOpenBusy (0.2): StartupEnv.Open failed only because another
	// connection held the database busy or locked past the store's busy
	// timeout. It is the one open failure Resume retries (Report.OpenBusy);
	// an implementation sets it from the database's own error code, never
	// from error text, and never for any other cause.
	CodeOpenBusy Code = "open-busy"
)

// Error is the error type of this contract. Detail is free text that never
// replaces Code.
type Error struct {
	Code   Code
	Detail string
	Err    error
}

func (e *Error) Error() string {
	s := "store: " + string(e.Code)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches any *Error with the same Code, so callers can write
// errors.Is(err, &store.Error{Code: store.CodeCursorRegress}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func errf(code Code, err error, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...), Err: err}
}
