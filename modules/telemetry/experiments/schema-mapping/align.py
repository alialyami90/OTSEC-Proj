"""Snapshot alignment for ring-buffer SER reads (A6 C-13, A2 section 7).

A read returns the whole buffer in chronological order. Between reads the
device appends rows at the end and drops the oldest at the front, so the next
read should equal prev[d:] + added for some d >= 0. Rows are compared by the
alignment key: the row's native bytes without its row number, because
the SEL-751 numbers row 1 as the newest and renumbers every row on each new
event (A6 R-A4-1). Identical rows stay separate records.
"""


def align_full(prev, new, min_overlap=1):
    """Return (status, added, possible_duplicates) where status is one of
    "first-read", "ok", "gap", "ambiguous".

    gap:       no d leaves an overlap of at least min_overlap rows; the buffer
               wrapped past the previous read, was cleared, the device
               restarted, or rows were removed. All of `new` is returned as
               added and the caller must emit a gap event.
    ambiguous: more than one d fits (periodic identical rows). The largest d
               (smallest overlap) is used, so every row that may be new is
               kept; the first `possible_duplicates` rows of `added` may
               already have been seen, and the caller flags them and emits an
               ambiguity event (A6 R-A4-2: a visible duplicate is better than
               a lost event).
    """
    if prev is None:
        return "first-read", list(new), 0
    fits = []
    for d in range(len(prev)):
        tail = prev[d:]
        if len(tail) >= min_overlap and new[:len(tail)] == tail:
            fits.append(d)
    if not fits:
        return ("ok", [], 0) if not prev and not new else ("gap", list(new), 0)
    d = fits[-1]
    added = new[len(prev) - d:]
    if len(fits) == 1:
        return "ok", added, 0
    return "ambiguous", added, fits[-1] - fits[0]


def align(prev, new, min_overlap=1):
    """(status, added) only; kept for A6's harness."""
    status, added, _ = align_full(prev, new, min_overlap)
    return status, added
