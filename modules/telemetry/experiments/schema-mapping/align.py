"""Snapshot alignment for ring-buffer SER reads (A6 C-13, A2 section 7).

A read returns the whole buffer in chronological order. Between reads the
device appends rows at the end and drops the oldest at the front, so the next
read should equal prev[d:] + added for some d >= 0. Rows are compared by the
digest of their native bytes; identical rows stay separate records.
"""


def align(prev, new, min_overlap=1):
    """Return (status, added) where status is one of
    "first-read", "ok", "gap", "ambiguous".

    gap:       no d leaves an overlap of at least min_overlap rows; the buffer
               wrapped past the previous read, was cleared, the device
               restarted, or rows were removed. All of `new` is returned as
               added and the caller must emit a gap event.
    ambiguous: more than one d fits (periodic identical rows). The smallest d
               (largest overlap) is used, and the caller must emit an
               ambiguity event so the choice is visible.
    """
    if prev is None:
        return "first-read", list(new)
    fits = []
    for d in range(len(prev)):
        tail = prev[d:]
        if len(tail) >= min_overlap and new[:len(tail)] == tail:
            fits.append(d)
    if not fits:
        if not prev and new:
            return "gap", list(new)
        return ("ok", []) if not prev and not new else ("gap", list(new))
    d = fits[0]
    added = new[len(prev) - d:]
    return ("ambiguous" if len(fits) > 1 else "ok"), added
