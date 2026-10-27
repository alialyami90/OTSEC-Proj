"""Dry-run check only (not for main): a reader racing a writer that replaces
the file by rename, as the collector replaces state.json. Readers: Python's
plain open, and slicerun.read_live (shares delete). Writers: MoveFileEx
with MOVEFILE_REPLACE_EXISTING (os.replace, and the collector's
renameDurable), and SetFileInformationByHandle(FileRenameInfoEx) with
FILE_RENAME_FLAG_POSIX_SEMANTICS. Report only: the exit code is 1 only if
read_live itself fails a read."""
import ctypes, json, os, struct, sys, tempfile, threading
from ctypes import wintypes
sys.path.insert(0, os.path.join(os.getcwd(), "tests", "integration", "slice"))
from slicerun import read_live

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
INVALID = wintypes.HANDLE(-1).value


def plain(p):
    with open(p, "rb") as f:
        return f.read()


def movefileex(tmp, p):
    os.replace(tmp, p)


def posix_rename(tmp, p):
    DELETE, SYNCHRONIZE, SHARE_ALL, OPEN_EXISTING = 0x00010000, 0x00100000, 7, 3
    h = k32.CreateFileW(tmp, DELETE | SYNCHRONIZE, SHARE_ALL, None, OPEN_EXISTING, 0, None)
    if h in (None, INVALID):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        name = p.encode("utf-16-le")
        # FILE_RENAME_INFO on x64: Flags (DWORD, padded to 8), RootDirectory,
        # FileNameLength (DWORD), FileName.
        buf = struct.pack("<IIQI", 0x1 | 0x2, 0, 0, len(name)) + name + b"\0\0"
        b = ctypes.create_string_buffer(buf, len(buf))
        if not k32.SetFileInformationByHandle(h, 22, b, len(buf)):  # FileRenameInfoEx
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(h)


def trial(read, write):
    p = os.path.join(tempfile.mkdtemp(), "state.json")
    with open(p, "w") as f:
        json.dump({"n": 0}, f)
    stop, errs, reads, first = threading.Event(), {"read": 0, "replace": 0}, [0], []

    def reader():
        while not stop.is_set():
            try:
                json.loads(read(p))
                reads[0] += 1
            except Exception as e:
                errs["read"] += 1
                first.append("read " + repr(e))
    t = threading.Thread(target=reader)
    t.start()
    for i in range(3000):
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"n": i}, f)
        try:
            write(tmp, p)
        except Exception as e:
            errs["replace"] += 1
            first.append("replace " + repr(e))
            os.remove(tmp)
    stop.set()
    t.join()
    return reads[0], errs, first[:2]


bad = False
for rn, r in (("plain open", plain), ("read_live", read_live)):
    for wn, w in (("MoveFileEx", movefileex), ("POSIX rename", posix_rename)):
        n, e, first = trial(r, w)
        print(f"reader {rn}, writer {wn}: {n} reads, {e['read']} read errors, {e['replace']} of 3000 replaces failed {first}")
        if r is read_live and (e["read"] or n == 0):
            bad = True
sys.exit(1 if bad else 0)
