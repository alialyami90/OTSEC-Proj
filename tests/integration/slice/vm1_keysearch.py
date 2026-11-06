"""M3's key search over a CI job's own output (D3 on #496).

test_slice_vm1_e2e.py writes the run's test keys (each password, Ku,
localized key and AES key, in hex) to the file OTSEC_VM1_KEYS_OUT names.
This script reads that file and the job's tee'd output, fails if any key
appears in the output raw, as hex in either case, or as base64, and then
deletes the key file. Usage: python vm1_keysearch.py KEYS OUTPUT
"""

import base64
import json
import os
import sys


def main(keys_path, out_path):
    with open(keys_path, encoding="utf-8") as f:
        keys = [bytes.fromhex(k) for k in json.load(f)]
    with open(out_path, "rb") as f:
        out = f.read()
    try:
        found = sum(1 for k in keys for n in (k, k.hex().encode(), k.hex().upper().encode(), base64.b64encode(k)) if n in out)
    finally:
        os.remove(keys_path)
    if not keys:
        print("vm1_keysearch: no keys to search for")
        return 1
    if found:
        print(f"vm1_keysearch: {found} key forms found in the job's output")
        return 1
    print(f"vm1_keysearch: none of {len(keys)} keys, in 4 forms each, is in {len(out)} bytes of output")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
