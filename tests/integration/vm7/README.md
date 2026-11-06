# V-M7 over GT-ADV (C6, P4-3-C6 deliverable 3)

Evidence class: desk until the runner drives the binaries, then simulated. No device is contacted.

`vm7.py` decides V-M7 from what a run of the node stored and showed. It does not start a process or read a store. The runner that starts the node and the collector against the simulator, and gathers the `observed` dict described in `vm7.py`, comes with C5's part 3, because it needs part 3's status and store field names.

What it checks:

- **Each of GT-ADV's 128 cells** (`check`): the class and reason; the set the finding was decided under; every evidence kind the cell lists cited by the ID the run made; each evidence ID in its source's C12 form, so an operator entry never stands as a device read; the unread preconditions exactly; stale where the cell says so, and never on `confirmed`; operator-attested exactly on the cells that say so; `confirmed` only on a device-read identity; no field naming exploitability; each revision following its predecessor.
- **`product-not-named` cells with no stored finding** (D4-54): the cell passes only when the asset's last completed evaluation ran under the set in use and is later than the asset's newest identity record. A stored `product-not-named` revision is checked as a finding.
- **A restart, and a chain prune then a restart** (`check_restart`): no finding is added or revised, and each asset keeps its identity evidence ID, so an operator row still cites the same `policy.apply` record.
- **A later FID mismatch** (`check_mismatch`, run before and after a restart): the newest finding is `applicable-by-version`, with `firmware-version` unread, the identity stale and the mismatch read cited; `identity.read` keeps the mismatch FID and the last confirming read as its latest read.

`test_vm7_checker.py` builds the observation a node that follows GT-ADV and D4-54 would give, shows that it passes, and shows that each way of getting a cell or scenario wrong fails the cell it touches and no cell on another row.

Run: `python -m pytest -q tests/integration/vm7`.
