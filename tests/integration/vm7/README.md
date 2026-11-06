# V-M7 over GT-ADV (C6, P4-3-C6 deliverable 3)

Evidence class: desk for the checker; simulated for the run on the binaries. No device is contacted.

`vm7.py` decides V-M7 from what a run of the node stored and showed. It does not start a process or read a store. The runner on the binaries is `tests/integration/slice/test_slice_vm7_e2e.py`: it starts a node, a collector and a simulator for each device-read row, gathers the `observed` dict described in `vm7.py`, and checks every cell. The control rows' `tcp/80` is their asset's `asset_controls` entry, recorded by a `policy.apply` record (D4-56).

What it checks:

- **Each of GT-ADV's 128 cells** (`check`): the class and reason; the set the finding was decided under; every evidence kind the cell lists cited by the ID the run made; each evidence ID in its source's C12 form, so an operator entry never stands as a device read; the unread preconditions exactly; stale where the cell says so, and never on `confirmed`; operator-attested exactly on the cells that say so; `confirmed` only on a device-read identity; no field naming exploitability; each revision following its predecessor.
- **`product-not-named` cells with no stored finding** (D4-54): the cell passes only when the asset's last completed evaluation ran under the set in use and on the asset's newest identity record (it names that record's evidence ID, as C5 proposed on #458, rather than comparing times). An operator-only row has no identity record, so there the evaluation names the declared identity's `policy.apply` record and the IDs are matched the same way (C1, after C4 on #459). A stored `product-not-named` revision is checked as a finding.
- **A restart, and a chain prune then a restart** (`check_restart`): no finding is added or revised, and each asset keeps its identity evidence ID, so an operator row still cites the same `policy.apply` record.
- **A later FID mismatch** (`check_mismatch`, run before and after a restart), on a device-read row and on an operator-only row (C1's ruling, #459): the newest finding is `applicable-by-version`, with `firmware-version` unread and the identity stale, and the identity source unchanged; a device-read finding cites the mismatch read (C12 0.1 cannot cite it on an operator identity, a C12 0.2 item); `identity.read` keeps the mismatch apart, and the last confirming read, if any, as its latest read.

`test_vm7_checker.py` builds the observation a node that follows GT-ADV and D4-54 would give, shows that it passes, and shows that each way of getting a cell or scenario wrong fails the cell it touches and no cell on another row.

Run: `python -m pytest -q tests/integration/vm7`.
