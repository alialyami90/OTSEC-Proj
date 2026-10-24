# collectorclient test data

`register-sel-751.json` is a copy of `contracts/register/testdata/sel-751.json` (C3, revision 2).

`result-ok.json` is a copy of `contracts/adapter/testdata/results/valid/ok.json` (C2), a synthetic simulated session (evidence class simulated; nothing in it is device output). It is copied rather than read across packages, so this package's tests do not depend on another package's test data layout.
