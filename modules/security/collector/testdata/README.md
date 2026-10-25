# collector test data

Each file is copied rather than read across packages, so this package's tests do not depend on another package's test data layout.

- `register-sel-751.json` is a copy of `contracts/register/testdata/sel-751.json` (C3, revision 2). The tests sign it with a release key they generate.
- `sel-751-simulated.json` and `profile-sel-751-ascii.json` are copies of the C1 fixtures in `contracts/asset/testdata/valid/`. The tests move the asset's endpoint to 127.0.0.1 (D2-10).
- `result-ok.json` is a copy of `contracts/adapter/testdata/results/valid/ok.json` (C2). It is a synthetic simulated session (evidence class simulated); nothing in it is device output.

The test secrets are in the test files themselves. They are test values (D2-5), never device passwords.
