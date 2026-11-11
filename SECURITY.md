# Security policy

OTSEC is a cybersecurity platform for operational technology: electrical substations, SCADA environments and protective relays. It is under development. No release exists, nothing in this repository is supported for production use, and no device family is called supported.

## Reporting a vulnerability

**Report it privately, through GitHub.** On this repository's **Security** tab, choose **Report a vulnerability**. That opens a private advisory which only the maintainers can read.

- Do not open a public issue or pull request for a vulnerability.
- Say what you found, the file and the commit it is in, how to reproduce it, and what an attacker could do with it.
- A report about how the platform could be used as a path into operational equipment is especially wanted.

This is a small project with no release yet, so no response time is promised. Reports are read, and the answer or the fix is given through the same private advisory.

## What you may test

- **Your own copy of the code,** built and run on machines you own, against the simulators in this repository or against lab equipment you own.
- **Never** equipment, networks or systems that you do not own or are not authorized to test.
- **Never** an operational substation or any industrial network that is in service. A read-only command can still disturb a protective relay.

The project runs no public service and no hosted instance, so nothing of the project's is online to test.

This permission covers security research for the purpose of reporting to this project. It grants no other right: see [LICENSE.md](LICENSE.md).

## What is in scope

- The code in this repository: the site node (`cmd/otsec`), the privileged collector (`cmd/otsec-collector`), the contracts and the modules they use.
- The repository's GitHub Actions workflows.

## What is not a vulnerability here

- **Test keys and test credentials in the repository.** They are public on purpose. The repository holds test credentials only, and a release build refuses the test advisory keys.
- **Plaintext Telnet to the simulated SEL-751.** It is the device family's own limit, it is labelled insecure, and it is accepted for the lab only ([ADR-0005](docs/decisions/ADR-0005-first-slice-scenario-and-transport.md)).
- **A limit that the project's own records already state.** The threat model ([docs/threat-model.md](docs/threat-model.md)) and the exit reports under `docs/` list the known risks. A report that shows one of them is worse than recorded is still welcome.

## Supported versions

None. No release exists. Fixes go to the `main` branch.
