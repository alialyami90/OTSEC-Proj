# Security policy

OTSEC is a cybersecurity platform for operational technology: electrical substations, SCADA environments and protective relays. It is under development. No release exists, nothing in this repository is supported for production use, and no device family is called supported.

## Reporting a vulnerability

**Report it privately, through GitHub.** On this repository's **Security** tab, choose **Report a vulnerability**. That opens a private advisory which only the maintainers can read.

- Do not open a public issue or pull request that describes a vulnerability.
- If the **Report a vulnerability** button is missing, open an issue that says only that you have a security report, with no details, and ask for a private channel.
- Say what you found, the file and the commit it is in, how to reproduce it, and what an attacker could do with it.
- Please do not publish the details before a fix is available.

Reports of these kinds are especially wanted:

- a way to use the platform as a path into operational equipment;
- a command that reaches a device without being in the signed command register;
- a weakness in the collector's credential store, or in the channel between the node and the collector;
- a signature check or a rollback check that can be bypassed.

This is a small project with no release yet, so no response time is promised. Reports are read, and the answer or the fix is given through the same private advisory.

## What you may test

- **Your own copy of the code,** built and run on machines you own, against the simulators in this repository or against lab equipment you own that is out of service and isolated. The code has only ever been run against simulators, so treat any real device as untested.
- **The workflows, in your own fork only.**
- **Never** equipment, networks or systems that you do not own or are not authorized to test.
- **Never** an operational substation or any industrial network that is in service. A read-only command can still disturb a protective relay.
- **Never against this repository itself:** no pull request, issue or workflow run made as a test, no denial of service, no social engineering, and no testing of other people's forks.

The project runs no public service and no hosted instance. What is online is this repository and its GitHub Actions workflows, and the limits above apply to both.

This permission covers security research for the purpose of reporting to this project. It grants no other right: see [LICENSE.md](LICENSE.md).

## What is in scope

- The code in this repository: the site node (`cmd/otsec`), the privileged collector (`cmd/otsec-collector`), the contracts and the modules they use.
- The repository's GitHub Actions workflows.

## What is not a vulnerability here

- **Test keys and test credentials in the repository.** They are public on purpose. The repository holds test credentials only, and a build made without the test tag refuses the test advisory keys. Two things **are** vulnerabilities: a build made without the test tag that accepts a test key, and a real secret committed by mistake.
- **Plaintext Telnet to the SEL-751.** It is the device family's own limit, and the collection path is labelled insecure. The owner accepted it for the first slice, with the controls that [ADR-0005](docs/decisions/ADR-0005-first-slice-scenario-and-transport.md) lists, and not for production use. A report that one of those controls fails is wanted.
- **A limit that the project's own records already state.** The threat model ([docs/threat-model.md](docs/threat-model.md)) and the exit reports under `docs/` list the known risks. A report that shows one of them is worse than recorded is still welcome.

## Supported versions

None. No release exists. Fixes go to the `main` branch.
