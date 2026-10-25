# A6: Windows installer check (#92, A3 T-13)

Owner: A6. These scripts run A5's installer (`otsec install`, `platform/winsvc`) on a real Windows host, check what it created, and then remove all of it. The owner approved one run on their PC on 2026-10-25, with cleanup afterwards.

| File | Shell | What it does |
| --- | --- | --- |
| `installer_check.ps1` | elevated | Preflight, W-4 refusal, install, checks, a short run of the node service, uninstall, cleanup |
| `nonadmin_check.ps1` | normal user | While the elevated script waits, checks that a non-admin user is refused each read and write it tries |
| `node.template.json` | | Node configuration from `nodeconfigtest`: one simulated SEL-751 at 127.0.0.1:2323. `STOREDIR` is replaced with `%ProgramData%\OTSEC\store` |
| `collector.stand-in.json` | | JSON passed to `-collector-config`. It is not A3's format, and no collector runs |

## Order

1. Non-admin shell: build `otsec.exe` from the PR head, then create `%ProgramData%\OTSEC\store` (the W-4 pre-created folder).
2. Elevated: `installer_check.ps1 -Exe <otsec.exe> -LogDir <dir>`. It stops at once if any OTSEC service, folder, firewall rule, event source or WER value already exists, apart from that one folder.
3. When `<dir>\elevated-installed` appears, non-admin shell: `nonadmin_check.ps1 -LogDir <dir>`. The elevated script waits up to 15 minutes for `<dir>\nonadmin-done`.
4. The elevated script then starts `otsec-node` for 90 s and stops it. Its `finally` block uninstalls and removes `%ProgramData%\OTSEC`, `%ProgramFiles%\OTSEC`, and the `ExcludedApplications` key if this run created it. It ends with `RESULT CLEAN`.

## What it covers, and what it does not

- **Covered:**
  - W-4: a pre-created folder stops the installer.
  - The exact directory ACEs from `TestDirs`, including `config\tls` (D2-12). That check and the two non-admin `config\tls` refusals were added after the 2026-10-25 run and have not run yet.
  - `node.json`, and `collector.json` from `-collector-config`.
  - The provision marker and `collector\public`.
  - Each service's configuration: virtual account, unrestricted SID, `SeChangeNotifyPrivilege` as the only privilege, restart on failure.
  - The W-3 firewall rule, the WER value and the event sources.
  - A second install is refused.
  - Non-admin refusals.
  - The node service runs under its account and creates its store.
  - Uninstall, and nothing is left behind.
- **Not covered, owed until A3's collector binary exists:**
  - W-1: the pipe impostor.
  - W-2 on a live token. Only the configured privilege list is checked here.
  - W-3 by connection: only the collector reaching port 23.
  - The collector's first start from the provision marker.
- Events that `otsec-node` writes stay in the Application event log. They are log data, not configuration.

Evidence class: native Windows host, simulated device. No device is contacted. The collector binary is a renamed copy of `otsec.exe`, which is installed but never started.
