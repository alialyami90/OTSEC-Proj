# Release record

Owner: D7 (brief P4-D7-1, in PR #614, not yet on `main`). Reviewers: D3 (the update path and the supply-chain rows) and D6 (that every claim can be checked).

This file records what the two binaries contain and under which licences, and what a release still lacks. It is an inventory, not a release. Nothing here is compliant, certified or release-ready. No release of OTSEC has ever been built for distribution or shipped to a node.

**Evidence class: `desk`.** Every row of §1 to §6 was read on 2026-11-11 from `main` at `b383a242` (#611), from the Go toolchain's own output (Go 1.27.3, `windows/amd64` host), from the licence files in the Go module cache and the Go distribution, and, for the third-party programs, from upstream files downloaded on the same day. No test was run for those sections. §7 was read on 2026-11-15, at the commits it names, and states its own evidence.

Paths below are relative to the module cache (`$(go env GOMODCACHE)`) or to the Go distribution (`$(go env GOROOT)`).

## 1. The inventory of each binary

### How it was derived

The release build is the one ADR-0003 names: `CGO_ENABLED=0 go build -trimpath`, with no build tags. The targets are `windows/amd64` (the site node, ADR-0007) and `linux/amd64` and `linux/arm64` (ADR-0003). The set of linked modules depends on the target, so each target is listed.

```sh
# environment for every command below
export GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0

# the inventory block in §1.2, one line per linked module
for t in windows/amd64 linux/amd64 linux/arm64; do
  for b in otsec otsec-collector; do
    GOOS=${t%/*} GOARCH=${t#*/} go list -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Sum}}{{with .Replace}} => {{.Path}} {{.Version}}{{end}}{{end}}{{end}}' \
      ./cmd/$b | sort -u | sed "s#^#$t $b #"
  done
done

# cross-check against the built binary (the build info Go embeds)
GOOS=windows GOARCH=amd64 go build -trimpath -o <scratch>/otsec.exe ./cmd/otsec
go version -m <scratch>/otsec.exe

# the cache matches go.sum
go mod verify
```

Results on 2026-11-11 at `b383a242`:

- `go list -deps` and `go version -m` agree for `windows/amd64` and `linux/amd64`, both binaries. `go version -m` reports `go1.27.3`, `-trimpath=true`, `CGO_ENABLED=0` and `vcs.revision=b383a242740f790de5bef0203563cd1e8481e7a9`. `linux/arm64` was listed with `go list` only, not built.
- `go mod verify`: "all modules verified".
- **Modules linked per binary** (third-party, excluding the main module `otsec.local/otsec`):

| Binary | `windows/amd64` | `linux/amd64` | `linux/arm64` |
| --- | --- | --- | --- |
| `cmd/otsec` | 9 | 8 | 8 |
| `cmd/otsec-collector` | 1 | 1 | 1 |

- **Standard library packages linked:** `cmd/otsec` 187 on `windows/amd64` and 184 on `linux/amd64`; `cmd/otsec-collector` 149 and 147.
- Only `platform/store` imports `modernc.org/sqlite`. Every module in `cmd/otsec`'s list other than `golang.org/x/sys` comes in through it.

### 1.1 The Go toolchain and standard library

| Component | Version | What is linked |
| --- | --- | --- |
| Go runtime and standard library | `go1.27.3` (`$GOROOT/VERSION`: "time 2026-10-19T22:20:36Z") | Both binaries, every target |
| `golang.org/x/crypto`, vendored in the standard library | `v0.52.1-0.20260526024921-9beb694f9766` (`$GOROOT/src/vendor/modules.txt`) | `cmd/otsec` only: `chacha20`, `chacha20poly1305`, `cryptobyte`, `cryptobyte/asn1`, `internal/alias`, `internal/poly1305` |
| `golang.org/x/net`, vendored | `v0.55.1-0.20260731170536-c1d18010be90` | Both binaries: `dns/dnsmessage` |
| `golang.org/x/sys`, vendored | `v0.45.0` | `cmd/otsec` only: `cpu` |
| `golang.org/x/text`, vendored | `v0.37.0` | Neither binary |

The standard library's own copy of `golang.org/x/sys/cpu` (v0.45.0) and the module `golang.org/x/sys` v0.49.0 are both linked into `cmd/otsec`. They are separate packages, and both are listed.

### 1.2 Modules linked into each binary

The `h1:` value is the module's line in `go.sum`, as `go list` reports it.

<!-- inventory:begin -->
```text
windows/amd64 otsec github.com/dustin/go-humanize v1.1.0 h1:dbKTrvD0klcbBV/h4AWJdMuZogJACoMlvWIWZ5b2xWg=
windows/amd64 otsec github.com/mattn/go-isatty v0.0.24 h1:tGZZoVgT/KiqK1c8ocVLeDS8BSWMRd47J3Lbz7vsReI=
windows/amd64 otsec github.com/ncruces/go-strftime v1.1.0 h1:vtPmPWMkb539RGV9WpWT9EwJGvrOCKvMNI4obWL47Hk=
windows/amd64 otsec github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec h1:W09IVJc94icq4NjY3clb7Lk8O1qJ8BdBEF8z0ibU0rE=
windows/amd64 otsec golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
windows/amd64 otsec modernc.org/libc v1.79.0 h1:9Dvvv++bAMSkSuBzuOFAatbTV5OIoq6Y6FohmD3e7q8=
windows/amd64 otsec modernc.org/mathutil v1.7.1 h1:GCZVGXdaN8gTqB1Mf/usp1Y/hSqgI2vAGGP4jZMCxOU=
windows/amd64 otsec modernc.org/memory v1.12.1 h1:nFMiWrpStgZczNl6XI9GnIk/rWhYIyHGUaR04pGbp9g=
windows/amd64 otsec modernc.org/sqlite v1.61.0 h1:sQi63oLQ9uquAUA4CzOisH35Q3pEszkPBuHM0tFL8CY=
windows/amd64 otsec-collector golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
linux/amd64 otsec github.com/dustin/go-humanize v1.1.0 h1:dbKTrvD0klcbBV/h4AWJdMuZogJACoMlvWIWZ5b2xWg=
linux/amd64 otsec github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
linux/amd64 otsec github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec h1:W09IVJc94icq4NjY3clb7Lk8O1qJ8BdBEF8z0ibU0rE=
linux/amd64 otsec golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
linux/amd64 otsec modernc.org/libc v1.79.0 h1:9Dvvv++bAMSkSuBzuOFAatbTV5OIoq6Y6FohmD3e7q8=
linux/amd64 otsec modernc.org/mathutil v1.7.1 h1:GCZVGXdaN8gTqB1Mf/usp1Y/hSqgI2vAGGP4jZMCxOU=
linux/amd64 otsec modernc.org/memory v1.12.1 h1:nFMiWrpStgZczNl6XI9GnIk/rWhYIyHGUaR04pGbp9g=
linux/amd64 otsec modernc.org/sqlite v1.61.0 h1:sQi63oLQ9uquAUA4CzOisH35Q3pEszkPBuHM0tFL8CY=
linux/amd64 otsec-collector golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
linux/arm64 otsec github.com/dustin/go-humanize v1.1.0 h1:dbKTrvD0klcbBV/h4AWJdMuZogJACoMlvWIWZ5b2xWg=
linux/arm64 otsec github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
linux/arm64 otsec github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec h1:W09IVJc94icq4NjY3clb7Lk8O1qJ8BdBEF8z0ibU0rE=
linux/arm64 otsec golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
linux/arm64 otsec modernc.org/libc v1.79.0 h1:9Dvvv++bAMSkSuBzuOFAatbTV5OIoq6Y6FohmD3e7q8=
linux/arm64 otsec modernc.org/mathutil v1.7.1 h1:GCZVGXdaN8gTqB1Mf/usp1Y/hSqgI2vAGGP4jZMCxOU=
linux/arm64 otsec modernc.org/memory v1.12.1 h1:nFMiWrpStgZczNl6XI9GnIk/rWhYIyHGUaR04pGbp9g=
linux/arm64 otsec modernc.org/sqlite v1.61.0 h1:sQi63oLQ9uquAUA4CzOisH35Q3pEszkPBuHM0tFL8CY=
linux/arm64 otsec-collector golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=
```
<!-- inventory:end -->

What differs by target, and why (from `go list -deps` on each target):

- `github.com/mattn/go-isatty` and `github.com/ncruces/go-strftime` are linked on `windows/amd64` only. `modernc.org/libc`'s Windows build imports them.
- `github.com/google/uuid` is linked on Linux only. `modernc.org/libc`'s Linux build imports it through `modernc.org/libc/uuid/uuid`.
- Of `modernc.org/sqlite`, the packages linked are `modernc.org/sqlite`, `modernc.org/sqlite/lib` and `modernc.org/sqlite/vtab`. `modernc.org/sqlite/vec` and `modernc.org/sqlite/vfs` are not linked.
- Of `golang.org/x/sys`: `cmd/otsec-collector` links `windows`, `windows/registry`, `windows/svc` and `windows/svc/eventlog` on Windows, and `unix` on Linux. `cmd/otsec` adds `cpu` and `windows/svc/mgr` on Windows.

Every module that `go.mod` names (2 direct, 8 indirect) is linked into `cmd/otsec` on at least one target.

### 1.3 Modules in `go.sum` that neither binary links

These 15 modules have lines in `go.sum` but are not in `go.mod`, and no package of theirs is in either binary on any target above. `go mod why -m` shows each is reached only through the test packages of `modernc.org/libc` (`modernc.org/libc.test`) or `modernc.org/sqlite` (`modernc.org/sqlite.test`). Their licences were not read for this record, because nothing of theirs is shipped.

| Module | Version | Reached through |
| --- | --- | --- |
| `github.com/google/pprof` | `v0.0.0-20261016150608-1facf8f91b50` | `modernc.org/sqlite.test` |
| `modernc.org/fileutil` | `v1.4.0` | `modernc.org/sqlite.test` |
| `golang.org/x/tools` | `v0.52.0` | `modernc.org/libc.test` |
| `golang.org/x/sync` | `v0.24.0` | `modernc.org/libc.test`, through `golang.org/x/tools` |
| `golang.org/x/mod` | `v0.42.0` | `modernc.org/libc.test`, through `modernc.org/ccgo/v4` |
| `github.com/hashicorp/golang-lru/v2` | `v2.0.7` | `modernc.org/libc.test`, through `modernc.org/gc/v3` |
| `modernc.org/cc/v4` | `v4.30.3` | `modernc.org/libc.test` |
| `modernc.org/ccgo/v4` | `v4.37.0` | `modernc.org/libc.test` |
| `modernc.org/gc/v2` | `v2.6.5` | `modernc.org/libc.test`, through `modernc.org/ccgo/v4` |
| `modernc.org/gc/v3` | `v3.2.0` | `modernc.org/libc.test`, through `modernc.org/ccgo/v4` |
| `modernc.org/goabi0` | `v0.2.0` | `modernc.org/libc.test` |
| `modernc.org/opt` | `v0.2.0` | `modernc.org/libc.test`, through `modernc.org/cc/v4` |
| `modernc.org/sortutil` | `v1.2.1` | `modernc.org/libc.test`, through `modernc.org/cc/v4` |
| `modernc.org/strutil` | `v1.2.1` | `modernc.org/libc.test`, through `modernc.org/cc/v4` |
| `modernc.org/token` | `v1.1.0` | `modernc.org/libc.test`, through `modernc.org/cc/v4` |

## 2. Licences of what is linked

Each row names the file that was read and its SHA-256. The SPDX identifier is D7's judgement from the text. A file named here that is not a licence (`AUTHORS`, `CONTRIBUTORS`) is not listed.

### 2.1 Go

| Component | File read | SPDX | SHA-256 |
| --- | --- | --- | --- |
| Go runtime and standard library | `$GOROOT/LICENSE` | BSD-3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| Go, patent grant | `$GOROOT/PATENTS` | none (Google's additional patent grant) | `96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc` |
| Vendored `x/crypto`, `x/net`, `x/sys` | `$GOROOT/src/vendor/golang.org/x/{crypto,net,sys}/LICENSE` and `PATENTS` | BSD-3-Clause, with the patent grant | Each `LICENSE` is `911f8f57…`, each `PATENTS` is `96f408bf…`: byte-identical to the two files above |

### 2.2 Modules

| Module | File read | SPDX | SHA-256 |
| --- | --- | --- | --- |
| `github.com/dustin/go-humanize@v1.1.0` | `LICENSE` | MIT | `a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71` |
| `github.com/google/uuid@v1.6.0` | `LICENSE` | BSD-3-Clause | `0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d` |
| `github.com/mattn/go-isatty@v0.0.24` | `LICENSE` | MIT | `08eab1118c80885fa1fa6a6dd7303f65a379fcb3733e063d20d1bbc2c76e6fa1` |
| `github.com/ncruces/go-strftime@v1.1.0` | `LICENSE` | MIT | `38ae43959daf953a393a585b2988672cb65a5a541aca0d0be5e72595a0a16883` |
| `github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec` | `LICENSE` | BSD-3-Clause | `dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d` |
| `golang.org/x/sys@v0.49.0` | `LICENSE` | BSD-3-Clause | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `golang.org/x/sys@v0.49.0` | `PATENTS` | none (patent grant) | `96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc` |
| `modernc.org/libc@v1.79.0` | `LICENSE` | BSD-3-Clause | `95ff867eb55a56935fa7492406cfa953fb7c13ca73f4c0a86ae05756b4605600` |
| `modernc.org/libc@v1.79.0` | `LICENSE-3RD-PARTY.md`: notices for Go (BSD-3-Clause), musl libc (MIT; it names parts under BSD-2-Clause and other permissive terms, and a public-domain part), go-netdb (MIT) and NixOS/nixpkgs (MIT) | BSD-3-Clause AND MIT AND BSD-2-Clause | `f597097efe3d97021f89170746bd3a0fb9a8b6fb26b82043ed68a4e0283bee6c` |
| `modernc.org/mathutil@v1.7.1` | `LICENSE` | BSD-3-Clause | `bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5` |
| `modernc.org/memory@v1.12.1` | `LICENSE` | BSD-3-Clause | `59895e669f48f168b6b858358f6005779cdf40a265f7828813061b56af67b496` |
| `modernc.org/memory@v1.12.1` | `LICENSE-GO` (The Go Authors) | BSD-3-Clause | `2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067` |
| `modernc.org/memory@v1.12.1` | `LICENSE-MMAP-GO` (Evan Shaw) | BSD-3-Clause | `c2eba69f20d05414538c3a5df7694dde392e065ff70882e1625e90f5d6659fff` |
| `modernc.org/sqlite@v1.61.0` | `LICENSE` | BSD-3-Clause | `c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822` |
| `modernc.org/sqlite@v1.61.0` | `LICENSE-SQLITE` (SQLite, transpiled into `lib/`) | public domain (the file is titled "SQLite Is Public Domain") | `8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0` |

Files read and set aside:

- `modernc.org/memory@v1.12.1/LICENSE-LOGO` (`5ae5bee3072a841376451b48d8cfcec7188e10543926d5870828d36c8a750dc5`) holds only a URL to the project's logo image. The logo is not in the binary.
- `modernc.org/sqlite@v1.61.0/LICENSE-SQLITE_VEC` (MIT, `6ce72bbe12d975bd5286e5ab0a064c069693300c47bccbc57bec18485f1621ea`) covers `modernc.org/sqlite/vec`, which is not linked.
- `modernc.org/mathutil@v1.7.1/mersenne/LICENSE` (`c05630f9ca899ea094620d37daea6ba66f99adbf9268ea5fea9db607e1102bd9`) covers the `mersenne` package, which is not linked.
- `modernc.org/libc@v1.79.0/testdata/` holds a GPLv2 text (`testdata/nsz.repo.hu/libc-test/src/math/crlibm/COPYING`, `dcc100d4161cc0b7177545ab6e47216f84857cda3843847c792a25289852dcaa`) and an MIT notice for libc-test (`testdata/nsz.repo.hu/libc-test/COPYRIGHT`, `41b8f2e2706012eb534f89e72ff547308cb81dcb9acf077c40a9058a7c06088d`). `go build` ignores `testdata` directories, so neither reaches a binary.
- `modernc.org/sqlite@v1.61.0/LICENSE-3RD-PARTY.md` (`4194f8e7119be72babd499db4f6f1f7547e36e8a7bffcb2b9c8df241b8f1576a`) is upstream's own inventory, read for its first four sections only. It classifies `go-isatty` and `go-strftime` as "in the module graph, not compiled into anything". That is not true of OTSEC's `windows/amd64` build (§1.2), so upstream's classification is not used here.

No linked component was found under a copyleft licence, and none was found without a licence file.

## 3. What each licence asks of a distributor, and whether it is done

No release has been distributed, so no duty has yet been owed. Each line says what the first distribution of a binary will owe, and whether the repository already has it.

| Component | What distributing the binary asks | Done today |
| --- | --- | --- |
| Go runtime, standard library and its vendored `x/` packages | BSD-3-Clause: reproduce the copyright notice, the conditions and the disclaimer in the documentation or other materials. No endorsement by the names. `PATENTS` asks nothing. | **Open** |
| `golang.org/x/sys` | As Go. | **Open** |
| `github.com/google/uuid` (Linux only), `github.com/remyoudompheng/bigfft`, `modernc.org/mathutil` | BSD-3-Clause, as Go. | **Open** |
| `modernc.org/libc` | BSD-3-Clause for `LICENSE`, and the notices in `LICENSE-3RD-PARTY.md` (Go, musl, go-netdb, nixpkgs), which are MIT and BSD and ask for the notices to be kept. D7 has not mapped which notice covers which linked file, so the whole file is carried. | **Open** |
| `modernc.org/memory` | BSD-3-Clause, three times: `LICENSE`, `LICENSE-GO`, `LICENSE-MMAP-GO`. | **Open** |
| `modernc.org/sqlite` | BSD-3-Clause for the Go code. SQLite itself is public domain and asks nothing. | **Open** (the BSD part) |
| `github.com/dustin/go-humanize`, `github.com/mattn/go-isatty` and `github.com/ncruces/go-strftime` (the last two Windows only) | MIT: include the copyright notice and the permission notice. | **Open** |

**Open duty R-1:** the repository has no third-party notices file, and neither binary carries one. A release needs a notices file, beside each binary or inside its package, holding the texts in §2 for the binary's target. This record lists the duty and does not fix it.

No linked component asks for a source offer.

## 4. Third-party programs under ADR-0009's option (a), not shipped today

The owner chose option (a) on 2026-11-10 and said no work starts on it yet (D4-78). None of these programs is in the repository or in either binary. AP-31, which is proposed, requires that a program a node runs be shipped in the signed release, never be fetched at install time, and be listed in the inventory. No signed release exists.

The four files ADR-0009 hashed on 2026-11-07 were downloaded again on 2026-11-11 from `raw.githubusercontent.com`, and all four hashes are unchanged.

| Program | File read (repository, ref, commit on 2026-11-11) | SPDX | SHA-256 | Same as ADR-0009 |
| --- | --- | --- | --- | --- |
| Npcap | `nmap/npcap`, `master`, `ac3db0346a2ff652e174e15756193ea055f042d5`: `LICENSE` | LicenseRef-Npcap (proprietary; source published for review) | `0543f4f93939013f80852d33469b1b5a2623676b387994ffb7a01e34e443ac83` | yes |
| Suricata | `OISF/suricata`, default branch `main` at `9c1423f170d21231dda62b5d87ad4aedbcce4c1d`: `LICENSE` | GPL-2.0 (the text; whether files say "or later" was not checked) | `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643` | yes |
| Suricata | the same commit: `doc/userguide/install/windows.rst` | (documentation) | `ca1dc37d836147cc3a382fee8fad496deb0dd1fe9cb959ff6a96b874df76a67f` | yes |
| Zeek | `zeek/zeek`, `master`, `5a6529c8a60600ac732f4e6dce84a5407a8cddb2`: `COPYING` | BSD-3-Clause | `1f984adb6b5cd93d5035c2a87c2df5f38922649fbea90c7bd79ff321d17333aa` | yes |
| Zeek | the same commit: `COPYING-3rdparty` | several (below) | `b815419a9ec7c307d49983dc5cead5e411ace082a638a2d7bbd4d3deb1ac8a4a` | not in ADR-0009 |
| ICSNPP-DNP3 | `cisagov/icsnpp-dnp3`, `main`, `b31dbadeceb1cbcda16aef89c650559cd177dd7e`: `LICENSE.txt` | BSD-3-Clause (Battelle Energy Alliance) | `4c66ca6036dae3010138952138e8df3a7d037cf05a9643a108f20f05c794e98d` | ADR-0009 kept no hash |
| ICSNPP-Modbus | `cisagov/icsnpp-modbus`, `main`, `6dd3dab173169e454a73925d0426d3c019104852`: `LICENSE.txt` | BSD-3-Clause | `4c66ca6036dae3010138952138e8df3a7d037cf05a9643a108f20f05c794e98d` (byte-identical to ICSNPP-DNP3's) | ADR-0009 kept no hash |

What shipping each beside the product would ask, from the text read:

- **Npcap.** The file says Npcap "is not open source software and may not be redistributed or used in other software without special permission from the Nmap Project". The free licence allows five systems and forbids redistribution and transfer without written consent. Shipping it in the release needs the "Npcap OEM Redistribution License". It also names three BSD-style components (libpcap, WinPcap, `ieee80211_radiotap.h`) whose acknowledgement text "be added somewhere in the documentation", and points to `npcap.com/src/docs/Npcap-Third-Party-Open-Source.pdf` for that text. **Not read:** the OEM licence's price and terms (pending: D4's brief P4-4-S1, which is in PR #614 and not yet on `main`), and the third-party PDF (on `npcap.com`, not fetched).
- **Suricata.** GPLv2 §1 and §3: with each copy of the executable, give the licence text, and either the complete corresponding source, including "the scripts used to control compilation and installation", or a written offer of it valid for at least three years. §3(c), passing on the offer received, is for noncommercial distribution only. Running Suricata as a separate process does not put OTSEC's binaries under the GPL (ADR-0003, ADR-0009), but the Suricata binary that a release ships carries these duties. **Not read:** the third-party components inside Suricata's source and its Windows installer, and their licences.
- **Zeek.** `COPYING` is BSD-3-Clause: carry the notice, the conditions and the disclaimer. `COPYING-3rdparty` says it "may not contain the licenses of all third party software contained in Zeek". It lists code under MIT, BSD, Boost-1.0, Apache-2.0, MPL-2.0 (`mozilla-ca-list.zeek`), LGPL-3.0-or-later with its author's permission to use it in Zeek under BSD (Multifast), public domain (SQLite) and the JSON licence, whose term "The Software shall be used for Good, not Evil" is unusual. Which of these reach a Zeek build for Windows is `unknown`: no official Zeek binary for Windows was found (ADR-0009). Shipping Zeek means carrying `COPYING`, the notices in `COPYING-3rdparty` that apply to the build, and the MPL-2.0 file's source.
- **ICSNPP-DNP3 and ICSNPP-Modbus.** BSD-3-Clause: carry the notice, the conditions and the disclaimer. Their READMEs were not read again for this record.

Security duties beside the licence duties, all **open** (from D3's review of #615). The hashes above are of licence files at branch tips, not of any program version.

- **A pinned version and artifact hash for each program,** with the upstream signature checked when the artifact is taken in.
- **Who watches each program's advisories.** `govulncheck` covers Go modules only, not Npcap, Suricata, Zeek or ICSNPP (AP-30 asks for a re-check of upstream advisories for each pinned version).
- **The libraries each program bundles,** with their versions, in the inventory and the SBOM.
- **Npcap's driver signature, and its installer,** which runs with administrator rights.
- **Nothing fetched at run time:** no rule set, signature update or package (zkg for ICSNPP, for example) is downloaded by a node. Each comes in the signed release.

## 5. What does not exist yet

A list only. No design is in this brief.

1. **Signing of the update package, and the key's holder.** TB9 requires an offline release key that is not present on central. Who holds it and where it is kept is owed by the owner (`HANDOFF.md`, item 12). No key, real or test, exists for signing an update package. HR-18 (the advisory set's key, recommended never to be the release key) is not decided either.
   - **A separate thing that does exist: the command register's signing** (C7, `contracts/authz/registersig.go`). Its code calls the register's signer a "release key": the node holds `TrustAnchor` release public keys, installed at enrollment or by a signed release and never by central policy. The collector keeps a `FamilyFloor` per device family and refuses a lower revision. The tests sign with keys derived from fixed seeds. That is register signing, not update-package signing. Neither may be cited as evidence for the other.
   - The key the owner places therefore also decides which commands reach devices, because a register that verifies against a trust anchor names the operations the collector may run (C3, AP-27).
2. **The SBOM.** None is generated. Proposed format, for D1 to decide: one CycloneDX 1.6 JSON document per release and target, built from `go version -m` of the release binaries, with the non-Go components of option (a) (Npcap, the engine, its decoders) added by hand, and signed with the release.
3. **The update package's contract.** Not opened. D7 drafts it when D1 opens it, and D1 approves it. D5 builds the node's update verifier.
4. **The update package's anti-rollback floor.** Not designed. (The register's per-family floor in item 1 is a different floor, and it exists.) AP-10's three refusals (a tampered package, a signed package below the floor, an unsigned package) have no code and no test.
5. **The record of which versions upgrade and roll back together** (R8.7). It is §7. No release exists, so it holds floors and conditions, not released versions.
6. **A release build.** ADR-0003 names `CGO_ENABLED=0 go build -trimpath` from a pre-installed pinned toolchain. No workflow runs a release build. CI's integration job builds without `-trimpath`, and builds `cmd/otsec` with the test tag `otsec_testclock`, under which the node accepts the advisory test keys as anchors (`platform/node/advisory_testbuild.go`). Neither is a release build.
7. **What is pinned and what is not.** Facts and open items, not findings:
   - **The toolchain.** ADR-0003 says it is pinned with `go.mod`'s `go` and `toolchain` lines. `go.mod` has `go 1.27.3` and no `toolchain` line. Every workflow's `setup-go` step reads `go-version-file: go.mod`. `go mod tidy` removes a `toolchain` line that equals the `go` line: I checked this with Go 1.27.3 in a scratch module, where `toolchain go1.27.3` beside `go 1.27.3` was dropped. So it is ADR-0003's wording that needs correcting, which is D1's job.
   - **`govulncheck`** runs for `linux/amd64` and `windows/amd64` (`govulncheck.yml`). `linux/arm64` is a target in ADR-0003, but no workflow builds it and nothing checks it.
   - **The module proxy.** A release build should run with `GOPROXY=off`, so that it uses only modules already verified against `go.sum` (D3's review). Nothing sets this today.
   - **GitHub Actions** are pinned by tag (`actions/checkout@v4`, `actions/setup-go@v5`, `actions/setup-python@v5`, `actions/upload-artifact@v4`), not by commit SHA. Runners are named `ubuntu-latest` and `windows-latest` in `ci.yml`, `govulncheck.yml` and several dispatch workflows, so the runner image is not pinned either.
8. **The project's own licence.** `LICENSE.md` exists since D4-85: a proprietary notice, all rights reserved, with no licence granted beyond what it states, and material that names another source left to its owners. So the notices file of R-1 says of OTSEC itself only that it is under `LICENSE.md`'s terms, and carries that file beside the third-party texts. It must not suggest that the third-party licences cover OTSEC. No lawyer has read `LICENSE.md` (D4-85, "Limits").

## 6. How the inventory is kept true

The block between the two marker lines `inventory:begin` and `inventory:end` in §1.2 is the command's output, sorted per target and binary. It shows that this file and `go.sum` disagree when, at the repository root, the output of the §1 command differs from the block:

```sh
# the markers are anchored to whole lines, so this text's own mentions of them do not match
sed -n '/^<!-- inventory:begin -->$/,/^<!-- inventory:end -->$/p' docs/release.md | grep -v '^<!--' | grep -v '^```' > recorded.txt
# run the §1 loop into generated.txt
diff recorded.txt generated.txt   # empty when they agree
```

- The `h1:` field comes from `go.sum`, so a module bump, a changed hash, or a module that starts or stops being linked on any target shows as a diff.
- **A `replace` directive fails the check.** For a replaced module, `go list` prints the original path and version with an empty `h1:` field. I checked this with Go 1.27.3 in a scratch module that replaced a module with a local folder. So the §1 command also prints `=> <path> <version>` from `.Replace`, and any line containing `=>` fails. The recorded block has none.
- **The release binaries themselves.** The block is identical with `-tags otsec_testclock` (checked: all six target and binary lists are the same), and the diff never reads a binary. So the check also runs `go version -m` on each release binary, and fails unless:
  - the output has no `-tags` line (a tagged build prints `build -tags=otsec_testclock`, checked);
  - `CGO_ENABLED=0`;
  - `-trimpath=true`;
  - `vcs.modified=false`;
  - its `dep` lines equal the block's lines for that target and binary.
- **The toolchain:** `go version` must report the version in §1.1, and that version must equal `go.mod`'s `go` line.
- **Licences:** a licence change inside a bumped module does not show in the diff. The check recomputes the SHA-256 of every file named in §2 and compares it with the table.
- **Not covered by the check** (D3's review):
  - a build with a `go.work` workspace in effect, so the check must run with `GOWORK=off`;
  - a newly linked package from a module that is already listed;
  - `go:embed` assets;
  - third-party source copied into the repository instead of required as a module;
  - the hash of the Go toolchain archive itself.
- **What would gate it.** An edit to this file alone is Markdown-only, so it skips `ci.yml` and `govulncheck.yml` (CLAUDE.md, "Testing and merging"). A CI test of the check would catch a `go.sum` change that leaves this file stale. It would not run on a PR that edits only the block.
- D6 may turn this into a test. This record does not write it.

Every toolchain or dependency bump updates this file in the same PR, and D7 reads the new component's licence (D7's role file).

## 7. Rollback floors, and what rolls back together

Brief P4-4-CC deliverable 6, and P4-D7-2's two floors and release blocker (D4-88). Read on 2026-11-15 at `main` `2ef5639f`.

**Evidence class.** Each rule is `desk`: it is read from the approved texts and the decision log named in its row. Each test named passed in `main`'s push CI at the commit given, on both `go` jobs (`CI-Linux` and `CI-Windows`, with the run), with these exceptions:

- the C8 0.13 row also cites #699's PR-head run, and the first attempt of its push run's Linux job failed on another test;
- D6's lifted old-reader leg (§7.1, "Below C8 0.13's reader") cites #699's PR-head run as well as `main`'s push run;
- the C12 0.2 row's Linux job ran `go test` without `-v`, so only its package's result is in that log.

Those tests run in process, over fixtures written from the texts. No release has been built from any commit below, no node has been upgraded or rolled back, and no rollback has been run end to end.

**What a floor is.** A floor is the lowest build a node may be rolled back to once it has run a build that writes the form named. Any build below the floor is kept out of that node's rollback set. Each floor is a merge commit on `main`, and a release built from that commit or a later one carries it. The node and the collector are built from the same commit, so one release carries both. The sensor is a separate host with its own image (ADR-0009, option (b)), so a release of the node does not carry the sensor: the C13 rows pair two builds, with an order (§7.2).

### 7.1 The floors

| Floor | Merge commit on `main` | For a node that has run a build that writes | What the floor build carries | Tests passed at that commit |
| --- | --- | --- | --- | --- |
| **C12 0.2** (D4-61) | `f1f48ce6f8b6b7a4f1766ca3e5a8e317c9991454` (#509) | `otsec.finding/0.2`, from `a37a5e8c` (#511) | The node's refusal, per asset, of an `otsec.finding/` minor that `finding.Known` does not name. **Corrected** (D6's B1 on #704): #615 named `3c6b8a7b` (#507), which only adds `finding.Known`. At that commit no product code in `platform/` calls it, so the node's fold still skips a stored 0.2 finding silently, which D4-61 bars | Push run [42269302811](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42269302811): `TestFindingsRefuseAnUnknownMinor` passed on `go (windows-latest)`. `go (ubuntu-latest)` ran without `-v`, and `platform/node` was `ok` |
| **C13 0.2: CH-35's bridge** (D4-87; D4-103 ruling 2.1) | `26dce26e2d4f755b1e595a1699c464bb9fd4de59` (#682, deliverable 1) | `otsec.netcheckpoint/0.2`, from `26545062` | CH-35's bridge items 1 to 5, and D4-102 item 5 (d) in `alertsAfter`: skip, count and alarm | Run [43707598076](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43707598076), both `go` jobs: `TestDetectorBridgeLaterCheckpoint` (items 1 and 2, R-4), `TestDetectorBridgeLaterRecords`, `TestBridgeAggregateKeys` and `TestBridgeUnknownDegraded` (items 3 and 4), `TestHoldTieKeepsLaterMinor` (item 5), `TestDetectorAlertUnreadableSkipped` and `TestDetectorAlertUnreadableBounds` ((d), N-13's leg (2)) |
| **C13 0.3** (C13 0.3 §1.2; D4-105 item 1.2) | `2654506240f86f4843f62aed8a01b766dbda49c6` (#687, deliverable 2) | `otsec.netcheckpoint/0.3`, from `65ad611b` (#689) | Bridge items 1, 2 and 5 for a later minor, (d), and the 0.2 stamp on an alert whose coverage carries a 0.2 field | Run [43711955481](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711955481), both `go` jobs: `TestDetectorLaterCheckpoint` (R-4 moved to 0.3, N-13's leg (1)), `TestHoldTieKeepsLaterMinor` (a 0.3 body), `TestDetectorAlertUnreadableSkipped`, `TestDetectorAlertUnreadableBounds`; the 0.2 alert stamp: `TestWindowAlertSchema` (`contracts/netobs`) and `TestDetectorAlerts02Observations` (`modules/detection/netdetect`) |
| **C8 0.13's reader** (C8-1; D4-88; D4-108 item 1) | `2ef5639f10b5e6610b901626d86a917e3f127373` (#699, deliverable 5) | Any 0.13 audit record: `sensor.enrolled`, `sensor.revoked`, `sensor.link_refused`, or a `collector.request` with a sensor target. No build writes one yet: the node's writers are owed to the dialer-and-enrolment brief | The 0.13 reader in the scheduler's fold | `TestC81SensorRecordsFoldHoldsNoRun`, with its control (the 0.12 reader holds every run). **PR-head evidence:** #699's run [43732127564](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43732127564) (`ci`, `pull_request`, at `2f301d4b`), where it passed in both `go` jobs. **`main`'s push run** [43737404596](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43737404596) at `2ef5639f`: it passed in both `go` jobs, and `go (windows-latest)` succeeded. The first attempt of `go (ubuntu-latest)` failed on `TestLinkKeyAnotherFaultAlarms` (`platform/node`), a test #699 does not touch. D1 triaged it as a test defect: the test read a half-written file. D5's fix is #705. The rerun (attempt 2) of `go (ubuntu-latest)` succeeded, with both `TestC81SensorRecordsFoldHoldsNoRun` and `TestLinkKeyAnotherFaultAlarms` passing |

What a rollback below each floor costs, and what each floor still costs:

- **Below the bridge,** a node that has written a 0.2 checkpoint restarts its detector silently: no `network-detector-not-restored`, the retained observations' alerts stored a second time, and the 0.2 document never removed, up to 1,354,752 bytes in the configuration class (CH-35, "The rollback").
- **Below the bridge, from 0.3,** a node that has written a 0.3 checkpoint gets either a restore failed whole by one `own-session-mismatch` alert or the same silent restart (C13 0.3 §1.2, "The rollback floor"). Those costs come from builds without bridge items 1 and 2 and (d), which every build from `26dce26e` carries (§7.1's bridge row). Between `26dce26e` and `26545062`, no approved text states the cost of a rollback from 0.3. The floor for a 0.3 node stays `26545062`, as C13 0.3 §1.2 and D4-103 ruling 2.1 set it.
- **At the bridge or the 0.3 floor,** the stated limits stay:
  - the retained observations' alerts are raised again, with the alarm;
  - while rolled back from 0.3, no tied flow is judged by CH-51, so HR-24 is again hidden whole;
  - `hold` matches by position, so a skipped alert shifts the comparisons after it (D4-105 item 5; D4 owes the options).
- **Below C8 0.13's reader,** a 0.12 build refuses a `sensor.*` record and a `collector.request` with a sensor target. The scheduler takes such a record as a bad record and holds every run (`asset-suspensions-unknown`), so SER collection stops on that node, not only the sensor (C8-1). D6's old-reader leg, `TestCCD0C81OldReaderRefuses`, tests a different form in each run:
  - at `36fabc3a` (#683), run [43649202635](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43649202635), both `go` jobs, `main`'s 0.12 reader refused the narrowed records of D4-104 item 2 (a);
  - in #699, D6 lifted the leg to full 0.13 records. At #699's head `2f301d4b`, run [43732127564](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43732127564) (PR-head evidence), both `go` jobs, the 0.13 reader read each full record and refused the same bytes stamped 0.12. The same test passed at `2ef5639f` in `main`'s push run [43737404596](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43737404596): both `go` jobs, and the Linux rerun. The 0.12 reader's refusal of the full records ran only at `8e96c821`, as `desk` (the test file's own note).
- **Readers before writers** (C8-1): the first build that writes a 0.13 record ships no earlier than a release that carries `2ef5639f`.
- **No floor for the key register** (NK-6): its schema does not change.

### 7.2 What rolls back with the floors

- **The configuration.** The node decodes its configuration strictly (`DisallowUnknownFields`, `platform/node/config.go`), so a rollback restores the configuration shape the floor build accepts (CH-35; `docs/phase4/D5-sensor-node.md` §1.15 item 4; NK-6).
  - At all three C13 and C8 floors, and on `main` at `2ef5639f`, `NetworkSensor` (`platform/node/netsensor.go`) is the same. Its fields are `sensor_id`, `evidence_class`, `outage_hours`, `alert_retention_days`, `node_addresses`, `node_macs`, `node_vlans` and `link_key_ref`.
  - A build from before `805e8567` (#685) refuses `link_key_ref`. A floor build refuses the third part's `sensors` list, which no merged build accepts yet.
  - Outside the tests, no configuration carries a `network_sensor` section while F-027's gate holds (D4-88, D4-96). Under that rule the shape that rolls back is a configuration with no `network_sensor` section.
- **The sensor and the node** (C13 0.3 §1.1). They are two builds on two hosts. **Upgrade the node first, then the sensor. Roll back the sensor first, then the node.** In that order the link stays up, and a 0.2 sensor's records are stored at 0.2 and judged by the base rules only (`network-own-session-unjudged` is raised meanwhile). In the wrong order the link is down (`hello`) until the node catches up, and the records wait in the sensor's buffer (CH-20). Nothing in 0.3 bounds how long a 0.2 sensor runs behind a 0.3 node. The four sensor programs are built, pinned and rolled back together in one image (`docs/phase4/D3-sensor-link.md`, AP-31 (1)). No sensor build exists yet, so this pair has no sensor commit.
- **The collector's configuration below `2ef5639f`.** From `2ef5639f`, `node.sensor_enrol` and `node.sensor_revoke` are admin kinds (`adminKinds`, `contracts/authz/adminsig.go`). A collector built below `2ef5639f` refuses a configuration whose `admin_keys` list names either kind (`ValidateAdminKinds`, called from `cmd/otsec-collector/config.go`), and does not start. So a rollback of the collector below `2ef5639f` restores a key list without those two kinds.
- **C2 0.10** (`410a04d5`, #684) rolls back with C13 0.3 (`65ad611b`) and with the node build that reads C2 0.10's Telnet facts (C2 0.10 §4).
  - That reader is HR-24's stage 3, which is not merged. At `2ef5639f`, `git grep` finds no reader of `TelnetFacts` in `platform/`, `modules/detection/` or `cmd/` outside `_test.go` files.
  - The cost of each split is fail-closed noise, and no stored data is lost. A collector rolled back to 0.9 under a 0.10 node gives a `comparison M6b reason no-profile` alert for each tied Telnet flow, once that reader exists. A node rolled back to 0.9 ignores the fields.
  - `410a04d5`'s push runs passed: `ci` [43711989055](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711989055), `a6-c2-old-reader` [43711989122](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711989122), in which the last 0.9 `DecodeResult` read every 0.10 golden, and `a6-c2-netns` [43711989091](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711989091).
- **C4 0.4** (stamped by every producer from `26545062`) has no floor, on one condition (C4 0.4 §3; `docs/phase4/D5-sensor-node.md` §1.15 item 7).
  - **Receivers first.** Every forwarded event's `ev` becomes `otsec.event/0.4` at once. Upstream receivers are upgraded before the nodes that write to them (`contracts/syslog/doc.go`, "Versions"). A conforming 0.3 receiver reads 0.4. A receiver that refuses an unknown minor reports every forwarded event as `unsupported version` until it is upgraded.
  - **The condition: no pending C4 event outlives the process that built it.** A 0.3 build reads every stored 0.4 event, and refuses only a pending one. So a rollback from 0.4 code loses nothing while this condition holds. It holds on `main` by D5's reading (`desk`). Its node test, `TestHeldPoolEventBuiltAtWrite` (E4-7's node leg), is owed to the C13 0.2 intake brief. Any change that holds a built event across a restart, or a second writer of pending events into a node's store, gives C4 0.4 a floor, and this record must name it before that change merges.
  - **Tests:** `TestCCD0E47StoredEvents` passed at `36fabc3a`, run [43649202635](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43649202635): the 0.3 `Decode` read a stored 0.4 SER, Syslog, node health and network-observation event. `TestEvent04Commits` passed at `26545062`, run [43711955481](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711955481): the store refuses a pending event of a later minor.
- **Rules that will add rows.** Each states its floor before D1 approves the later minor:
  - a later C13 minor that adds a `coverage.degraded` value states what a bridge-floor node writes for it (D4-104 item 1.2);
  - a later C4 minor that adds a capture-loss counter states its reader floor (D4-105 item 1.4, reading 5).

### 7.3 The order of the first release

CH-35 and `docs/phase4/D5-sensor-node.md` §1.15 item 1 say that the bridge build is released on its own, before any build that writes 0.2, and that the 0.2 writer ships no earlier than the release after it. **D1 ruled that this is a rule about rollback sets** (D1's comment 6897989367 on #704). Its purpose is that a node never rolls back below a reader of what it has written (D4-61, CH-35).

- **No OTSEC build has been released.** A node first installed from a release at or above every floor in §7.1 has no earlier release to roll back to. So the first release may carry the 0.2 and 0.3 writers, and nothing needs to ship before them.
- **The condition.** This holds only while no build below a floor has been released to any site. **Released** means installed at any site, by any means. The record of the first release states that no earlier release exists.
- **The check.** Each release's record names the commit it was built from, with the output of `git merge-base --is-ancestor <floor> <release commit>` for each floor in §7.1. Exit status 0 means the release carries that floor. The record keeps any release whose check fails for a floor out of the rollback set of a node that has run that floor's writer.
- **Nothing on a node enforces the floors yet.** AP-10's anti-rollback floor for the update package is not designed (§5 item 4). Until it is, a floor holds only by this record and by whoever installs the release.
- **When it is designed,** the signed anti-rollback floor a node holds is at or above every §7.1 floor that applies to a build that node has run.
- **If a build below a floor ever ships,** the rule applies to that floor as written: a release of the floor build goes first, and the writer ships no earlier than the release after it.

### 7.4 Release blocker

**No release ships while F-027's gate holds** (D4-88, D4-96). F1 to F11 must be closed, and every test owed by a later brief must have passed. F-027 in `docs/verification.md` is the record of its state. This record does not restate it.

## What this record does not establish

- It is not legal advice, and it does not say that any duty is met.
- Per-file licence mapping inside `modernc.org/libc` and `modernc.org/memory` was not done. The whole notice files are listed instead.
- Licences of the 15 unlinked modules (§1.3) were not read.
- For option (a): the Npcap OEM price and terms, Npcap's third-party PDF, Suricata's bundled components, and which of Zeek's third-party parts reach a Windows build are all `unknown`.
- Fetching the inventory downloaded `github.com/google/uuid` and the 15 unlinked modules into the module cache on the machine that ran it. `go mod verify` passed afterwards.
