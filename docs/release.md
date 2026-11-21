# Release record

Owner: D7 (brief P4-D7-1, in PR #614, not yet on `main`). Reviewers: D3 (the update path and the supply-chain rows) and D6 (that every claim can be checked).

This file records what the two binaries contain and under which licences, and what a release still lacks. It is an inventory, not a release. Nothing here is compliant, certified or release-ready. No release of OTSEC has ever been built for distribution or shipped to a node.

**Evidence class: `desk`.** Every row of §1 to §6 was read on 2026-11-11 from `main` at `b383a242` (#611), from the Go toolchain's own output (Go 1.27.3, `windows/amd64` host), from the licence files in the Go module cache and the Go distribution, and, for the third-party programs, from upstream files downloaded on the same day. No test was run for those sections. §7 was read on 2026-11-15, at the commits it names, and states its own evidence. §8 was read on 2026-11-16, and states its own evidence.

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

Brief P4-4-CC deliverable 6, and P4-D7-2's two floors and release blocker (D4-88). Read on 2026-11-15 at `main` `2ef5639f`. The C4 0.6 rows (brief P4-D7-C406, D4-121 item 3.4) were read on 2026-11-21 at `main` `2326f34f`, against `docs/phase4/D4-c4-0.6-proposal.md` §4, §5, §6 "Order" and §7, approved at `5e7f0487` (#768, D4-121 item 1.1).

**Evidence class.** Each rule is `desk`: it is read from the approved texts and the decision log named in its row. Each test named passed in `main`'s push CI at the commit given, on both `go` jobs (`CI-Linux` and `CI-Windows`, with the run), with these exceptions:

- the C8 0.13 row also cites #699's PR-head run, and the first attempt of its push run's Linux job failed on another test;
- D6's lifted old-reader leg (§7.1, "Below C8 0.13's reader") cites #699's PR-head run as well as `main`'s push run;
- the C12 0.2 row's Linux job ran `go test` without `-v`, so only its package's result is in that log;
- the C13 §15 row's below-floor reading is `desk`: the refusal is read from `main`'s code at `2dde13b6` and at `64c88207`. The forward read is read from the code at `26545062` (netobs's own minor 0.2) and at `65ad611b` (where it becomes 0.3), and from the probes on #760 and #762 cited in it. Its named tests passed in `main`'s push run [44474826246](https://github.com/alialyami90/OTSEC-Proj/actions/runs/44474826246);
- the C4 0.6 row's below-floor reading is `desk`: what a build below `2326f34f` does with a later-minor record is read from the C4 and C13 forward-read notes (option (b) in each) and from `git grep` at `554f9d12`, #780's first parent, where neither `ErrLaterMinor` nor `CheckEventMinor` exists. D6's old-reader leg E6-17 is owed and is not cited.

Those tests run in process, over fixtures written from the texts. No release has been built from any commit below, no node has been upgraded or rolled back, and no rollback has been run end to end.

**What a floor is.** A floor is the lowest build a node may be rolled back to once it has run a build that writes the form named. Any build below the floor is kept out of that node's rollback set. Each floor is a merge commit on `main`, and a release built from that commit or a later one carries it. The node and the collector are built from the same commit, so one release carries both. The sensor is a separate host with its own image (ADR-0009, option (b)), so a release of the node does not carry the sensor: the C13 rows pair two builds, with an order (§7.2).

### 7.1 The floors

| Floor | Merge commit on `main` | For a node that has run a build that writes | What the floor build carries | Tests passed at that commit |
| --- | --- | --- | --- | --- |
| **C12 0.2** (D4-61) | `f1f48ce6f8b6b7a4f1766ca3e5a8e317c9991454` (#509) | `otsec.finding/0.2`, from `a37a5e8c` (#511) | The node's refusal, per asset, of an `otsec.finding/` minor that `finding.Known` does not name. **Corrected** (D6's B1 on #704): #615 named `3c6b8a7b` (#507), which only adds `finding.Known`. At that commit no product code in `platform/` calls it, so the node's fold still skips a stored 0.2 finding silently, which D4-61 bars | Push run [42269302811](https://github.com/alialyami90/OTSEC-Proj/actions/runs/42269302811): `TestFindingsRefuseAnUnknownMinor` passed on `go (windows-latest)`. `go (ubuntu-latest)` ran without `-v`, and `platform/node` was `ok` |
| **C13 0.2: CH-35's bridge** (D4-87; D4-103 ruling 2.1) | `26dce26e2d4f755b1e595a1699c464bb9fd4de59` (#682, deliverable 1) | `otsec.netcheckpoint/0.2`, from `26545062` | CH-35's bridge items 1 to 5, and D4-102 item 5 (d) in `alertsAfter`: skip, count and alarm | Run [43707598076](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43707598076), both `go` jobs: `TestDetectorBridgeLaterCheckpoint` (items 1 and 2, R-4), `TestDetectorBridgeLaterRecords`, `TestBridgeAggregateKeys` and `TestBridgeUnknownDegraded` (items 3 and 4), `TestHoldTieKeepsLaterMinor` (item 5), `TestDetectorAlertUnreadableSkipped` and `TestDetectorAlertUnreadableBounds` ((d), N-13's leg (2)) |
| **C13 0.3** (C13 0.3 §1.2; D4-105 item 1.2) | `2654506240f86f4843f62aed8a01b766dbda49c6` (#687, deliverable 2) | `otsec.netcheckpoint/0.3`, from `65ad611b` (#689) | Bridge items 1, 2 and 5 for a later minor, (d), and the 0.2 stamp on an alert whose coverage carries a 0.2 field | Run [43711955481](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43711955481), both `go` jobs: `TestDetectorLaterCheckpoint` (R-4 moved to 0.3, N-13's leg (1)), `TestHoldTieKeepsLaterMinor` (a 0.3 body), `TestDetectorAlertUnreadableSkipped`, `TestDetectorAlertUnreadableBounds`; the 0.2 alert stamp: `TestWindowAlertSchema` (`contracts/netobs`) and `TestDetectorAlerts02Observations` (`modules/detection/netdetect`) |
| **C8 0.13's reader** (C8-1; D4-88; D4-108 item 1) | `2ef5639f10b5e6610b901626d86a917e3f127373` (#699, deliverable 5) | Any 0.13 audit record: `sensor.enrolled`, `sensor.revoked`, `sensor.link_refused`, or a `collector.request` with a sensor target. No build writes one yet: the node's writers are owed to the dialer-and-enrolment brief | The 0.13 reader in the scheduler's fold | `TestC81SensorRecordsFoldHoldsNoRun`, with its control (the 0.12 reader holds every run). **PR-head evidence:** #699's run [43732127564](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43732127564) (`ci`, `pull_request`, at `2f301d4b`), where it passed in both `go` jobs. **`main`'s push run** [43737404596](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43737404596) at `2ef5639f`: it passed in both `go` jobs, and `go (windows-latest)` succeeded. The first attempt of `go (ubuntu-latest)` failed on `TestLinkKeyAnotherFaultAlarms` (`platform/node`), a test #699 does not touch. D1 triaged it as a test defect: the test read a half-written file. D5's fix is #705. The rerun (attempt 2) of `go (ubuntu-latest)` succeeded, with both `TestC81SensorRecordsFoldHoldsNoRun` and `TestLinkKeyAnotherFaultAlarms` passing |
| **C13 0.2 and 0.3, §15's keys in place** (D4-117 item 3.8; C13 0.3 §15.8; D4-119 items 2.1 and 7.1; D1's ruling 7001264083 on #760, to be recorded in D4-120) | `64c88207d8b64ae1b7b7e8a1fdd27877ad94eefc` (#760, P4-4-C13-ABS; head `e510baa6`, first parent `2dde13b6`) | **Every stored DNP3 function and every SNMPv3 record from the first sensor build** (D3's F2 on #762): on the 0.2 and 0.3 channels `objects_unread` is required on every DNP3 `function`, and `usm_parsed` on every SNMPv3 record. The tokens are `sa: unknown`, `objects_unread`, `dnp3_sa_unknown`, `usm_parsed`, `inner_vlans`, and, in a 0.2 or 0.3 record, an `engine_id` of `""` or of 1 to 4 octets. A 0.1 record keeps its 5-to-32-octet form (`engineIDForm01`; D1's ruling item 5, done in `e510baa6`). **First build that accepts each:** `64c88207`. Six tokens are accepted on the channel and through `DecodeStored`. `dnp3_sa_unknown` is accepted through `DecodeStored` only, and by the link's `ValidateStored` before it stores, because the channel refuses `node` (`validateChannel`: "a sensor's record never carries node"). **First build that writes each:** the same commit for `dnp3_sa_unknown`, which the node sets on a DNP3 `NoSAClasses` function with `sa: unknown` (`nodeObject`, `platform/sensorlink/link.go`); every other token is written by the sensor, not yet built. Outside the tests no build stores any of them: nothing in `cmd/` calls `sensorlink` (§15.8, "Why in place") | `DecodeStored` that reads every token, and refuses nothing it accepted at `2dde13b6` (§15.8, "What changes in the stored path") | `main`'s push run [44474826246](https://github.com/alialyami90/OTSEC-Proj/actions/runs/44474826246) at `64c88207`, both `go` jobs: `TestStoredAcceptsToday15`, `TestKeySweep15Stored`, `TestSA15`, `TestSNMPv315`, `TestVLAN15`, `TestNodeObjectSA15` and `TestEngineIDStored15` passed. `TestEngineIDStored15` decodes a stored 0.2 and 0.3 `engine_id` of `""`, 1 and 4 octets, and refuses them at 0.1 (D6's finding 4 on #762). **Owed before item 4's gate** (D1's ruling item 7): D6's old-reader leg (§15.9, D6's point 7), in a new `a6-*.yml`, at two reader commits: `2dde13b6`, #760's first parent, where each token is refused, and `26545062`, where the forward read below is asserted as this row's stated behaviour, not as a safety pass. It tests `DecodeStored` at those two commits only. It does not test `observeTo`, the channel refusal, or what the detector does with a forward-read record, which stay `desk` |
| **C13 and C4 (b): a later minor refused at judging** (D4-120 items 2.2 and 2.6; C4 0.6 §3 and §5, approved in D4-121 item 1.1; D4-121 item 2.6) | `2326f34ff47b60854b286f760fd39c7f5177a827` (#780, C4 0.6 step 3; first parent `554f9d12`). Both refusals land in this one merge, so this is one row (C4 note §2 (b), "One row or two"): at `554f9d12`, `git grep` finds neither `ErrLaterMinor` nor `CheckEventMinor` | **Either** a `network-observation` or `collection.run` event stamped above the C4 minor current at this commit (`otsec.event/0.6`, unless another C4 minor lands first), **or** a stored observation whose body is stamped above C13's minor at this commit (`otsec.netobs/0.3`, unless a C13 minor lands first). No build writes either yet: `event.Identifier` is 0.6 and netobs's `self` is 0.3 at `2326f34f`. The row binds a node once a build above those minors has written such a record on it. **Why 0.4, 0.5 and 0.6 sit below the trigger:** none changed the `network-observation` or `collection.run` envelope. That reading is `desk` for 0.4 and 0.5 (C4 note §1.4). For 0.6, an added envelope key is tested by E6-4 (c)'s head leg (#778), and an added value of an open set stays `desk` (C4 0.6 §1) | `ErrLaterMinor` in `validateStored` and in `CheckEventMinor` (`contracts/netobs`); their calls in `ObservationFromEvent`, `observationOf` (`platform/node/netdetector.go`) and `runSessionOf` (`platform/node/netintake.go`); `network-observation-refused` with `detector.observation-refused`'s counts (from #777 and #779); `network-session-refused` with the in-memory `runs_session_missing` | `main`'s push run [44888139645](https://github.com/alialyami90/OTSEC-Proj/actions/runs/44888139645) at `2326f34f`, both `go` jobs: E6-6 to E6-12 (`TestE6x6LaterC4Observation`, `TestE6x7CheckHelper`, `TestE6x7GuardMinorsApart`, `TestE6x8ValidatePath`, `TestE6x9Unreadable`, `TestE6x10FieldSplit`, `TestE6x11Placement`, `TestE6x12LaterC13Stored`; `contracts/netobs`), D6's E6-6 (`TestC4v06E66LaterC4Observation`; `tests/contract`), E6-13 (`TestObservationRefusedLaterMinor`), E6-14 (`TestRunSessionOfLaterOtherType`, `TestRunSessionOfOrder`, `TestRunSessionRefusedSecondDrive`) and E6-15 (`TestHeldRecordLaterMinor`; all three `platform/node`). **Owed before item 4's gate:** D6's R3 leg, E6-17. It runs in the C13 old-reader workflow that D4-120 item 3.4 adds, which does not exist at this commit, so it is not cited from the `go` jobs here |

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
- **Below §15's floor** (`64c88207`; D4-119 items 2.1 and 7.1; D1's ruling 7001264083 on #760), a build must not be the rollback target of a node that has stored a record in the row's scope: a DNP3 function or SNMPv3 record from a sensor, or any record carrying a §15.8 token. The builds below the floor read such a record in one of two ways (`desk`, read from code):
  - **From `65ad611b` (#689) to `2dde13b6`, #760's first parent, the record is refused.** There netobs's own minor is 0.3, so `DecodeStored` decodes a 0.2 or 0.3 record strictly. `objects_unread`, `dnp3_sa_unknown`, `usm_parsed` and `inner_vlans` are unknown keys (`decode`). `unknown` is not in the closed `sa` set, and `engineIDForm` takes 5 to 32 octets only (`form`). The replay (`observeTo`, `platform/node/netdetector.go`) turns the refused record into `nil`, counts it under `Refused` (`observations_refused`) and judges nothing on it (§15.8 condition (b)). So every retained DNP3 function, writes and controls included, and every SNMPv3 record goes unjudged (D3's F2 on #762), and only that count shows it.
  - **From `26545062` (#687) to `65ad611b`'s parent, the record is read forward and judged** (D6's finding 1 on #762; D4's probe in 7001201557, `desk`). These are seven builds on `main`'s first-parent line. There netobs's own minor is 0.2, so `DecodeStored` reads a 0.3 record with `strictjson.Forward`. `objects_unread`, `inner_vlans` and `usm_parsed: true` are dropped without a word. The record is then judged as if its objects had been read to the end and it had no inner tags, which is the fail-open that §15.3 and §15.4 exist to prevent. A 0.2 record with a token is still refused, and so are `sa: unknown`, the engine ID forms and `usm_parsed: false`. What the forward read loses (D4's 7001201557, D3's 7001225871; read from code):
    - the class survives, because the detector reads `node.function_class`, which #760's node set at intake, so `unauthorized-write` still fires;
    - `new-function` judges an unread record by the headers read so far, so a write whose objects were not read to the end can go unflagged;
    - the inner-VID case of `node-address-spoofed` is lost;
    - the learner learns the unread record's objects, so a baseline approved from that draft during the rollback keeps them after it. A later build restores a learner checkpoint written at `26545062` with what it learned, and nothing in it says which records were read forward, so this loss would outlast the rollback. No build below #760 runs the network learner, so no such draft exists (D4's answer 7001396105 on #760 to D6's question 5, `desk`). A learner checkpoint carries no stamp of the build that wrote it, which belongs with the open item on later minors below.
    - `26545062` is C13 0.3's floor in the row above. For a node that has stored a record in this row's scope, `64c88207` is the floor instead, and these seven builds are out of its rollback set.
  - **The loss outlasts the rollback** (D3's F1 on #762). This is a risk tied to AP-10. `Detector.Observe` takes a refused record's seq into `Through`, and the next checkpoint stores it. So a node upgraded again past the floor restores past those records and never judges them. `observations_refused` is a count in the running process's status, with no alarm and no stored record, so after a restart nothing shows which records went unjudged. **Open item, owner D5, options first, before P4-4-DE** (D1's ruling item 4).
    - **From `24296a1a` (#779) the loss is counted, not recovered.** D5's options were approved (D4-120 item 2.5) and coded in #777 (`50f1e56a`: the refusal classifier and `network-observation-refused`) and #779 (`24296a1a`: the `detector.observation-refused` counts event and its lasting mark). A refused record is still not judged again (C4 note §2 (b), "The loss outlasts the rollback"). The paragraph above stays true of every build below `50f1e56a`.
    - **The forced checkpoint's restart loss** (D4-121 item 3.3; C4 0.6 §4 "The forced checkpoint" and §7). When the counts event owed for the counts or for the `unsure` range is held past `RefusedCountsWait` (one hour, `platform/node/netrefused.go` at `2326f34f`), by its write's failure, the budget, the ceiling, or a replay of T + 1 to U slower than that wait, the checkpoint is stored without it and `network-refused-counts-unwritten` is raised, naming the range and the cause (`replay below <U>` for the slow replay). A restart before the event is written then shows the counts as exact, or as not exact only above the forced checkpoint, and that alarm in the OS log is the only record of the range. It is bounded and alarmed, the same class as D5's stated limit for counts (D5's note §2.4 and §8). It is a residual of this item, not closed by it.
  - **The channel.** A sensor that writes a token to a node below the floor has the record refused at the channel, and each refusal counts under `sensor-record-refused` (§15.8, "Why in place"). §7.2's order does not avoid a refusal here: a #760 node refuses an old-form record as `missing`. No sensor build predates #760, so no old-form sensor exists to roll back to.
  - **Nothing in the row's scope is stored yet.** No sensor is wired, so no node holds such a record today. The floor binds a node from its first stored DNP3 function or SNMPv3 record from a sensor.
  - **Two forms under one name** (§15.8, D3): "0.2" and "0.3" each name the form before #760 and the form after it, and a `hello` cannot tell them apart. This is harmless only while no producer of the old form exists. From the first sensor build (P4-4-DE), any change to a key being required or optional, or to a closed set, is a new minor (§15.8 condition (a)).
  - **A new minor is read forward too.** #760's `DecodeStored` reads a later minor forward and drops the keys it does not know (D6's 7001254947, `desk`). So the next C13 minor that adds such a key repeats the forward read above in released builds. **Open item, owner D4, options before the next C13 minor and before P4-4-DE** (D1's ruling item 3). Until it is settled, each later C13 minor carries its own row here, stating what a forward-reading build drops. **Settled for the stored observation** by option (b) (D4-120 item 2.2), coded at `2326f34f`: from that build a stored observation of a later C13 minor is refused at judging, not read forward, and the builds below it are bounded by §7.1's C4 0.6 row.
  - **How this floor is held today: by this record only.** No OTSEC build has been released, §7.4 blocks every release, and §7.3's condition keeps every build below a floor out of the first release. No build below #760 was ever released. No node enforces the floor. A build below the floor that is installed by hand is a release under §7.3 ("installed at any site, by any means"), and it is outside the rollback set. But nothing on a node stops it, and AP-10, once built, stops it only through the update path (§7.4). AP-10's signed anti-rollback floor must exist before the first release ships (§7.4).
- **Below C4 0.6's row** (`2326f34f`; C4 0.6 §5), a build reads a later-minor record forward: a `network-observation` or `collection.run` event of a later C4 minor through `event.Decode`, and a stored observation of a later C13 minor through `DecodeStored`, which drops the keys it does not know and judges the rest (C13 and C4 forward-read notes, `desk`). That is the fail-open the row exists to prevent, so such a build must not be the rollback target of a node that has stored a record in the row's scope.
- **At or above it, a rollback across a later minor still costs records** (C4 0.6 §5, "Its cost, stated in the row, per trigger"; D7's N1 on #765). Records written by the later build are refused and alarmed while rolled back, and never judged afterwards, because `Through` and the health position pass them (above, "The loss outlasts the rollback"):
  - **under the C4 trigger,** the replay window's `network-observation` events and `collection.run` sessions. Held records are outside it, because `Link.record` stamps the releasing build's C4 minor;
  - **under the C13 trigger,** the replay window's stored observations whose body is of a later C13 minor, held records included: such a held record is committed as held, refused at judging, and its seq passes `Through` (E6-15).
  - A refused `collection.run` is counted in memory only (`runs_session_missing`) and alarmed once per node process run (`network-session-refused`). A durable count is D5's open item (D4-121 item 3.1).
  - A later minor that changes a known key's JSON type, or a later C4 `kind`, is refused and counted as `malformed`, not `later-minor`, so its alarm lacks the "move this node forward" remedy. It still fails closed (C4 0.6 §7).
- **AP-10's floor is at least `2326f34f`** (C4 0.6 §5; both forward-read notes). AP-10 refuses an older build only through the update path (§7.4). A hand install below `2326f34f` bypasses it, and is a release outside the rollback set (§7.3). §7.3's per-floor `merge-base --is-ancestor` check needs no change. Like the §15 row, this floor is held today by this record only: no build has been released.
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
- **C4 0.6** (`otsec.event/0.6`, stamped by every producer from `9a6df521`, #772; approved in D4-121 item 1.1) has no floor of its own (C4 0.6 §4, §5 "0.6 itself adds no floor"). Its code landed in four merges: #772 (`9a6df521`, the two `detector.*` types, the stamp and `netobs.SelfIdentifier()`), #777 (`50f1e56a`, the refusal classifier and `network-observation-refused`), #779 (`24296a1a`, the counts event and its lasting mark) and #780 (`2326f34f`, both refusals, §7.1's C4 0.6 row). Its upgrade notes:
  - **Receivers first** (C6, `contracts/syslog/doc.go`, "Versions"). Every forwarded event's `ev` becomes `otsec.event/0.6` at once, as with 0.4 and 0.5. `Render` renders the new details as `hd` parameters, and C6 does not change.
  - **No reader floor, on the C4 0.4 condition.** Every earlier reader accepts every 0.6 event and no earlier build acts on a `detector.*` event (C4 0.6 §4). The condition holds if the writer rule of C4 0.6 §2.3 holds: the counts and baseline events are kept as counts or alarm state and built when written, so no pending C4 event outlives the process that built it. An event owed for the counts or the `unsure` range is not kept across a restart: the next start derives it again from U > T, outside the forced checkpoint (§7.1, "The forced checkpoint's restart loss"). Any change that keeps a built event across a restart gives C4 0.6 a floor, and this record must name it before that change merges.
  - **The first start of a build with the counts writer** (`24296a1a` or later) finds no `detector.observation-refused` event, so the counts begin at that start (`since` = now, `through` = 0; `restoreRefused` in `platform/node/netrefused.go`: "none, or one this build cannot read: begin again"). Refusals counted by an earlier build, in its in-memory `observations_refused`, are in no count.
  - **When the start marks the counts as not exact.** Only when the newest counts event's `through` (U) is above the restored checkpoint's `Through` (T), over T + 1 to U, after a crash or a failed checkpoint (D4-121 item 2.1). The writer's C4 and C13 minors only name the cause in the status text. **An ordinary upgrade after a clean stop is not marked** (U ≤ T). An upgrade after a crash with U > T is marked, as "a build change" when a minor differs and "a crash or a build change" when they are equal.
  - **A start that sets or widens the range owes a counts event**, and the checkpoint waits for it: no checkpoint between T and U is stored, so a crash or a stop before the write leaves the full range for the next start (C4 0.6 §4 "Set" and "Two ranges"). The one exception is the forced checkpoint (§7.1).
  - **The mark clears only when the counts begin again** under a new `since`: the newest counts event not found within the scan, or pruned, or a checkpoint that did not restore. A counts write, a restart, an upgrade or a clean stop does not clear it. The carried range is unchanged, except as widened under "Two ranges", until `since` begins again (C4 0.6 §4 "Stop").
  - **A rollback below 0.6 and a move forward again is not marked** (0.6, then a build below 0.6, then 0.6 or later; D4-121 item 3.2). A build below 0.6 writes no counts event, so the start shows the counts as exact, or as not exact only for a range it carried before, and the rolled-back build's refusals are counted nowhere. No trace of them remains: `observations_refused` is in memory and in the status file, which the next build overwrites, and nothing about a refusal reaches the OS log (C4 0.6 §4). Such a rollback can only be a hand install. AP-10 refuses an older build through the update path only (§7.4), and a hand install is a release outside the rollback set (§7.3). The rolled-back build is also below §7.1's C4 0.6 row.
  - **The forced checkpoint's restart loss** is a residual of §7.1's "The loss outlasts the rollback", stated there.
  - **Tests.** E6-4 (a), the earlier readers in the 0.5 code: `TestC4v06E64aEarlierReaders`, `TestC4v06E64aStrictLeg` and `TestC4v06E64aFillPins` (`tests/contract`) passed in both `go` jobs of `main`'s push run [44857882549](https://github.com/alialyami90/OTSEC-Proj/actions/runs/44857882549) at `e6152113` (#771, before #772). E6-16 and E6-18 (`platform/node/netrefusedcounts_test.go`), among them `TestRefusedCountsBuiltAtWrite`, `TestRefusedCountsCrashAfterEvent`, `TestRefusedCountsMarkHeldBelowU`, `TestRefusedCountsMarkWidened`, `TestRefusedCountsBeginAgain`, `TestRefusedCountsForcedMarkOnly` and `TestRefusedCountsBothRanges`, in `main`'s push run [44888139645](https://github.com/alialyami90/OTSEC-Proj/actions/runs/44888139645) at `2326f34f`, both `go` jobs.
- **The C4 split: what a build at or above `2326f34f` refuses at judging, and what it still reads forward** (C4 0.6 §3.3; D4-120 item 2.6). The C4 0.4 entry's forward read and C6's receiver rule depend on the second column.

  | Refused at judging when of a later minor (§7.1's C4 0.6 row) | Still read forward, as below the row |
  | --- | --- |
  | A `network-observation` event of a later C4 minor (`ObservationFromEvent`, `observationOf`) | SER, Syslog, and every health event except `collection.run` on the network path, `sensor.counters` and both `detector.*` types included (`event.Decode` is unchanged; E6-11) |
  | A `collection.run` of a later C4 minor (`runSessionOf`) | `netobs.alert` (`AlertFromEvent`, `AlertFromHealth`): an alert records a judgement already made |
  | A stored observation whose body is of a later C13 minor (`validateStored`), held records included | Network baselines (`DecodeBaseline` is unchanged; `IsCanonical` already refuses a later baseline that adds a key) |
  | | A `collection.run` detail key that a later node build adds: node-defined, moved by no C4 stamp, D5's residual (C4 note §1.5, §3) |

  The forward read in the second column is safe today, since no C4 minor after 0.2, 0.6 included, changed a SER or Syslog envelope field (C4 note §1.1, `desk`; C4 0.6 §1), and is held for later minors by the second new rule below, a review, not a mechanism (C4 note §3, "Residual under (b)").
- **Rules that will add rows.** Each states its floor before D1 approves the later minor:
  - a later C13 minor that adds a `coverage.degraded` value states what a bridge-floor node writes for it (D4-104 item 1.2);
  - a later C4 minor that adds a capture-loss counter states its reader floor (D4-105 item 1.4, reading 5);
  - a later C4 minor states its rollback cost for `network-observation` and `collection.run` as "the replay window's records refused and alarmed while rolled back, and never judged afterwards" (C4 note §3 condition 3; D7's N1 on #765);
  - a later C4 minor that adds or changes an envelope field or flag value of a SER, Syslog or health event states what a forward-reading reader (the event baseline's feed) does with it, and that a key added to `received` or `clock` stops an older build's sensor start while an intake record holds it (C4 note §1.3, D6's F5). If the forward reading is less restrictive, the minor takes a §7.1 floor at its first reader (C4 note §3 condition 3, D3's F1).

### 7.3 The order of the first release

CH-35 and `docs/phase4/D5-sensor-node.md` §1.15 item 1 say that the bridge build is released on its own, before any build that writes 0.2, and that the 0.2 writer ships no earlier than the release after it. **D1 ruled that this is a rule about rollback sets** (D1's comment 6897989367 on #704). Its purpose is that a node never rolls back below a reader of what it has written (D4-61, CH-35).

- **No OTSEC build has been released.** A node first installed from a release at or above every floor in §7.1 has no earlier release to roll back to. So the first release may carry the 0.2 and 0.3 writers, and nothing needs to ship before them.
- **The condition.** This holds only while no build below a floor has been released to any site. **Released** means installed at any site, by any means. The record of the first release states that no earlier release exists.
- **The check.** Each release's record names the commit it was built from, with the output of `git merge-base --is-ancestor <floor> <release commit>` for each floor in §7.1. Exit status 0 means the release carries that floor. The record keeps any release whose check fails for a floor out of the rollback set of a node that has run that floor's writer. **In the first release's record, each floor's check is pass/fail:** a check that fails for any §7.1 floor stops that release (D1's ruling 7001264083 on #760, item 6).
- **Nothing on a node enforces the floors yet.** AP-10's anti-rollback floor for the update package is not designed (§5 item 4). Until it is, a floor holds only by this record and by whoever installs the release.
- **When it is designed,** the signed anti-rollback floor a node holds is at or above every §7.1 floor that applies to a build that node has run.
- **If a build below a floor ever ships,** the rule applies to that floor as written: a release of the floor build goes first, and the writer ships no earlier than the release after it.

### 7.4 Release blocker

**No release ships while F-027's gate holds** (D4-88, D4-96). F1 to F11 must be closed, and every test owed by a later brief must have passed. F-027 in `docs/verification.md` is the record of its state. This record does not restate it.

**No release ships without AP-10's anti-rollback floor** (D1's ruling 7001264083 on #760, item 2). The node's update verifier refuses a signed package below the floor, and the floor a node holds is at least every §7.1 floor, the C4 0.6 row's `2326f34f` included. This is an open item: D7 owns its text and D5 the verifier. It is not designed (§5 items 3 and 4). It binds only packages that go through the update path, not a reimage or a hand install.

## 8. The sensor's engine image: what ships (P4-D7-P1)

Brief P4-D7-P1, for D4-112 item 4.6. Read on 2026-11-16 at `main` `b315695`. Amended on 2026-11-17 for D3's review (6931175701) and D1's rulings in D4-114 item 4.

**Evidence class: `desk`,** except the run named below, which is `CI-Linux`. Every statement here was read from one of these sources, each named where it is used:

- the files in `modules/telemetry/experiments/engine-linux/` and `.github/workflows/d4-engine-linux-eval.yml` at `b315695`;
- the Zeek 9.0.1 tarball, downloaded from the release URL in `zeek-patch/build.env`, whose SHA-256 equals the pin `fbee2eb5…97f2`;
- the base image's one layer, fetched from Docker Hub by the digest in `build.env`;
- the GitHub Actions API's metadata for run [43820030979](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43820030979) (`CI-Linux`, `ubuntu-24.04`): its head, jobs and steps, and its artifacts' names, ids and expiry dates. The artifacts' contents were not read (§8.1);
- the log of that run's job [133140767081](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43820030979/job/133140767081) (`hr23`, head `b1490522`, `success`; `CI-Linux`), read on 2026-11-17 with `gh run view --job 133140767081 --log`, step "Build C1p and C2 from one pinned tree";
- the decision log (D4-112 items 1 and 4.6, D4-113 item 2, D4-114 item 4), D3's review of #723 (6931175701), AP-30, AP-31 and AP-32 in `docs/threat-model.md`, O-7 in `docs/phase4/D1-sensor-host-recommendation.md`, SL-3 in `docs/phase4/D3-sensor-link.md`, and `docs/phase4/D4-hr23-design.md` §4.5.

No image was built or run for this section: the machine that read it has no Docker daemon. Nothing here is built, released or distributed.

**Marks.** **Owed by D4** marks a change to D4's files, which D7 does not edit. The choices that set security policy are D3's (AP-31), and D3 made them in 6931175701. D1 ruled on the rest in D4-114 item 4.

### 8.1 What the image built today carries

The image the HR-23 build makes as C2 (`zeek-patch/Dockerfile`, targets `runtime` and `c2`). The files under `engine-linux/` at `b315695` equal those at `b1490522` (`git diff` prints nothing). D2, D3, D6 and D7 accepted that head (D4-113 item 2), and its dispatch run [43820030979](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43820030979) built it.

- **The base.** `debian@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392` (`BASE_IMAGE` in `build.env`). The manifest fetched by that digest hashes to the digest. It names one layer, `sha256:37fb86c2a767b88d500c6872195f88078f64765fe0d2f9cc375cc2efbd4c0a41` (29,856,132 bytes), and the layer fetched hashes to it.
  - The layer is Debian 13.7 (`/etc/debian_version`).
  - It holds 78 packages from 55 source packages (`/var/lib/dpkg/status`, SHA-256 `0702973f302c065dec7bb21d5c611e5b4d7718afafa7a7e3b9ec139b87e0b77d`). §8.5 lists them.
- **The runtime stage** names five packages: `libmaxminddb0 libpcap0.8 libssl3 libuv1 libz1`. They are installed by name, not version, after an `apt-get update` at build time, so each build takes the versions the mirror serves that day.
  - **What run 43820030979's build did** (job 133140767081's log, `#8 [runtime 2/2]`; `CI-Linux`). apt reported "1 upgraded, 4 newly installed":
    - **four new packages:** `libdbus-1-3` 1.16.2-2, which the Dockerfile does not name and apt added as a dependency, `libmaxminddb0` 1.12.2-1, `libpcap0.8t64` 1.10.5-2 and `libuv1t64` 1.50.0-2, all from `trixie/main`;
    - **one upgrade:** `zlib1g`, from the base's 1:1.3.dfsg+really1.3.1-1+b1 to 1:1.3.dfsg+really1.3.1-1+deb13u1, from `trixie-security/main`;
    - **unchanged:** `libssl3t64`, "already the newest version (3.5.7-1~deb13u3)", the base's version.
  - These are one build's versions. Another dispatch can take others.
  - The build record's `runtime-packages.txt` (the Dockerfile's `c1p` and `c2` targets; `build.sh`, the record step) lists every package in the image by name and version (`dpkg-query -W`). It does not mark which packages this stage added.
  - **Not read:** the run's artifact `d4-engine-linux-eval-hr23` (id 14205108829). This session's egress refused the storage host it is served from. So the source packages and licences of the four new packages, and of `zlib1g` at its new version, are `unknown`: the log names neither.
- **The Zeek tree.** C2 copies the whole `DESTDIR` install of the configure line into `/usr/local/zeek`. That install holds, beside `bin/zeek` and the scripts under `share/zeek`, the programs below. Each `bin/` name is one the job's log shows installed into `/stage/c2/usr/local/zeek/bin/` (the "-- Installing:" lines; `CI-Linux`); the rest is read from the CMake files in the pinned tarball.
  - **The Spicy and HILTI toolchain:** `spicyc`, `spicyz`, `spicy-build`, `spicy-config`, `spicy-driver`, `spicy-dump`, `spicy-precompile-headers`, `hiltic` and `hilti-config`, with their runtime archives (`auxil/spicy/`, the `install` rules; `src/spicy/spicyz/CMakeLists.txt`). Spicy stays on (the Dockerfile's header; D7's C6). The log neither builds nor installs `hilti-cxx-driver`. In the pinned tarball, `auxil/spicy/hilti/toolchain/CMakeLists.txt` adds that target only inside `if (MSVC)`, and `bin/hilti-cxx-driver.cc` stops with `#error "hilti-cxx-driver is only needed on Windows/MSVC"` (read by D6 from the tarball at its pin, 6932126214; `desk`). So it is built only with MSVC.
  - **Zeek's own build tools and development files:** `binpac`, `bifcl`, `zeek-config`, `zeek-cut`, `paraglob-test`, `zeek-cluster-layout-generator`, `zeek-systemd-generator`, the headers under `include/`, and the CMake package files.
  - **Test and operator tools**, which the configure line leaves on. In `CMakeLists.txt` ("On UNIX, install additional Zeek tools by default"), `INSTALL_BTEST`, `INSTALL_ZEEK_CLIENT` and `INSTALL_AUX_TOOLS` default to on outside Windows. The line passes `--disable-btest-pcaps`, but not `--disable-btest`, `--disable-zeek-client` or `--disable-auxtools`. So BTest, `zeek-client` and `zeek-archiver` are installed.
  - **`adtrace` and `rst`** are installed only in binary-packaging mode or when `zeek-aux` is the top-level project (`auxil/zeek-aux/CMakeLists.txt`, `AddAuxInstallTarget`). `rst` forges TCP RST packets on a raw socket (`auxil/zeek-aux/README`; `rst/rst.c` opens `SOCK_RAW` with `IP_HDRINCL` and calls `sendto`). **The job's log installs no `bin/rst` and no `bin/adtrace` into `/stage/c2`** (`CI-Linux`). The record's `files-c2.txt` lists neither (read by D6 from the run's artifact, 6932126214; `CI-Linux`). D7 did not read the artifact. BTest's `btest-diff-rst`, `btest-rst-cmd`, `btest-rst-include` and `btest-rst-pipe` are installed. They are BTest's helpers, not `rst`, and none ships under (C) (§8.4 item 1). So a check for `rst` matches the file name exactly, not a substring.
  - BTest and `zeek-client` are Python programs, and the runtime stage installs no Python. The Spicy toolchain compiles through a C++ compiler, and the runtime stage has none. By these readings, none of them can run in this image, but all of them ship in it.

  This is the "full install, with toolchain and test tools" of D4-112 item 4.6.
- **Records and notices** under `/usr/local/zeek/share/otsec-build/`: the build and runtime package lists, `generated.sha256`, `binpac.txt`, and `notices/`. `notices/` holds Zeek's `COPYING`, the patch, and every `COPYING*` and `LICENSE*` file of the tree outside test folders.
- **Not in the image:** the project's script and ICSNPP. `run.sh` (`zeek_run`) mounts two folders read-only at run time:
  - `/exp`, which is the whole `engine-linux/` folder (`here` in `run.sh`). Zeek loads `probe.zeek` from it, and other files there in other configurations (`modbus-sig.zeek`, for example);
  - `/pkgs`.

  It runs `sh /exp/in-container.sh` inside the image, so the harness needs the base's `sh` and coreutils. Its pipe modes also run `cat … | zeek -r -` inside the container.
- **Other steps that run tools inside the image under test** (D3's B1): `build.sh`'s record step runs `sh -c 'find … | xargs sha256sum'` (`files-<v>.txt`), `sha256sum /usr/local/zeek/bin/zeek`, `cat` of the records and `ldd` inside it. The `c1p` and `c2` targets' last step runs `dpkg-query` inside the image. Under (C), none of these programs is in the shipped image (§8.4 items 2 and 5). `run.sh`'s two `cat`s of `consts.zeek` are not among them: they run in `$ZEEK_IMAGE`, the stock image `pins.env` pins (`zeek/zeek@sha256:71c1d6b6…`), never in C1p or C2 (D6's N4).

### 8.2 What the shipped engine image carries

Three options:

- **(A) Ship C2 as built.** The measured image is trivially the shipped one. But it ships the toolchain, the test tools, the headers, and possibly `rst`. Each is more for an engine exploit to find on the sensor host (AP-30), and more to inventory, patch and give source for.
- **(B) A runtime-only engine image on the Debian base.** It is built in the same build, from the same tree, and measured. `/usr/local/zeek` holds only:
  - `bin/zeek`;
  - the shared libraries it loads from the tree, as `ldd` in the record names them;
  - `share/zeek`, the scripts;
  - any plugin directory the record shows Zeek loading;
  - `share/otsec-build`, the records and notices.

  The base and the runtime stage's packages stay as they are.
- **(C) As (B), without the Debian userland.** The image holds `zeek`, its scripts and records, the shared objects `zeek` loads (§8.4 items 1 and 6), and the copyright and licence files for each. It has no shell, package manager or Perl anywhere in the image.

**Settled: (C) is the image that ships and that the counted run measures** (D3's choice in 6931175701; D1's ruling, D4-114 item 4.1):

- **The ship check covers the whole image under every option,** and fails on any file with a setuid or setgid bit or a `security.capability` attribute (D3's N1; §8.4 item 1).
- **(B) is a fallback only on that condition.** Under (B), the programs that carry those bits or attributes are removed, or their bits cleared. (A) is not used.
- **No shipped image carries `rst`,** or any other program of the tree that opens a raw socket to send (AP-31 (3), AP-32). `libpcap`'s `pcap_inject` stays in every option, because `zeek` links it. That is acceptable only because the engine holds no packet socket and has no route (SL-3; D3's review).
- **(C) does not replace SL-3** (D3's N6; reason 1 below).

The reasons:

1. **(C) removes tools, not the ability to run code** (D3's N6). An exploit in the engine finds no shell, `apt`, `dpkg` or Perl in its container, and no program the sensor does not run. A Zeek script that calls `system` fails, and the sensor needs none. An exploit with native code execution needs no shell, so (C) narrows the tools it can use and the inventory, and nothing more. The barrier stays SL-3 (`docs/phase4/D3-sensor-link.md`): the engine's own account, the empty network namespace, no packet socket and no key.
2. **(A) and (B) ship setuid programs and a fetcher** (D3's reasons 1 and 2). The base lists `login`, `mount`, `passwd` and `util-linux` (§8.5), which install setuid-root programs. In this layer, the tar headers carry setuid on `chfn`, `chsh`, `gpasswd`, `mount`, `newgrp`, `passwd`, `su` and `umount`, setgid on `chage`, `expiry` and `unix_chkpwd`, and no extended attribute (read by D6 from the layer, 6932126214; `desk`). `apt`, `sqv` and the archive keyring are a package fetcher, which AP-31 (1) requires to be absent or off. (C) ships neither.
3. **Patching cost** (D3's reason 3). Any rebuild is a new engine that needs its own counted run (design §4.5), so each base-package advisory that applies to the image (AP-30 (4)) forces a re-measurement. Under (C), only the libraries `zeek` loads can force one.
4. **Licences.** Under (C), the only copyleft code in the image is what the libraries `zeek` loads carry. Which libraries those are is `unknown` until `ldd` is read from the record (§8.3 A; §8.4 item 6). Under (B) or (A), most of the Debian base comes as well, and the source the release must carry with the image grows to match (§8.3 F).
5. **(C) costs a harness change and a record change.** The image has no `sh`, so the run calls `zeek` as the entrypoint, one capture per container, and every step that today runs a tool inside the image reads the shipped image from the host instead (owed by D4, §8.4 items 2 and 5).
6. **No option removes the GPL from a sensor release.** Under O-7 (the project ships a signed host image with the base system; `docs/phase4/D1-sensor-host-recommendation.md`), the host image carries a Linux kernel and a userland, whatever the engine image holds. §8.3 settles the route for both.

**What this does to "the image measured is the one shipped" (D4-112 item 4.6; `docs/phase4/D4-hr23-design.md` §4.5):**

- It holds only if the counted run runs C2 from the chosen image itself, by its image ID, and the release carries those bytes, not a rebuild.
- Each dispatch builds again, `apt-get update` takes the day's versions, and nothing shows the build to be reproducible. So the counted run's own job must keep the image (§8.4 item 4).
- If the image changes after the counted run (for example, from (C) to the (B) fallback), it is a new engine for this purpose. HR-23's result reaches it only by its own counted run or a shown reproducible build (design §4.5; D7's N2).
- **One term: image ID** (D3's N4). This record means by it the `Id` that `docker image inspect -f '{{.Id}}'` prints for the image on the runner of the counted run, which is what `build.sh` records today. The value depends on the daemon's image store (D3's N4): with the containerd image store it is, by D7's understanding, the digest of the image's index or manifest, and with the classic store the digest of its configuration. Docker's documentation was not read for this. So the job logs which store its daemon uses (`docker info`), and every later comparison of an image ID is made under the same store. Design §4.5's "digest" is to be read as this image ID; aligning that word in the design is D4's (owed by D4, §8.4 item 3). A registry's manifest digest is not used: nothing is pushed to a registry.

### 8.3 Copyleft components, source and licence texts

Each licence statement below cites the file it was read from. This is not legal advice.

**A. The Debian base (§8.5).** For 69 of the 78 packages, the copyright file names GPL, LGPL or MPL for at least one file. That flag is a coarse reading of each file's `License:` fields, or of its text where it has none (`debian-archive-keyring`, `libcrypt1`, `gcc-14-base`). It is not a per-file mapping.

- **Programs:**
  - GPL-3+: `bash`, `coreutils`, `grep`, `sed`, `gzip`;
  - GPL-2+: `dpkg`;
  - GPL-2.0-only: `mawk`;
  - GPL-1+ or Artistic: `perl-base`;
  - the `util-linux` family, `tar`, `findutils`, `diffutils`, `apt`, `sysvinit-utils` and `hostname`, whose copyright files name GPL for some of their files.
- **What `zeek` loads from the base is `unknown`,** because the record's `ldd zeek` was not read (§8.4 item 6). The likely candidates are listed here as the base's copyright files state their licences, not as what `zeek` loads:
  - `libc6`: LGPL-2.1+ for its main parts, with other licences for some files (`/usr/share/doc/libc6/copyright`, SHA-256 `f5788886…850d`);
  - `libstdc++6` and `libgcc-s1`: GPL-3+ with the GCC Runtime Library Exception. Their doc folders link to `gcc-14-base`, whose copyright file (SHA-256 `20390f8a…2f79`) carries the exception. The exception covers programs compiled with GCC. It does not lift the GPL's duties for the libraries themselves when they are shipped;
  - `libssl3t64`: Apache-2.0, with Artistic or GPL-1+ named for some files (`/usr/share/doc/libssl3t64/copyright`, §8.5), at the base's version, which the runtime stage left unchanged in run 43820030979 (§8.1).

**B. Static linking.** `sqv` is a Rust program. Its `Static-Built-Using` field (`/var/lib/dpkg/status`) names the crates compiled into it, and their source is part of its corresponding source. Any such field among the runtime stage's packages counts the same way. Under (C), `sqv` is not shipped.

**C. The runtime stage's packages.** Their names and versions in one build are in §8.1 (`CI-Linux`). Their source packages and licences are `unknown`, because their copyright files were not read (§8.4 item 5).

**D. Zeek and its tree.**

- `COPYING` is BSD-3-Clause. Its SHA-256 `1f984adb…333aa` equals the pin `COPYING_SHA256` and §4's row.
- `COPYING-3rdparty` adds the following. §4's SHA-256 `b815419a…8a4a` is of the file on `zeek/zeek` `master` at `5a6529c8`, read on 2026-11-11, not of the tarball. For this section the file was read from the 9.0.1 tarball at its pin, and that copy hashed on 2026-11-16 to the same `b815419a9ec7c307d49983dc5cead5e411ace082a638a2d7bbd4d3deb1ac8a4a`. The tarball's `COPYING` hashed to `1f984adb…333aa`.
  - **MPL-2.0 for `scripts/base/protocols/ssl/mozilla-ca-list.zeek`** (SHA-256 `2af43b238928818e2263b95f0e1b6ea51d9f8c5006fc51528c11d156998a8794`). It is installed with the scripts, so it ships in its own source form. Its header names the MPL and the address of its text. D7 reads that as meeting MPL-2.0 §3.1's duty to inform recipients and to say how to get the licence (`/usr/share/common-licenses/MPL-2.0` in the base, SHA-256 `fab3dd6b…3e85`). Under (C), the base's copy is not in the image, so the build copies it in (F.2).
  - **Multifast:** LGPL-3.0-or-later, with its author's "explicit permission" to use it in Zeek under BSD.
  - **The JSON licence** ("used for Good, not Evil") covers only RapidJSON's `bin/jsonchecker/` (its section of `COPYING-3rdparty`), which is test data the build does not use.
- **The notices are wider than what ships.** The Dockerfile's `find` also copies the licence files of `auxil/vcpkg/ports/` (for example `ffnvcodec`, `vulkan-sdk-components`), which are Windows packaging and are not built here. That copy states no duty. R-1's notices file must not present them as parts of the image.
- `zeek` itself is BSD. It is a separate program that links the LGPL `libc6` dynamically. No GPL term reaches `zeek` or OTSEC's binaries from these readings.

**E. The project's patch.** `hr23-fc-dispatch.patch` is OTSEC's own (`LICENSE.md`), changes BSD code, and ships in `notices/`.

**F. The settlement, for D1 to approve with this PR:**

1. **The source goes with the image, and no written offer is made.** Every distribution of the engine image carries, in the same package or from the same place, a source bundle (GPL-2 §3(a); GPL-3 §6(a), or §6(d) for a download). The bundle holds:
   - for each Debian binary package that any file in the image comes from: the Debian source package at the image's source version (the `.dsc` and the files it names), and each source named in its `Built-Using` and `Static-Built-Using` fields;
   - the Zeek tarball and its `.asc` at the pins, the patch, the `Dockerfile`, `build.env` and `build.sh`. These are "the scripts used to control compilation and installation" that GPL-2 §3 asks for where a GPL part is built. For Zeek they are a convenience.

   **Why not a written offer.** A written offer (GPL-2 §3(b); GPL-3 §6(b)) binds whoever makes it, for at least three years, to answer any third party. GPL-3 §6(b) also adds "as long as you offer spare parts or customer support". No one holds that role, and the owner has not named one. §6(d) also keeps the source "available for as long as needed". Source in the same package ends the duty at each distribution.

   The texts read: `/usr/share/common-licenses/GPL-2` (SHA-256 `edaef632…33f6`) and `GPL-3` (`3972dc97…6986`) in the base layer.
2. **The licence texts in the image.**
   - Under (B), the image keeps `/usr/share/doc/*/copyright`: the slim variant excludes `/usr/share/doc/*` but includes the copyright files (`/etc/dpkg/dpkg.cfg.d/docker`). It also keeps `/usr/share/common-licenses/` (`base-files`), to which the copyright files point.
   - Under (C), the build copies into the image the copyright file of each package any shipped file comes from, and the licence texts those files point to. It also copies the base's `/usr/share/common-licenses/MPL-2.0` (SHA-256 `fab3dd6b…3e85`) into `share/otsec-build/notices/`, for `mozilla-ca-list.zeek` (D above). The source bundle holds the same file. Both are owed by D4 (§8.4 items 1 and 7). The header's address is then a second route, not the only one.
   - Either way, Zeek's notices stay in `share/otsec-build/notices/`, and R-1's notices file names the engine image and points to them.
3. **When the bundle is owed.** Before the image is first distributed, which can be earlier than a release. A copy reaching anyone outside the project is a distribution: a release, a registry push, or an artifact of this public repository. **The job's artifact in this public repository is itself a distribution** (D4-114 item 4.3). So the source bundle (§8.4 item 7) is complete, and reviewed by D7, D3 and D6, before the counted run uploads the image.
   - Today no workflow uploads an image: `d4-engine-linux-eval.yml` uploads records and tables only.
   - §8.4 items 4 and 7 keep it so until the bundle is complete and reviewed, and then the bundle travels with the image.

### 8.4 Owed by D4 before HR-23's counted run

D7 edits none of these files. Each item is a check D4 can run. **The harness change these items need is owed by D4 in D4's own PR, after the fuzz PR and before HR-23's counted run** (D4-115). **Each rule has its own control** (D3's N7): the check names the rule that failed, and each control asserts that its own rule failed, so a control that would trip another rule first proves nothing. Each control is shown failing in the PR that adds the check (self-check item 1).

**Name.** Below, "the shipped (C) image" is the runtime-only image of option (C) (§8.2). "C2" is HR-23's patched build, and "C2 as built" is the full image the Dockerfile's `c2` target makes today (§8.1). The shipped (C) image holds C2's `zeek`, not C2's whole tree.

**Read the shipped (C) image from the host, never from inside it or from a sibling** (D3's B1). The shipped (C) image has no shell, coreutils, `ldd` or `dpkg`. Every value below that is taken of the shipped (C) image is read from its own filesystem by its image ID, on the host, from its own layers in a `docker save` archive of that image ID, applying whiteouts (D6's N8). The archive is either one made at build time, before the run, for the record and item 1's check, or item 4's, made after the run; both hold the same bytes under one image ID (D6's N10). `docker export` of a container is not used for the checks of item 1: it also carries entries that belong to the container, not the image (D6 names `/.dockerenv`, `/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/mtab` and the mount points, by D6's understanding, not read from Docker's documentation), and a file of the same name that the build added would pass beside them. Below, "the layers" means these. It is never taken from C2 as built, C1p, a control image or the build stage. A value taken from another image breaks the tie between the record and the shipped bytes, and no check would notice. Only `zeek` itself runs inside the shipped image, as the entrypoint (`zeek --version`, `zeek -NN`, and the run).

1. **The shipped (C) image's target, and its check.** D4 builds the image that §8.2 settles, in the same build and from the same tree. C1p and the controls take the same shape, so that the record check's "one tree" comparison still compares like with like. D4 updates that check's list of the files that differ, which today includes two `.pac` files under `include/` (`dnp3-analyzer.pac`, `dnp3-protocol.pac`). The record check reads the layers of the shipped (C) image and fails, naming the rule, if:
   - **any file anywhere in the image** is outside the kept list (D3's N1). The kept list names every path in the image, not only those under `/usr/local/zeek`, so a stray file the build copies in fails the check. Control: the shipped (C) image with one extra file added.
   - **any file has a setuid or setgid bit, or a `security.capability` attribute** (D3's N1; D4-114 item 4.1). They are read from the layers' tar headers. **Three controls** (D3's N7), each setting its bit or attribute on a file already in the kept list: one setuid, one setgid, one capability. Each control image reads its own bit or attribute in its own build stage (for example with `getcap`) before the check runs, so that a capability control that does not fail tells "the layers drop the attribute" apart from "the control never carried it". If the layers do not carry the attribute, the check is not accepted until it reads it another way.
   - **the shipped (C) image holds a shell, a package manager, Perl or Python anywhere** (D6's provisional point 3): any file named `sh`, `bash`, `rbash`, `dash`, `busybox`, `sqv`, or matching `apt*`, `dpkg*`, `perl*` or `python*`, in any folder (D6's N2: the base holds `perl5.40.1`, `rbash`, ten `dpkg-*` programs, four more `apt-*` programs and `sqv`). The kept list already excludes them; this names them so that a kept list that grows cannot let one in. **Controls:** `/bin/sh`, and `/usr/bin/perl5.40.1`, each added to both the image and the kept list (D3's N7; D6's N2).
   - **the image holds `rst`** (by exact file name; §8.1), or any of `zkg`, `zeekctl`, `btest*`, `zeek-client`, `spicyc`, `hiltic`, `binpac`, `bifcl` or `include/`. **Control:** `bin/rst` added to both the image and the kept list (D6's N6).
   - **the shipped (C) image's `zeek -NN` differs from that of C2 as built** (`plugins-c2.txt`), byte for byte (D3's N2). A missing library or plugin file either stops `zeek` at start or drops an analyzer without a sound. C2 as built installs `lib/zeek/plugins` and `lib/zeek/spicy` empty, and its plugins are built into `zeek` (D6's N1). **Control:** the shipped (C) image without one of the tree's libraries that `zeek` loads, for example `lib/libhilti.so`, so `zeek` fails to start and `-NN` differs, while the kept-list rule, which checks only for extra files, passes. **Limit:** `-NN` lists plugins only. What glibc (NSS, gconv) and OpenSSL (providers, configuration) load with `dlopen` is not checked by this rule or any other in this list.
2. **The harness and the record for the shipped (C) image** (D3's B1; D6's provisional point 2).
   - **The harness.** The run calls `zeek` as the container's entrypoint, one capture per container. The checks that `in-container.sh` makes today (exit code, the per-capture output folder, "not run") move to the host side. The pipe modes, which today run `cat … | zeek -r -` inside the container, feed the container's stdin from the host instead.
   - **The record.** Each step of §8.1's "other steps" reads the layers instead: `build.sh`'s file list (`files-<v>.txt`) and the SHA-256 of `zeek` are hashed on the host; its `cat` of the records reads them from the layers (D6's N10).
   - **`ldd`** (item 6) is taken one of two ways: from the layers, by reading `zeek`'s `NEEDED` entries on the host and resolving each inside the image's tree, never against the host's libraries, and then each resolved library's own `NEEDED` entries in turn, until no new library appears (D6's N3); or by `ldd` in C2 as built, with the SHA-256 of its `zeek` shown equal to that of the shipped (C) image's `zeek`. **Control:** the host-side set equals the `ldd` set the record gives for C2 as built (with equal `zeek` hashes; 19 lines in run 43820030979's record, by D6's reading), leaving out `linux-vdso.so.1`, which the kernel maps and no file holds (D6's N9), and a walk of one level only must fail that comparison.
3. **The counted run names what it measured** (D3's N3).
   - It runs the shipped (C) image by its image ID (§8.2, "One term"). It logs that ID, the daemon's image store, and the `zeek` binary's SHA-256 read from the layers (design §4.5).
   - **Settled: every file the run could load is hashed on the host, before and after the run** (option (c); D1's ruling on D6's B1, 6933304617). The measured run is unchanged: no script is added to it. Before each Zeek container starts, the host hashes every file in every folder mounted into it except the output folder. Today `zeek_run` mounts `/exp` (which includes `/exp/zeek-patch`), `/pkgs` and `/pcaps`, all read-only, and `/out`, the output. After the run, it hashes them again, and the check fails unless both sets are equal. **The one exception is the run's own output folder** (`/out` today; D6's N11; D3's N8). It is the only writable mount, it is named in the check, and it is left out of the equality set by that name. Zeek's logs leave the container through it. Any other writable mount fails condition 1, and any mount that is not hashed fails condition 3, so declaring another mount to be the output cannot get it past either rule. Inside the container Zeek reaches only the image and these mounts, so the set covers every script and signature file the run could load (`@load`, `@load-sigs`). The base scripts inside the image are covered by the image ID and item 2's per-file hashes (D6). Scripts outside the image are carried by the release by these hashes. Four conditions, each with its control (D1's ruling):
     1. **The mount list is taken from the container itself,** by `docker inspect` between `docker create` and `docker start`, not from the script's own arguments (D6). The check fails unless every mount except the named output folder is read-only (`RW` false) (D3's N8). Without this, an engine compromised by one capture could rewrite a script that a later container loads, and put it back before the last hash. **Control:** a run with one hashed mount writable, which must fail on this rule.
     2. **The whole `docker create` line is logged** for each Zeek run (D6), with the full `zeek` command line.
     3. **Every mount is hashed.** Control: a run with one extra mount that is not hashed, which must fail on this rule (D6).
     4. **Nothing else is reachable** (D4). Zeek's search path is read from the shipped (C) image's own `zeek --help`; script arguments are absolute paths, and the check fails on a command-line file outside the hashed set and the image; and each run's output folder must not exist before its container starts. **Controls,** one per rule (D3's N7; D6's N11): a command line that names a file outside the hashed mounts and the image, which must fail on the coverage rule; and a run whose output folder exists before its container starts, which must fail on the new-folder rule. Zeek 9.0.1's search path begins with `.`, so Zeek also searches its working directory: `CI-Linux`, run 44125345917 (head `f4b9ab7f`), which read `$ZEEKPATH` from each image's own `zeek --help` (stock, C1p, C2 and the control images; the shipped (C) image does not exist yet, so it is read again from that image). So the check fails unless the container's working directory is in the image (under no mount) or is the run's own output folder, which the new-folder rule requires to be new for its one capture, one capture per container. `in-container.sh` (working directory the capture's new output folder) and `mountcheck.py`'s `search-path` rule (a direct `zeek` whose working directory is under a mount fails; control `test_control_dot_with_the_working_directory_under_a_mount_fails_search_path`) enforce this today.
     - **Equality control:** one file in `/exp` changed between the two hashes, which must fail on the equality rule.
     - The image's own `Env` and `Entrypoint` are covered by its image ID.
     - **Suricata's containers are outside the mount check** (D4-118 item 2.2; D1's 6955017919 on #744): Suricata is not the measured engine, nothing of it ships, and its image's four declared `VOLUME`s would need a second exemption. It holds only while every host folder a Suricata container shares with a Zeek container is mounted read-only, except the output folder. What this leaves, through Suricata's writable output folder: D4-118 item 2.4.
   - D4 aligns design §4.5's "digest" with "image ID" (§8.2).
4. **Keep the measured image. Settled: option (i), with the owner's offline storage as its durable home** (D4-114 item 4.2).
   - **In the counted run's own job,** after the run, `docker save` the shipped image by its ID and log the archive's SHA-256. An archive kept that way is the only route from a hosted runner that keeps the measured bytes.
   - **The job checks the archive** (D6's provisional B1; D3's N4). It reads the image ID and the `zeek` binary's SHA-256 from the saved archive itself, and fails unless both equal what the run logged. **Two controls** (D3's N7), one per comparison: an archive whose image ID differs and whose `zeek` is the same (the shipped (C) image with one file added), and a copy of the shipped archive with `zeek`'s bytes changed in its layer and its ID left as it is. Each must fail on its own comparison.
   - **The archive and the source bundle (item 7) go in an artifact of their own** (D3's N5). That artifact holds no per-row output of the counted run, so no row that finding 1 (D4-112 item 1.3) keeps inside the job leaves it through this artifact. Whatever goes to the durable home goes whole.
   - **The durable home is the owner's offline storage:** two copies, both outside the checkout, taken before the artifact expires. `reference/` and `tools/` sit inside the checkout, where Go and pytest do not read `.gitignore`, so neither is used. The owner checks each copy's SHA-256 against the archive's logged SHA-256, since `docker load` is not run on the owner's PC. Anyone who later loads a copy runs the job's check on it: the loaded image's ID, under the logged image store, and its `zeek` SHA-256 read from the host, equal the logged values. This is the owner's step ("Waiting on the owner" in `HANDOFF.md`).
   - **Expiry.** The workflow sets no `retention-days`, so the repository's default applies: run 43820030979's artifacts expire on 2027-02-14, 90 days after the run. D1 records the counted run's artifact expiry date in that run's decision entry.
   - **Not used: a GitHub Release asset** (D3; D4-114 item 4.2). It would be a public, unsigned copy that cannot be withdrawn, of an image that O-7 says ships signed, before a release key holder is named (TB9).
   - **Not chosen: (ii),** a rebuild shown to be bit-identical (design §4.5). That needs every package pinned by version and a reproducible build, which nothing yet shows.
5. **The package record of the shipped image,** so that D7 can complete §8.3 A and C (D6's provisional point 2). Under (C), the shipped image has no `dpkg` and no package database, so the Dockerfile's `dpkg-query` step, which today runs in the `c1p` and `c2` targets, cannot run in it. The record is taken in the stage the shipped files are copied from, which has `dpkg`, and is tied to the shipped image by hash:
   - for each package that a shipped file comes from: `dpkg-query -W -f '${Package} ${Version} ${source:Package} ${source:Version}\n'`, with its `Built-Using` and `Static-Built-Using` fields;
   - `dpkg -S` of each shipped file outside `/usr/local/zeek`, with that file's SHA-256 in the stage. The check fails unless each equals the same file's SHA-256 in the shipped image's layers, and fails on any shipped file outside `/usr/local/zeek` that no package owns and the kept list does not name as the build's own (records, notices, copyright files). **Controls** (D6's N6): one shipped library whose bytes differ from the stage's, and one unowned file that the kept list does not name, each failing its own rule;
   - the SHA-256 of each `/usr/share/doc/<package>/copyright` copied in (§8.3 F.2).
6. **`ldd` of the shipped `zeek`,** taken as item 2 says. D4 quotes it for the shipped image in the PR that builds that image. D7 then names, in §8.3 A, the libraries `zeek` loads and their licences.
7. **The source bundle (§8.3 F.1). Owner: D4,** from the package record of item 5. It holds:
   - the Debian source package for each source version in the record;
   - each source named in a `Built-Using` or `Static-Built-Using` field;
   - the Zeek tarball and its `.asc`, the patch, and the build files.

   Debian's archive or its snapshot archive may serve these sources, and fetching them happens at build time, never on a sensor (AP-31 (1)). The bundle's own SHA-256, and the SHA-256 of each file in it, are logged beside the image archive's.

   **The bundle is complete, and reviewed by D7, D3 and D6, before the counted run uploads the image** (D4-114 item 4.3). D7 checks it against the package record. Because each build takes the day's versions (§8.1), the review is of a bundle and record made by a dispatch before the counted run that uploads no image. The counted run's job makes its bundle by the same step, and uploads the image only if its record names the same packages and source versions as the reviewed one and its bundle's file list and hashes equal the reviewed bundle's. **Two controls,** one per comparison: a record with one source version changed, and a bundle with one file's bytes changed and its record unchanged (D6's N6). Each must stop the upload.

   **A run whose record drifts is not the counted run** (D6's N7). It uploads no image, so item 4 keeps nothing, and it cannot stand as the measurement of the shipped image. Each dispatch runs `apt-get update` (§8.1), so any Debian update between the review dispatch and the counted run causes this. The new bundle is reviewed, and the counted run is repeated.

After the counted run, D7 records here, with the run (design §4.5): the measured image's ID and image store, the `zeek` binary's SHA-256, the archive's and the bundle's SHA-256, and the artifact's expiry date.

### 8.5 The base image's packages

One line per package from the base layer's `/var/lib/dpkg/status`. The fields are:

- the binary package and its version;
- the source package and its version;
- the SHA-256 of `/usr/share/doc/<package>/copyright`, following the doc folder's link where there is one;
- `copyleft` where that file names GPL, LGPL or MPL for any file (§8.3 A), and `-` otherwise.

The runtime stage's packages are not here: §8.1 names them from one build's log. Under (C), most of these packages ship no file (§8.2).

```text
apt 3.0.4 apt 3.0.4 77ab918ade9bce20b07524572fc8eab3f8c0cab4d246f282043892aaa9538803 copyleft
base-files 13.8+deb13u7 base-files 13.8+deb13u7 c84c664bce3a83eaa327bb9e354c0df588bc535b5e95474aab7ca3cce74937cd copyleft
base-passwd 3.6.7 base-passwd 3.6.7 0f1cde79bd80a75f9029ae9a8c252b642223027ef36f6989c63a8230aae576a7 copyleft
bash 5.2.37-2+b10 bash 5.2.37-2 06319d84c3e5ed096036f6a9310a030c7e84e50dff2b8a6792285c83ec0ada73 copyleft
bsdutils 1:2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
coreutils 9.7-3 coreutils 9.7-3 3a63d4b11a7ba4c1c17175072ea28e07b0f80c7bc1ca042b27431fe65a14755b copyleft
dash 0.5.12-12 dash 0.5.12-12 d98c53f281321baad38164aa9ae6e368a9253be6ec51bd26a759b5e72b326f4a copyleft
debconf 1.5.91 debconf 1.5.91 57163c71bd8a5289660892827dd0dfaa7fef47f89deedc9dc6711ced7d0a28d7 -
debian-archive-keyring 2025.1 debian-archive-keyring 2025.1 8f918c0bebd1454a084698a95c09d9a03cec8453dad1fc6eab9e6427da9d33a9 copyleft
debianutils 5.23.2 debianutils 5.23.2 aeb68ea374f488431b8963df24f05482692edfa70d7556d7e528dd06d255461c copyleft
diffutils 1:3.10-4 diffutils 1:3.10-4 ac6fcf18142bab7569188ae75b204a9e1c73c050c0f9467adaf080759e516123 copyleft
dpkg 1.22.22 dpkg 1.22.22 3376ec6f7bebf6b1e55da9d5dc591c73e752b45dccb0488e8365d2cf216a1746 copyleft
findutils 4.10.0-3 findutils 4.10.0-3 f51541fbdfe15c01cd3fd3a06ad3b74478902d36a958d95b1756434979d97ed5 copyleft
gcc-14-base 14.2.0-19 gcc-14 14.2.0-19 20390f8a6f3b1e4d7cb45dd8652dabb259bbef688cbad839bcdb0b9ba7252f79 copyleft
grep 3.11-4 grep 3.11-4 42d9b4d610396b1e8d1303dcb9487af3f5a2d2709623cf03a04cf76acdf6c5e3 copyleft
gzip 1.13-1+deb13u1 gzip 1.13-1+deb13u1 02c197fa26ad056ed2382bb8c3e6323d47edfda4539f727b4ab3f4dbf64ac413 copyleft
hostname 3.25 hostname 3.25 94189fc5a9a7b7224d96e1a0cfdfe9be0df2018b04bf21d591627ab96b30cad1 copyleft
init-system-helpers 1.69~deb13u1 init-system-helpers 1.69~deb13u1 7534601cc4fa513804d16490359f5831e7b6a1212da3bbf948bebdd4c8799783 copyleft
libacl1 2.3.2-2+b1 acl 2.3.2-2 9a2dfb4a5abc7e84be2cc41f1089be665519c9409549296f6c19de57ab1d37c2 copyleft
libapt-pkg7.0 3.0.4 apt 3.0.4 77ab918ade9bce20b07524572fc8eab3f8c0cab4d246f282043892aaa9538803 copyleft
libattr1 1:2.5.2-3 attr 1:2.5.2-3 0cbec745d85ea775450b2d54fac55277197f429e52d611f72852ed420450620e copyleft
libaudit-common 1:4.0.2-2+deb13u1 audit 1:4.0.2-2+deb13u1 6c7011e93f643b112c4cc3622131e28a30477afad6c4f5efe466b13aa7f603cc copyleft
libaudit1 1:4.0.2-2+deb13u1 audit 1:4.0.2-2+deb13u1 6c7011e93f643b112c4cc3622131e28a30477afad6c4f5efe466b13aa7f603cc copyleft
libblkid1 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
libbsd0 0.12.2-2 libbsd 0.12.2-2 47eaa031b1741a33a93e7cc8909bfe153acaec7ddff12e4dc7377d0e2ec10e91 -
libbz2-1.0 1.0.8-6 bzip2 1.0.8-6 832ed535ff3c3d025a8d2348eb1b697b89addcf2eaadbc17650262040b9145e2 copyleft
libc-bin 2.41-12+deb13u4 glibc 2.41-12+deb13u4 f5788886720a2605a946e81d571e6c8162b09f58d2e2ceb8d36e5768fccd850d copyleft
libc6 2.41-12+deb13u4 glibc 2.41-12+deb13u4 f5788886720a2605a946e81d571e6c8162b09f58d2e2ceb8d36e5768fccd850d copyleft
libcap-ng0 0.8.5-4+b1 libcap-ng 0.8.5-4 567997de097e3738564c90e6fe13343b2daae21a7926d6fb161df41322c1840b copyleft
libcap2 1:2.75-10+deb13u1+b3 libcap2 1:2.75-10+deb13u1 04f9fb974e10f6ca0cd226811f72b3855f8383daad0e5de7adac8d5b0b7796c3 copyleft
libcrypt1 1:4.4.38-1 libxcrypt 1:4.4.38-1 5a5e7ca0e9f3f9679977e3a3e9ede45ad92885a3297ea78e766979f9866c5a16 copyleft
libdb5.3t64 5.3.28+dfsg2-9 db5.3 5.3.28+dfsg2-9 8b53da37d73289d9df7317b3a2dbe16491f1fa9fec8b77b86d69704b40ce2c26 copyleft
libdebconfclient0 0.280 cdebconf 0.280 cf63099896d1c0f6529c41b8d95738e6fea342ffba609187d339c4f38ce36ecc copyleft
libgcc-s1 14.2.0-19 gcc-14 14.2.0-19 20390f8a6f3b1e4d7cb45dd8652dabb259bbef688cbad839bcdb0b9ba7252f79 copyleft
libgmp10 2:6.3.0+dfsg-3 gmp 2:6.3.0+dfsg-3 7d366aef5ba325150246de1d7820c4c9926cd27ca61a69948492b26cd3b61601 copyleft
libhogweed6t64 3.10.1-1 nettle 3.10.1-1 344396197142cd506468b20029ea5722d507c980129bb3db4af02424ed6f39c6 copyleft
liblastlog2-2 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
liblz4-1 1.10.0-4 lz4 1.10.0-4 8dce0cb8c5a4486e4aac00466e4dd4b0b5b28d70efe3b3256ea4594099a8509c copyleft
liblzma5 5.8.1-1+deb13u2 xz-utils 5.8.1-1+deb13u2 d755588e2d89d7845d0d4e718ac45d49ae9fc53cec4540af105963c20598f9d7 copyleft
libmd0 1.1.0-2+b1 libmd 1.1.0-2 4365ef6255ad553fce69dd4bc0e093472c5d0e41b8ea493a545cc926ce171aa6 -
libmount1 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
libnettle8t64 3.10.1-1 nettle 3.10.1-1 344396197142cd506468b20029ea5722d507c980129bb3db4af02424ed6f39c6 copyleft
libpam-modules 1.7.0-5 pam 1.7.0-5 6b11ef9ab5429d9618cc72e8dfd4efefde363165ef174be0549918e0c44f5dcb copyleft
libpam-modules-bin 1.7.0-5 pam 1.7.0-5 6b11ef9ab5429d9618cc72e8dfd4efefde363165ef174be0549918e0c44f5dcb copyleft
libpam-runtime 1.7.0-5 pam 1.7.0-5 6b11ef9ab5429d9618cc72e8dfd4efefde363165ef174be0549918e0c44f5dcb copyleft
libpam0g 1.7.0-5 pam 1.7.0-5 6b11ef9ab5429d9618cc72e8dfd4efefde363165ef174be0549918e0c44f5dcb copyleft
libpcre2-8-0 10.46-1~deb13u3 pcre2 10.46-1~deb13u3 e915cde4251f96ec6af107ecd2e194440a4e69440893b0c982802f8a1e4ae40a -
libseccomp2 2.6.0-2 libseccomp 2.6.0-2 6da0653a365b80ab31478dbfe9e7c358e80d58b6d2b52b4e16b4dbb42d7d9f5c copyleft
libselinux1 3.8.1-1 libselinux 3.8.1-1 864f1bb189f609075d580b8c4aada16d85a44546884f1687989e1cacc8c56751 copyleft
libsemanage-common 3.8.1-1 libsemanage 3.8.1-1 fe5876a94047cafbeb8b164fd98304912d94b6028e19415f08b7a8a2f90645fe copyleft
libsemanage2 3.8.1-1 libsemanage 3.8.1-1 fe5876a94047cafbeb8b164fd98304912d94b6028e19415f08b7a8a2f90645fe copyleft
libsepol2 3.8.1-1 libsepol 3.8.1-1 78d2a34606a0302057ec499a3b3c07bcbc43ca334064ce4c80891a0f69c8f6c6 copyleft
libsmartcols1 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
libsqlite3-0 3.46.1-7+deb13u2 sqlite3 3.46.1-7+deb13u2 7b1679aaa97e6e49ec12460eefa85a82b432053bc468dd89dbdb50f2326589f3 copyleft
libssl3t64 3.5.7-1~deb13u3 openssl 3.5.7-1~deb13u3 6a7da622fe0637a334d2a8fc470852d2ffb77d9a2b2f930f854e32a41ad6ef35 copyleft
libstdc++6 14.2.0-19 gcc-14 14.2.0-19 20390f8a6f3b1e4d7cb45dd8652dabb259bbef688cbad839bcdb0b9ba7252f79 copyleft
libsystemd0 257.13-1~deb13u1 systemd 257.13-1~deb13u1 a79e4b379cabbd960bb44f6cc1a069081a3778c59a25ee529b68df5a2cb7d27d copyleft
libtinfo6 6.5+20250216-2 ncurses 6.5+20250216-2 f838d6048fbc59356b7e56c207a7cb32dc6bf4adea95514a002596bde8f6e1e7 -
libudev1 257.13-1~deb13u1 systemd 257.13-1~deb13u1 a79e4b379cabbd960bb44f6cc1a069081a3778c59a25ee529b68df5a2cb7d27d copyleft
libuuid1 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
libxxhash0 0.8.3-2 xxhash 0.8.3-2 81affefe3047c8a88a9e4c94c8c698f51a7e0787e75b58e901bf1f8fcd433f58 copyleft
libzstd1 1.5.7+dfsg-1 libzstd 1.5.7+dfsg-1 5cec9fef4d3fa7e0371fbef4ec3fc416e0105dc2a9922117f84e825cb11f50f8 copyleft
login 1:4.16.0-2+really2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
login.defs 1:4.17.4-2 shadow 1:4.17.4-2 305494b6f5f6bb65ead9160077d4fdf45ccdf06de7c958ff96f27a632b8729a3 copyleft
mawk 1.3.4.20250131-1 mawk 1.3.4.20250131-1 f6b94f461b09398ef192207356d89d7bf59833fe03082a14b910b3c740f2a318 copyleft
mount 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
ncurses-base 6.5+20250216-2 ncurses 6.5+20250216-2 f838d6048fbc59356b7e56c207a7cb32dc6bf4adea95514a002596bde8f6e1e7 -
ncurses-bin 6.5+20250216-2 ncurses 6.5+20250216-2 f838d6048fbc59356b7e56c207a7cb32dc6bf4adea95514a002596bde8f6e1e7 -
openssl-provider-legacy 3.5.7-1~deb13u3 openssl 3.5.7-1~deb13u3 6a7da622fe0637a334d2a8fc470852d2ffb77d9a2b2f930f854e32a41ad6ef35 copyleft
passwd 1:4.17.4-2 shadow 1:4.17.4-2 305494b6f5f6bb65ead9160077d4fdf45ccdf06de7c958ff96f27a632b8729a3 copyleft
perl-base 5.40.1-6+deb13u1 perl 5.40.1-6+deb13u1 8adf04cb72ca0719dee8fdb8d711768548d10373905eac21e8a640881c230257 copyleft
sed 4.9-2+deb13u1 sed 4.9-2+deb13u1 719320e425e8e6da53a55e0fcfa2f2ed9b1332cea16abd65321bd651b2a88568 copyleft
sqv 1.3.0-3+b2 rust-sequoia-sqv 1.3.0-3 b7ae2cde83ad585eae83cded853d125b034fcef480f6c4cee6d9ddd63327181a copyleft
sysvinit-utils 3.14-4 sysvinit 3.14-4 53c7ef3839f64b24cc25a0937d11ce228517a48be0cc794f0d67b7e209b2a9ba copyleft
tar 1.35+dfsg-3.1 tar 1.35+dfsg-3.1 a0a44d41b2a045eb5946a8952487151cfa6ff0cd080bbf4b2eec220751d23024 copyleft
tzdata 2026f-0+deb13u1 tzdata 2026f-0+deb13u1 cb61132bc0fc7b26ef5a82ee18b2fb644a1362f4f286ed980ff22e408471f59a -
util-linux 2.41.5-0+deb13u1 util-linux 2.41.5-0+deb13u1 56b67e2eb8bac5a15d91e261d558d73f1f029113cced229753138194997366b6 copyleft
zlib1g 1:1.3.dfsg+really1.3.1-1+b1 zlib 1:1.3.dfsg+really1.3.1-1 9e5b96d63773a5d177ba264254390f792be07e41748ebd94730981c6cac31cc6 -
```

## What this record does not establish

- It is not legal advice, and it does not say that any duty is met.
- Per-file licence mapping inside `modernc.org/libc` and `modernc.org/memory` was not done. The whole notice files are listed instead.
- Licences of the 15 unlinked modules (§1.3) were not read.
- For option (a): the Npcap OEM price and terms, Npcap's third-party PDF, Suricata's bundled components, and which of Zeek's third-party parts reach a Windows build are all `unknown`.
- Fetching the inventory downloaded `github.com/google/uuid` and the 15 unlinked modules into the module cache on the machine that ran it. `go mod verify` passed afterwards.
- For the engine image (§8):
  - the source packages and licences of the runtime stage's packages are `unknown`; their names and versions are from one build's log (§8.1);
  - that C2 holds no `bin/rst` rests on the build's install log; its `files-c2.txt` was not read;
  - which shared libraries `zeek` loads is `unknown` (its `ldd` was not read);
  - the Debian packages were not mapped file by file, only flagged from their copyright files;
  - GitHub's terms on who can download a public repository's artifacts were not read; the job's artifact is treated as a distribution (D4-114 item 4.3);
  - how the two image stores set the image ID, which entries `docker export` adds, and whether the `docker save` layers carry `security.capability`, were not read from Docker's documentation (§8.2; §8.4 item 1's controls settle the last);
  - what glibc and OpenSSL load with `dlopen` in the shipped image is not checked (§8.4 item 1);
  - no image of option (C) exists, no source bundle exists, and no image has been kept from a run.
