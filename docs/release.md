# Release record

Owner: D7 (brief P4-D7-1). Reviewers: D3 (the update path and the supply-chain rows) and D6 (that every claim can be checked).

This file records what the two binaries contain and under which licences, and what a release still lacks. It is an inventory, not a release. Nothing here is compliant, certified or release-ready. No release of OTSEC has ever been built for distribution or shipped to a node.

**Evidence class: `desk`.** Every row was read on 2026-11-11 from `main` at `b383a242` (#611), from the Go toolchain's own output (Go 1.27.3, `windows/amd64` host), from the licence files in the Go module cache and the Go distribution, and, for the third-party programs, from upstream files downloaded on the same day. No test was run for this record.

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
      -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Sum}}{{end}}{{end}}' \
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
| `modernc.org/sqlite@v1.61.0` | `LICENSE-SQLITE` (SQLite, transpiled into `lib/`) | blessing (public-domain dedication) | `8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0` |

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

The owner chose option (a) on 2026-11-10 and said no work starts on it yet (D4-78). None of these programs is in the repository or in either binary. Under AP-31, a program a node runs is shipped in the signed release, is never fetched at install time, and is listed in the inventory.

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

- **Npcap.** The file says Npcap "is not open source software and may not be redistributed or used in other software without special permission from the Nmap Project". The free licence allows five systems and forbids redistribution and transfer without written consent. Shipping it in the release needs the "Npcap OEM Redistribution License". It also names three BSD-style components (libpcap, WinPcap, `ieee80211_radiotap.h`) whose acknowledgement text "be added somewhere in the documentation", and points to `npcap.com/src/docs/Npcap-Third-Party-Open-Source.pdf` for that text. **Not read:** the OEM licence's price and terms (D4's work, pending, which D1's brief for this record calls P4-4-A6; on `main` at `b383a242`, P4-4-A6 in `docs/agent-handoffs.md` is D6's GT-PCAP brief), and the third-party PDF (on `npcap.com`, not fetched).
- **Suricata.** GPLv2 §1 and §3: with each copy of the executable, give the licence text, and either the complete corresponding source, including "the scripts used to control compilation and installation", or a written offer of it valid for at least three years. §3(c), passing on the offer received, is for noncommercial distribution only. Running Suricata as a separate process does not put OTSEC's binaries under the GPL (ADR-0003, ADR-0009), but the Suricata binary that a release ships carries these duties. **Not read:** the third-party components inside Suricata's source and its Windows installer, and their licences.
- **Zeek.** `COPYING` is BSD-3-Clause: carry the notice, the conditions and the disclaimer. `COPYING-3rdparty` says it "may not contain the licenses of all third party software contained in Zeek". It lists code under MIT, BSD, Boost-1.0, Apache-2.0, MPL-2.0 (`mozilla-ca-list.zeek`), LGPL-3.0-or-later with its author's permission to use it in Zeek under BSD (Multifast), public domain (SQLite) and the JSON licence, whose term "The Software shall be used for Good, not Evil" is unusual. Which of these reach a Zeek build for Windows is `unknown`: no official Zeek binary for Windows was found (ADR-0009). Shipping Zeek means carrying `COPYING`, the notices in `COPYING-3rdparty` that apply to the build, and the MPL-2.0 file's source.
- **ICSNPP-DNP3 and ICSNPP-Modbus.** BSD-3-Clause: carry the notice, the conditions and the disclaimer. Their READMEs were not read again for this record.

## 5. What does not exist yet

A list only. No design is in this brief.

1. **Release signing and the key's holder.** TB9 requires an offline release key that is not present on central. Who holds it and where it is kept is owed by the owner (`HANDOFF.md`, item 12). No key, real or test, exists for releases. HR-18 (the advisory set's key, recommended never to be the release key) is not decided either.
2. **The SBOM.** None is generated. Proposed format, for D1 to decide: one CycloneDX 1.6 JSON document per release and target, built from `go version -m` of the release binaries, with the non-Go components of option (a) (Npcap, the engine, its decoders) added by hand, and signed with the release.
3. **The update package's contract.** Not opened. D7 drafts it when D1 opens it, and D1 approves it. D5 builds the node's update verifier.
4. **The anti-rollback floor.** Not designed. AP-10's three refusals (a tampered package, a signed package below the floor, an unsigned package) have no code and no test.
5. **The record of which versions upgrade and roll back together** (R8.7). No release exists, so it has no rows. One entry is already owed from D4-61: the node's refusal of an `otsec.finding/` minor that `finding.Known` does not name (#507, `3c6b8a7b`) must be in every build a node can roll back to before any node writes C12 0.2 (#511, `a37a5e8c`; `finding.Identifier` is `otsec.finding/0.2` on `main`). No build has ever been released, so no release before `3c6b8a7b` exists. The record must keep any such build out of a rollback set.
6. **A release build.** ADR-0003 names `CGO_ENABLED=0 go build -trimpath` from a pre-installed pinned toolchain, pinned by `go.mod`'s `go` and `toolchain` lines. `go.mod` has a `go 1.27.3` line and no `toolchain` line. No workflow runs a release build. CI's integration job builds without `-trimpath`, and `cmd/otsec` with the test tag `otsec_testclock`. Neither is a release build.
7. **The project's own licence.** The repository has no `LICENSE` file. It is the owner's decision, and it decides what the notices file says about OTSEC itself.

## 6. How the inventory is kept true

The block between the two marker lines `inventory:begin` and `inventory:end` in §1.2 is the command's output, sorted per target and binary. It shows that this file and `go.sum` disagree when, at the repository root, the output of the §1 command differs from the block:

```sh
# the markers are anchored to whole lines, so this text's own mentions of them do not match
sed -n '/^<!-- inventory:begin -->$/,/^<!-- inventory:end -->$/p' docs/release.md | grep -v '^<!--' | grep -v '^```' > recorded.txt
# run the §1 loop into generated.txt
diff recorded.txt generated.txt   # empty when they agree
```

- The `h1:` field comes from `go.sum`, so a module bump, a changed hash, or a module that starts or stops being linked on any target shows as a diff.
- Two more lines belong in the same check: `go version` must report the version in §1.1, and that version must equal `go.mod`'s `go` line.
- A licence change inside a bumped module does not show in that diff. The check for it recomputes the SHA-256 of every file named in §2 and compares it with the table.
- D6 may turn this into a test. This record does not write it.

Every toolchain or dependency bump updates this file in the same PR, and D7 reads the new component's licence (D7's role file).

## What this record does not establish

- It is not legal advice, and it does not say that any duty is met.
- Per-file licence mapping inside `modernc.org/libc` and `modernc.org/memory` was not done. The whole notice files are listed instead.
- Licences of the 15 unlinked modules (§1.3) were not read.
- For option (a): the Npcap OEM price and terms, Npcap's third-party PDF, Suricata's bundled components, and which of Zeek's third-party parts reach a Windows build are all `unknown`.
- Fetching the inventory downloaded `github.com/google/uuid` and the 15 unlinked modules into the module cache on the machine that ran it. `go mod verify` passed afterwards.
