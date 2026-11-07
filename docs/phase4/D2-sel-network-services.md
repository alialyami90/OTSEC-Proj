# What the SEL families put on the wire (P4-4-A2)

D2, 2026-11-07. This note answers brief P4-4-A2 in `docs/agent-handoffs.md` (item 4, Stage A, D4-66). It gives GT-PCAP (D6, #527) and R6.7 the network services of each SEL family in the capability matrix (`docs/device-capabilities.md`, "Collection-method rungs"). For each family it lists:

- each service, with its protocol and port, its factory default, and the setting that turns it on;
- whether the service is on the insecure list;
- what a passive sensor can read in clear for identity (R1.1, R6.7).

**Evidence class.** Every cell is `desk`. It was read from the owner-supplied manuals in `/mnt/project-files/phase0/manuals-SEL/` (S22 to S43, `docs/phase0/A2-sel-portfolio.md` §1). Nothing was taken from the web (D4-58), and no device was contacted. A service is `unknown` where its manual is silent, and `unsupported` where the device's own list of ports or protocols leaves it out, as in the matrix. Page numbers are the manual's own, and a table or setting name is given wherever the manual has one. A port written "fixed" is one the manual says can't be changed.

**Families covered.** These are the nine families the matrix holds:

- the SEL-751 (S22) and SEL-787-4 (S34);
- the SEL-400 series (S32);
- the SEL-311L (S33);
- the SEL RTAC: the SEL-3505, SEL-3530 and SEL-3555-2 with SEL-5033 software (S23, with hardware S36 to S38);
- the SEL-2488 (S26) and SEL-2730M (S43);
- the SEL-2731 and SEL-2741 (S27 and S28, managed per S29 in RSTP mode and S30 in OT SDN mode);
- the SEL-3355-2 (S25).

The portfolio's S31 (SEL-5056) and S39 to S42 (SEL-3350, SEL-3610/3620/3622, SEL-735, SEL-2401/2404/2407) are not in the matrix, so they are not covered here.

## The insecure list (R6.7, V-M6)

The list is: Telnet, FTP, plain HTTP, SNMPv1 and v2c, unauthenticated Modbus/TCP, and DNP3 without Secure Authentication. In the tables below, **Insecure** is `yes` for a service on that list and `no` for one that isn't. It is `see note` where the answer depends on a setting.

None of these families documents Modbus/TCP security, so every Modbus/TCP service below is `yes`. Of the nine families, only the RTAC documents DNP3 Secure Authentication (S23 pp. 73–74, SA version 5, from firmware R143). Every other DNP3 service is therefore `yes`.

**Platform's own sessions.** The platform's own SEL Telnet and SNMPv3 sessions are a known flow for the baseline and the unknown-flow alerts, but they are still recorded as an insecure service where the list says so (#522). SNMPv3 is not on the list. SEL Telnet is.

## SEL-751 (S22)

Every network service is on Port 1, the Ethernet port. Its settings are in Table 4.104, "Ethernet Port Settings", pp. 4.249–4.251. Port 1 supports these protocols (Table 7.5 p. 7.13):

- Modbus TCP/IP, FTP, IEC 61850, DNP3 LAN/WAN, SNTP, EtherNet/IP and PTP;
- Telnet, which carries SEL ASCII, Compressed ASCII, SEL Fast Meter, Fast Operate, Fast SER and Fast Message;
- the web server (HTTP);
- C37.118 synchrophasors;
- PRP, HSR and RSTP.

| Service | Protocol and port | Default | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| Telnet (SEL ASCII, and the SEL Fast protocols inside it) | TCP `TPORT`, 23 by default (23 or 1025–65534) | **on** (`ETELNET := Y`, `MAXACC := 2`, `TIDLE := 15`) | `ETELNET` (p. 4.250) | yes |
| SEL Fast Operate inside the Telnet session | the Telnet port | off (`FASTOP := N`) | `FASTOP` (p. 4.250) | yes, as part of Telnet. It is a control path in clear. |
| FTP server | TCP 21, and 20 for active data (fixed, p. 4.251) | **on** (`EFTPSERV := Y`, `FTPACC := 2`, `FTPUSER := FTPUSER`, `FTPIDLE := 5`) | `EFTPSERV` (p. 4.250) | yes |
| Web server | TCP `HTTPPORT`, 80 by default (1–65535). No HTTPS in S22. | **on** (`EHTTP := Y`, `HTTPACC := 2`, `HTTPIDLE := 10`) | `EHTTP` (p. 4.251) | yes (plain HTTP) |
| IEC 61850 MMS | TCP 102 (fixed, p. 4.251) | off (`E61850 := N`) | `E61850` (p. 4.250); MMS file services `EMMSFS := N` | no |
| IEC 61850 GOOSE | layer 2 multicast, no IP | off (`EGSE := N`); fixed GOOSE `EFGTX := 0`, `EFGRX := 0` | `EGSE` (hidden unless `E61850 := Y`) | no |
| Modbus TCP | TCP `MODNUM1` and `MODNUM2`, 502 by default | off (`EMOD := 0`, 0 to 2 sessions) | `EMOD` (p. 4.250). `MODIP1` and `MODIP2` default to 0.0.0.0, which "effectively disables security and allows any master to communicate" | yes when on |
| DNP3 LAN/WAN | TCP and UDP `DNPNUM`, 20000 by default; per session `DNPTR` TCP or UDP, `DNPUDP` 20000 | off (`EDNP := 0`, 0 to 5 sessions) | `EDNP` (p. 4.251; Table D.7 p. D.11) | yes when on (no SA documented) |
| C37.118 synchrophasors | TCP or UDP, `PMOTS1` and `PMOTCP1` | off (`EPMIP := 0`) | `EPMIP` (p. 4.251; Appendix K) | no |
| SNTP client | UDP `SNTPPORT`, 123 by default | off (`ESNTP := OFF`; UNICAST, MANYCAST or BROADCAST) | `ESNTP` (p. 4.251; Table 7.6 p. 7.17) | no |
| PTP | UDP 319 and 320 (reserved, Table 4.105 p. 4.252) | off (`EPTP := N`) | `EPTP` (p. 4.251) | no |
| EtherNet/IP | 2222 and 44818 (reserved, Table 4.105 p. 4.252) | off (`EEIP := N`) | `EEIP` (p. 4.251) | no |
| RSTP | layer 2 | off (`ERSTP := N`) | `ERSTP` | no |
| PRP or HSR | layer 2: PRP trailer, or HSR tag | `NETMODE := FAILOVER` (FIXED, FAILOVER, SWITCHED, PRP or HSR) | `NETMODE` (p. 4.250) | no |
| SNMP, Syslog, SSH, SFTP, HTTPS, TLS | — | `unsupported`: left out of the Port 1 list (Table 7.5), and in none of the settings. This follows the matrix's rule: a protocol the device's own list leaves out is `unsupported`. | — | — |

The relay refuses a duplicate port setting, and any port setting equal to one of its fixed ports, 20, 21, 23, 102 and 502 (p. 4.251).

**Three services are on by default, and all three are on the insecure list:** Telnet, FTP and HTTP. Each one takes the Level 1 or Level 2 password in clear. How the web server takes it is not stated: S22 and S34 show only a login page offering Access Level 1 or 2 (p. 3.2 in each). Whether it is an `Authorization: Basic` header or a form POST is therefore `unknown`, and GT-PCAP carries both cases (D6 on #528).

**Identity in clear.**

- **`ID` at Level 0** (Table 7.43, Figure 7.38 p. 7.64) returns FID, BFID, CID, DEVID, DEVCODE, PARTNO and CONFIG. Any Telnet client can send it before logging in, so a third party's session can show it too. There is no serial number in the reply.
- **Banners.** `TCBAN` (default "TERMINAL SERVER"), `FTPCBAN` (default "FTP SERVER") and `HTTPBAN` are operator settings of up to 254 characters (p. 4.250). They are weak evidence: anyone can set them.
- **`CFG.TXT` over FTP** carries RELAYTYPE, FID, BFID and PARTNO (Figure 7.46). It shows in clear when any client retrieves it.
- **IEC 61850 MMS, when a client reads the nameplate:**
  - `DevIDLPHD1` gives `PhyNam.model` = PARTNO, `PhyNam.serNum` = the serial number, and `PhyNam.HwRev` (p. G.73);
  - `LLN0 NamPlt` gives vendor "SEL" and `swRev`, which is "Contents of FID string from ID command" (Table G.46 p. G.78).

  This is the only cleartext source of the serial number found in S22.

## SEL-787-4 (S34)

The SEL-787-4 has the same Port 1 model as the SEL-751, in Table 4.65, "Ethernet Port Settings", pp. 4.137–4.139. The defaults are the same:

- Telnet on: `ETELNET := Y`, `TPORT := 23`, `TCBAN := TERMINAL SERVER`.
- FTP on: `EFTPSERV := Y`, `FTPACC := 2`.
- HTTP on: `EHTTP := Y`, `HTTPACC := 2`, `HTTPPORT := 80`.
- Off: `E61850 := N`, `EGSE := N`, `EMMSFS := N`, `EMOD := 0` (`MODNUM1/2 := 502`), `ERSTP := N`, `EPMIP := 0`, `EDNP := 0` (`DNPNUM` 20000, Table D.7 p. D.11), `ESNTP := OFF` (`SNTPPORT := 123`, Table 7.5 p. 7.18), `EPTP := N` and `EEIP := N`.

The fixed and reserved ports are the same as the SEL-751's: 20, 21, 23, 102 and 502, PTP 319 and 320, and EtherNet/IP 2222 and 44818 (Table 4.66 pp. 4.139–4.140).

Two differences from the SEL-751:

- `NETMODE` offers FIXED, FAILOVER, SWITCHED and PRP, with no HSR (p. 4.137).
- The Port 1 protocol list (Table 7.4 p. 7.13) leaves out the web server, while Table 4.65 has `EHTTP` and Section 3 describes the web server (p. 3.2). This note takes the settings table: HTTP is documented and on by default.

SNMP, Syslog, SSH, HTTPS and TLS are `unsupported`, as for the SEL-751: they are left out of Table 7.4.

The insecure services are the same as the SEL-751's: Telnet, FTP and HTTP by default, and Modbus and DNP3 when they are turned on.

**Identity in clear.** `ID` at Level 0 (Table 7.31 p. 7.53); its fields were not re-read here. In MMS, `PhyNam.model` = PARTNO and `PhyNam.serNum` (p. G.74), and the nameplate gives vendor "SEL" and `swRev` = FID (Table G.41 p. G.79). The banners and `CFG.TXT` are as for the SEL-751.

## SEL-400 series: SEL-451, SEL-411L and SEL-400G (S32)

All IP services are on Port 5. **On the Ethernet ports, "IP" means FTP, HTTP, Telnet, SNTP, MMS, DNP and IEEE C37.118** (Table 15.4 note a, p. 15.7). Which card ports carry IP, PRP, HSR, PTP, GOOSE, SV and 87L depends on the card (Table 15.4). The two-port card's settings are Tables 12.14 to 12.26 (pp. 12.12–12.16). The five-port card's are Tables 12.27 to 12.33 (pp. 12.16–12.19), where each service is enabled per interface instead of Y or N, and every one defaults to `OFF` or `N`.

| Service | Protocol and port | Default (two-port card) | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| Telnet (SEL ASCII and Fast protocols) | TCP `TPORT`, 23 by default | off (`ETELNET := N`, `TCBAN := TERMINAL SERVER:`) | `ETELNET` (Table 12.17 p. 12.12) | yes |
| FTP server | TCP (port not stated in these tables) | off (`FTPSERV := N`). Anonymous login `FTPANMS := N`: "The Ethernet card does not require a password for the special FTP username 'anonymous'" when it is on | `FTPSERV` (Table 12.15 p. 12.12) | yes |
| HTTP server | TCP `HTTPPOR`, 80 by default | off (`EHTTP := N`) | `EHTTP` (Table 12.16 p. 12.12) | yes (plain HTTP) |
| IEC 61850 MMS, GOOSE, SV | MMS port not stated in S32; GOOSE and SV at layer 2 | off (`E61850 := N`, `EGSE := N`, `EMMSFS := N`) | `E61850` (Table 12.18 p. 12.13) | no |
| DNP3 LAN/WAN | TCP and UDP `DNPPNUM`, 20000 by default (1025–65534) | off (`EDNP := 0`, 0 to 6 sessions) | `EDNP` (Table 12.23 p. 12.14) | yes when on (no SA documented) |
| C37.118 | TCP `PMOTCP1` 4712, UDP `PMOUDP1` 4713 (output 2: 4722 and 4714) | off (`EPMIP := N`) | `EPMIP` (Table 12.24 p. 12.15) | no |
| SNTP client | UDP `SNTPPOR`, 123 by default | off (`ESNTP := OFF`) | `ESNTP` (Table 12.25 pp. 12.15–12.16); not on the five-port card's PORT E (Table 15.4 note f) | no |
| PTP | — | off (`EPTP := N`) | `EPTP` (Table 12.26 p. 12.16) | no |
| Modbus TCP | TCP `MODNUM1/2`, 502 by default | off (`EMOD := 0`) | SEL-400G only: `EMOD` (S32 SEL-400G part, Table 8.84 p. 8.31). Not in the SEL-451 or SEL-411L parts, and missing from Table 15.4 note a, although Table C.2 (p. C.6) gives the series "Modbus 2 sessions". `unknown` for those two. | yes when on |
| SNMP, Syslog, SSH, HTTPS | — | `unsupported`: left out of Table 15.4 note a's IP list, and in none of the port settings | — | — |

**Nothing is on by default** on the two-port card (pp. 12.12–12.16). Every IP service is something a site turns on. Table C.2 (p. C.6) gives the session limits: DNP 6, FTP 1, MMS 7, Telnet 3, Modbus 2, HTTP 1, PTP 2, SNTP 1 and synchrophasors 2.

**Identity in clear.**

- **`ID` at Level 0** (Table 14.88 p. 14.42) over Telnet.
- **`CFG.XML` over FTP** carries the firmware identification (p. 15.22).
- **MMS:** `LLN0 NamPlt.swRev` = VERFID, the relay FID string (p. 17.64). `DevIDLPHD1 PhyNam.serNum` = SERNUM, the serial number (p. 17.64). The nameplate gives vendor "SEL" (Table 17.39 p. 17.93).
- **DNP3 Object 0 device attributes**, sent to any master that reads them (p. 16.19):
  - variation 245 is the `SID` setting;
  - variation 246 is the `DNPID` port setting, default "RELAY1-DNP" (Table 12.23);
  - variation 247 is the `RID` setting.

  The firmware release notes add variation 242, which reports the firmware V-number (SEL-451 part, p. A.15).

## SEL-311L (S33)

Ethernet is an optional card, and the card's own manual is not in hand. S33 names Port 5 only in its card-firmware upgrade steps (pp. B.17–B.19), which use these settings: `ETELNET = Y`, `TPORTC = 1024`, `EFTPSERV = Y` and `FTPUSER = 2AC`. The same pages mention IEC 61850 with a CID file (p. B.19).

| Service | Protocol and port | Default | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| Telnet | TCP (port not stated in S33) | `unknown` | `ETELNET` (p. B.18) | yes |
| FTP | TCP (port not stated) | `unknown` | `EFTPSERV` (p. B.18) | yes |
| IEC 61850 | — | `unknown` | a CID file (p. B.19) | no |
| DNP3 | serial only: "You can use DNP on serial ports, Port 1–Port 3" (p. F.8) | — | — | not a network service |
| Syslog | "The SEL-311L does not support Syslog functionality" (p. K.6) | — | — | — |
| HTTP, SNMP, Modbus TCP, SNTP and everything else on the card | `unknown` | `unknown` | `unknown` | — |

**Identity in clear.** `ID` at Level 0 (p. 10.22), over the card's Telnet. Everything else is `unknown` until the card's manual is in hand.

## SEL RTAC: SEL-3505, SEL-3530 and SEL-3555-2 with SEL-5033 (S23)

An RTAC opens only what its project configures, apart from a short default list. The defaults are "Logical Ports" (pp. 1135–1136):

| Port | Service | Default | Turned on or off by | Insecure |
| --- | --- | --- | --- | --- |
| TCP 443 | HTTPS web interface and API | **on**, per Ethernet interface | "Enable Web Access" per interface (Table E.3 p. 1135) | no |
| TCP 80 | HTTP, which only redirects to 443 | off | "Enable HTTP Redirect", "Disabled by default" (Table 8.3 p. 609) | `see note` |
| TCP 5432 | ACSELERATOR RTAC project upload and download, ODBC over TLS (p. 602) | **on**, per interface | "Enable Database Access" per interface (Table E.3) | no |
| TCP 1217 | opened after an ACSELERATOR RTAC connection on 5432, "locked to the specific IP address that initiated the request" | while connected | none: "There is no user setting to close this port" | no |
| TCP 5433 | firmware upgrade | temporary | — | no |
| TCP 15453 | Comm Monitor Ethernet capture | while capturing | — | no |
| UDP 123 | SNTP | **on** | `Enable_NTP_Time_In` in `System_Time_Control` (p. 1136) | no |
| UDP 319, 320 | PTP | off | `Enable_PTP_Time_In` (p. 1136) | no |

Note on port 80: with the redirect on, the only plain-HTTP exchange is the redirect itself, and nothing in the manual says it carries a credential. Whether a redirect that carries no credential counts as plain HTTP on the list is a ruling for D1 and the owner (D6 on #528). It applies equally to the SEL-2488, SEL-2730M and SEL-2731 redirects. Until it is ruled, the list applies as written: plain HTTP.

Services the project adds, each off until configured:

| Service | Protocol and port | Turned on by | Insecure |
| --- | --- | --- | --- |
| DNP3 server | TCP 20000 by default, configurable; "not opened if no DNP server is configured" (Table E.4 p. 1136) | a DNP server in the project | yes, unless Secure Authentication is enabled (SA v5 from R143, p. 73). Under SA, "by default, read commands do not prompt challenges" (p. 74). |
| Modbus TCP server | TCP 502 by default, configurable (Table E.4) | a Modbus session in the project | yes |
| OPC UA server | TCP 4840 by default (Table E.4; p. 292) | the project | `unknown`: a setting allows or disallows anonymous connections (p. 292); the security mode was not read |
| IEC 60870-5-104 | TCP 2404 by default (`Portnumber`, p. 164, p. 183) | the project | not on the list. See "Not on the list" below. |
| IEC 61850 MMS server and client, GOOSE | port not stated; GOOSE at layer 2 | licensed options set at the factory (p. 195) | no |
| FTP or SFTP server | FTP or SFTP, one mode per project. There is no FTPS: "does not support FTP over SSL/TLS" (p. 116). | an FTP server POU in the project | yes in FTP mode, no in SFTP mode |
| Engineering access (pass-through) | Telnet or SSH, "configurable" (p. 602); the listening port is set in the project | an incoming access point (example on p. 408) | yes for Telnet, no for SSH |
| Tunnelled serial | raw TCP, Telnet, SSL/TLS or SSH (p. 603) | the project | yes for Telnet, `see note` for raw TCP |
| SNMP agent | v2c or v3 "as of firmware version R154" (p. 354); port not stated | an SNMP server in the project | yes for v2c |
| Syslog | outbound, RFC 3164 (p. 635), UDP, with a custom destination port allowed (release notes, p. 900); the default port is not stated. The Syslog Collector listens on UDP or TCP (p. 844). | a Syslog destination in the web interface | no |
| LDAP and RADIUS clients | outbound; LDAP 389 "unless your LDAP administrator specifies" (p. 629); RADIUS UDP 1024–65534 (p. 632) | the web interface | `unknown`: TLS for LDAP was not read |

Note on raw TCP: a raw TCP tunnel carries whatever serial protocol is inside it in clear, and is not itself on the list.

**Identity in clear.**

- The Syslog HOSTNAME, which is operator-set (p. 636).
- An SNMPv2c agent's MIB values: firmware version and host name (p. 355).
- An SNMPv3 agent's `msgAuthoritativeEngineID` in the message header.
- The HTTPS server certificate in the TLS handshake. By default it is "a single self-signed X.509 certificate" (p. 1138). Its subject fields are not stated, and whether TLS 1.3, which encrypts the certificate, is offered is `unknown`. The release notes record only that TLS 1.0 and 1.1 were removed.

## SEL-2488 (S26)

"All TCP/UDP ports can be disabled, and all are disabled by default (except for HTTPS and Captive Port [DHCP] on the ETH F interface)" (Table I.1 p. I.1). Only the front-panel port ETH F is enabled by default.

| Port | Service | Default | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| UDP 68 | DHCP, on ETH F only | **on** | Enable DHCP | no |
| TCP 443 | HTTPS web management | **on** on ETH F only (Table I.1 note a) | Enable Web Management | no |
| TCP 80 | redirects to 443 | **on** on ETH F only | Enable Web Management | `see note` (RTAC) |
| UDP 123 | NTP server | off | Enable NTP server | no |
| UDP 161 | SNMP, read-only; v2c and v3 (p. 18.6). A new profile defaults to v2c, and a v3 profile's authentication defaults to None (Table 19.1 p. 19.3). | off | Enable SNMP | yes for v2c. A v3 profile left at its defaults is noAuthNoPriv; see "Not on the list". |
| UDP 319, 320 | PTP UDP mode | off | Enable PTP UDP mode | no |
| SNMP traps (outbound) | v2c only: "An SNMP v2c profile is required before you can configure an SNMP trap server" (p. 19.3) | off | a trap server | yes |
| Syslog (outbound) | three destinations, port "fixed to the default port for the Syslog Protocol (514)" (p. 18.4); transport not stated | off | Syslog settings | no |
| LDAP (outbound) | "protected by use of TLS" (p. I.2) | off | LDAP settings | no |

There is no Telnet, FTP or command-line service (Table I.1). There are no default accounts: the first administrator is created when the device is commissioned (p. I.1).

**Identity in clear.** SNMPv2c responses (dashboard status; the OIDs are `unknown` until the device's own MIBs are read, p. 19.6). The v3 `msgAuthoritativeEngineID`. The Syslog header. The HTTPS certificate, as for the RTAC.

## SEL-2730M (S43)

"By default, only the web-based engineering access is enabled on the front port and SNMP is disabled on both" (p. 156).

| Port | Service | Default | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| TCP 80 | redirects to HTTPS | **on** on ETH F | web access setting | `see note` (RTAC) |
| TCP 443 | HTTPS web interface | **on** on ETH F | web access setting | no |
| UDP 161 | SNMP read-only: v1, v2c and v3 ("supports SNMPv1, SNMPv2c, and SNMPv3 read-only operations", p. 80) | off | SNMP setting | yes for v1 and v2c |
| SNMP traps (outbound) | trap servers (Table 5.15 p. 85) | off | trap server settings | yes for v1 and v2c |
| Syslog (outbound) | three destinations, UDP 514 (p. 127) | off | Syslog Settings (p. 86) | no |
| NTP client (outbound) | NTPv4, backward compatible to v2 (p. 92) | off | Enable NTP Client | no |
| RADIUS (outbound) | UDP, "typically 1812" (p. 44) | off | RADIUS settings | no |
| LDAP (outbound) | Appendix D | off | LDAP settings | `unknown` |

The switch "does not support any external file systems" (p. 156). No Telnet or SSH server is documented: the one Telnet and SSH mention, p. 49, is about engineering traffic passing through the switch's VLANs.

**Identity in clear.**

- SNMPv1 and v2c responses, including the FID in the Entity MIB (p. 155; column not stated).
- The v3 `msgAuthoritativeEngineID`.
- The Syslog header.
- The HTTPS certificate.

## SEL-2731 and SEL-2741 (S27 and S28; S29 in RSTP mode, S30 in OT SDN mode)

**RSTP mode (S29).** The ports are the same as the SEL-2730M's: 80 (redirect) and 443 on by default on ETH F, and 161 SNMP read-only off (p. 76). There are no external file systems (p. 76).

| Service | Protocol and port | Default | Turned on by | Insecure |
| --- | --- | --- | --- | --- |
| SNMP | UDP 161, v2c and v3 (p. 42; specifications p. 3). Version 3 requires a cryptographic algorithm and has no DES (p. 43; Table 4.13 p. 45). | off | SNMP setting | yes for v2c |
| Syslog (outbound) | RFC 3164 (p. 66), UDP, destination port 514 by default, 1–65535 (p. 49) | off | Syslog destination | no |
| NTP client (outbound) | NTP (p. 52) | off | NTP setting | no |
| LDAP (outbound) | port 389 "unless a different port number is specified" (p. 19). Binds need X.509 (p. 16). | off | LDAP settings | no |
| RADIUS (outbound) | UDP, "typically 1812" (p. 23) | off | RADIUS settings | no |
| PTP transparent clock | licensed option (p. 9; Table 4.8 p. 41) | off | licence and Table 4.8 | no |

**OT SDN mode (S30).** The ports are in Table D.1 (p. 24):

| Port | Service | Default | Notes | Insecure |
| --- | --- | --- | --- | --- |
| UDP 3002 | commissioning | **on** until commissioned | "Once commissioned, the port is disabled and can only be enabled again in a factory-default reset state" | `unknown` (the protocol is not described) |
| TCP 443 | HTTPS REST interface for the SEL-5056 | **on** | — | no |
| UDP 161 | SNMP read-only, v2c and v3 (p. 7) | off | v2c community "defaults to 'public'" if none is given (p. 7) | yes for v2c |
| TCP 6653 (outbound) | OpenFlow 1.3 to the flow controller, over TLS (pp. 6, 24) | after adoption | — | no |
| Syslog (outbound) | UDP (RFC 3164 or 5424) or TLS (RFC 5424 over 5425) (p. 7) | set by the SEL-5056 | — | no |

**Identity in clear.**

- RSTP mode: as the SEL-2730M. The FID is in the Entity MIB (S29 p. 75). Its letter after the product number gives the mode (pp. 7–8).
- OT SDN mode, before commissioning: the switch "publish[es] an OpenFlow discovery packet every few seconds", structured as LLDP. It is layer 2, and it "announces the presence of a new SDN switch and provides the default IP address" (S30 p. 5). It stops once the switch is adopted.
- SNMPv2c responses, and the v3 engine ID.

## SEL-3355-2 (S25)

The computer "and associated device drivers have no logical ports open by default". The operating system and applications open them, so they are outside SEL's documentation (Appendix C, p. C.6). ADR-0006 gives this family vendor-neutral coverage. The one SEL-defined network surface is Intel AMT on ETH 1 (Table C.2 p. C.6). It is off by default: "The default setting for Intel AMT is disabled, which disables all associated ports."

| Port | Service | Turned on by | Insecure |
| --- | --- | --- | --- |
| 623 | ASF-RMCP (DASH/DMTF) | Intel AMT enabled | `unknown` (not on the list; a management protocol) |
| 664 | ASF-RMCP over TLS | Intel AMT enabled | no |
| 5900 | KVM (VNC server) | the port 5900 setting | `unknown` (not on the list; see below) |
| 16992 | AMT web management over HTTP | Intel AMT enabled | yes (plain HTTP) |
| 16993 | AMT web management over HTTPS | TLS | no |
| 16994 | KVM, SOL and storage redirection | Redirection | `unknown` |
| 16995 | the same over TLS | Redirection and TLS | no |

SNMP comes from the Windows SNMP Service with the SEL SysMon extension (p. 7.7). Its version is the operating system's: `unknown`.

**Identity in clear.** Nothing SEL-specific is documented. What the operating system and its services show is vendor-neutral.

## Identity a passive sensor can read: whose session it is

R6.7 and C12 treat a passive read differently depending on whose session it came from:

- **A third party's session** is independent of the platform's read, but unauthenticated. A host that can send from the relay's address can answer an `ID` or an Object 0 read with whatever it likes, so this evidence never outranks the collector's read (AP-34, D4 on #528). It covers an engineer's Telnet `ID`, an SCADA master's DNP3 Object 0 read, an MMS client reading the nameplate, an FTP retrieval of `CFG.TXT` or `CFG.XML`, an SNMP manager's v1 or v2c response, and the v3 engine ID in any manager's exchange.
- **The platform's own session** is not independent. C2's SEL-751 run sends `QUI` and then `ID` at Level 0 in its probe phase, so the FID it reads also crosses the wire in clear. The same holds for the engine ID in its SNMPv3 sessions. Read passively, that is the same evidence as the C2 result. It does not corroborate it, and it does not count twice in C12 (#522; D6's GT-PCAP plan §2C). The flow is still recorded as an insecure service (Telnet) where it is one.
- **Banners and Syslog hostnames are operator settings** (`TCBAN`, `FTPCBAN`, `HTTPBAN` and the RTAC hostname). They are weak evidence of identity, and can be set to anything.
- **The source MAC address's OUI** is in every frame. Which OUIs SEL uses is not in these manuals: `unknown`.

## Not on the list, but in clear or unauthenticated

The insecure list is the owner's (R6 brief). These services are documented above and are not on it, yet they carry control or identity data with no authentication documented in the manuals read. This note does not add them to the list. It raises them for D1 and the owner:

- **SEL Fast Operate inside Telnet** (`FASTOP`; SEL-751 p. 4.250). It is covered by the Telnet flag, but its control content is a different finding from a cleartext login.
- **IEC 60870-5-104** (RTAC, TCP 2404). No security is documented.
- **IEC 61850 MMS and GOOSE** (relays and RTAC). No IEC 62351 profile is documented in any of these manuals.
- **C37.118** (relays) and **EtherNet/IP** (SEL-751 and SEL-787-4).
- **SNMPv3 at noAuthNoPriv.** It is possible wherever v3 authentication can be set to None, and a new SEL-2488 v3 profile defaults to that (Table 19.1). It is as readable as v2c, and it has no community string to steal.
- **Raw TCP serial tunnels and Intel AMT's redirection and RMCP ports.**

## What this gives GT-PCAP and C13

The family tables are a prior, not labels. GT-PCAP labels insecure use from the traffic it records, by V-M6's rules. DNP3, for example, is labelled from an unchallenged critical function, never from a table's "yes when on" (#527). GT-PCAP uses these tables only to choose which services a simulator profile offers, and on which ports (D6 on #528).

- **Default-on services**, for D6's labels:
  - SEL-751 and SEL-787-4: Telnet 23, FTP 21 and HTTP 80.
  - RTAC: HTTPS 443, ODBC/TLS 5432 and SNTP UDP 123.
  - SEL-2488: HTTPS 443, the redirect on 80 and DHCP 68, on ETH F.
  - SEL-2730M and SEL-2731/2741 in RSTP mode: 443 and the redirect on 80, on ETH F.
  - SEL-2731/2741 in OT SDN mode: UDP 3002 until commissioned, and 443.
  - The SEL-400 series and the SEL-3355-2: none.
- **Ports that are settings**, so detection must not rely on them alone:
  - SEL-751 and SEL-787-4: `TPORT`, `HTTPPORT`, `MODNUM1/2`, `DNPNUM`, `SNTPPORT` and the PMU ports.
  - SEL-400: `TPORT`, `HTTPPOR`, `DNPPNUM`, `SNTPPOR` and the PMU ports.
  - RTAC: the DNP3, Modbus, OPC UA, IEC 104 and access-point ports.
  - SEL-2731 in RSTP mode: the Syslog destination port.
- **Values a moved port can't take.** On the SEL-751 and SEL-787-4, a moved port can't equal another port setting or a fixed port (20, 21, 23, 102, 502), and `TPORT` is 23 or 1025–65534.

## Unknown, and what would settle it

- The SEL-311L's Ethernet card services and their defaults. This needs the card's manual.
- The SEL-400's FTP and MMS port numbers, and whether the SEL-451 and SEL-411L offer Modbus TCP.
- The RTAC's MMS, SNMP and Syslog default ports, and the security mode of its OPC UA server.
- Whether the RTAC, SEL-2488, SEL-2730M and SEL-2731 offer TLS 1.3, which decides what the certificate shows a passive sensor.
- The SEL-751's and SEL-787-4's DNP3 Object 0 attributes. S22 was not searched for them beyond a count.
- The SEL-2488's Syslog transport, and the SEL-2730M's LDAP transport.
- The OIDs that carry model and firmware on the SEL-2488, SEL-2730M and SEL-2731. The MIBs come from the devices.

Each of these is a document gap, not a test result. None of them changes a default-on service above.
