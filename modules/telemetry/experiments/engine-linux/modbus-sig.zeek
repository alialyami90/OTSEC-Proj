##! P4-4-E2 (D4): a Modbus/TCP content signature, as an experiment. It is
##! not adopted: D1 adopts it, or does not, on a counted run against D6's
##! pass conditions (D4-90). Loaded with probe.zeek in the `zeek-modbus-sig`
##! configuration only, which is "Zeek with the project's script and the
##! Modbus signature" in every table. It names no port, no address and no
##! capture (D6's rule 8), registers no port, and sets no option of Zeek's:
##! no `DPD::ignore_violations`, so S2 does not arise (D6's `cfg-alone`).
##!
##! What it matches. Zeek's Modbus analyzer is registered on 502/tcp only
##! (base/protocols/modbus/main.zeek at v9.0.1), so a server on another port
##! is not parsed (E-D4-03). modbus-sig.sig enables that same analyzer by
##! content, on any port, when the first payload of each side of a TCP flow
##! reads as Modbus/TCP ADUs (D2's strict check, notes 3 and 4 and finding G
##! on #637), in one of two orientations:
##!   - forward: the originator's are requests; the responder's are replies,
##!     and the first carries the first request's transaction ID and its
##!     function code, or that code plus 80h (an exception);
##!   - reversed, for a flow whose first frame is the server's (D4's N1 on
##!     #642; D1's ruling 6839544318): the originator's are replies and the
##!     responder's are requests. No transaction ID or code is compared: the
##!     first reply answers a request the capture does not hold.
##!
##! The framing it checks, and only this (D1's ruling 6839966277 on #642:
##! no narrower than the Modbus specification allows for a function code;
##! each check cites its clause, for D2 to confirm; neither specification
##! is in reference/, so each citation is `inference` until D2 labels it):
##!   [T1] MBAP header: transaction ID (any), protocol ID 0, length counting
##!        the unit ID and the PDU, unit ID (any). MODBUS Messaging on TCP/IP
##!        Implementation Guide V1.0b, section 3.1.3.
##!   [A1] A PDU is at most 253 octets, so a length is 2 to 254. MODBUS
##!        Application Protocol Specification V1.1b3, section 4.1.
##!   [A2] A request with function code 1 to 6 is the code and two 2-octet
##!        fields (starting address and quantity, or address and value), so
##!        its length is 6. Same specification, sections 6.1 to 6.6.
##!   [A3] A normal reply (code below 80h) to code 1 to 4 is the code, a
##!        byte count N and N octets, so its length is 3 + N. Sections 6.1
##!        to 6.4. Not applied to an exception reply (D6's `review-text`
##!        (e)): an exception is the code plus 80h and an exception code,
##!        section 7, and is accepted for every code it accepts.
##! Every other code it accepts with any length from 2 to 254.
##!
##! The codes it accepts: every code of fc-classes/1 (1 to 6, 8, 15, 16, 22,
##! 23, 43, 60h, 61h, 62h, 7Dh, 7Eh; modules/detection/netdetect/
##! fcclasses.go, D6's `review-text` (b)) and the other "Standard defined"
##! codes of Zeek's `Modbus::function_codes` (base/protocols/modbus/
##! consts.zeek at v9.0.1) except 5Bh, which Zeek cites to a separate
##! extension document.
##!
##! What Zeek gives an eval function, and what that means here (Zeek v9.0.1
##! src/RuleMatcher.cc, SHA-256 1be73e06...d545; src/RuleCondition.cc
##! l.150 to l.180): the conditions are evaluated only on a call in which a
##! pattern newly matches (RuleMatcher::Match, l.830), so once, on the
##! chunk of the reassembled stream in which the anchored pattern
##! completes, and `data` is that whole chunk (l.886 to l.890). A rule whose
##! `requires-reverse-signature` was not yet met is evaluated again, on the
##! same stored chunk, when the other side's rule fires (ExecRuleActions,
##! l.983 to l.989; ExecRule, l.1010 and l.1011). So:
##!   - a chunk holding several ADUs is read ADU by ADU (D2's finding G);
##!   - a chunk that ends partway through an ADU is checked as far as it
##!     goes, and the cut ADU is accepted on what it shows (D6's (c));
##!   - a chunk holding a header without its function code is accepted on
##!     the header, and its code is not compared with the reply's (D6's
##!     (c));
##!   - a first chunk of fewer than 6 octets cannot be read: the pattern
##!     then completes in a later chunk, whose octets are not the stream's
##!     first, and the side is most likely refused (a limit, not shown by
##!     any capture here).
##!
##! What it does on a parse violation. Nothing of its own. Once enabled,
##! the analyzer is Zeek's, and Zeek's stock DPD rule applies: a parse
##! violation in the first 10 KiB of the connection removes the analyzer,
##! conn.log drops `modbus` from `service`, and analyzer.log records the
##! violation (base/frameworks/analyzer/dpd.zeek at v9.0.1). A modbus.log
##! row written before that stays, and D6's `judge-named` counts it.
##!
##! Limits, by construction: only the first chunk of each side is read; both
##! sides must be seen, so a capture of one direction does not match; a
##! code outside the set (Schneider's 5Ah among them) does not match; Modbus
##! RTU or ASCII framing carried in raw TCP has no MBAP header and is not
##! meant to match.

@load-sigs ./modbus-sig.sig

module OtsecModbusSig;

export {
	## The function codes accepted (see the header).
	const codes: set[count] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C,
		0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B,
		0x60, 0x61, 0x62, 0x7D, 0x7E,
	};
}

## The code of an ADU whose header arrived without its function code.
const UNSEEN = 256;

## The first request's transaction ID and function code, by connection,
## kept until the responder's first payload is read (forward orientation).
global first_request: table[string] of vector of count &create_expire=10 min;

## [A2] and [A3] for one ADU whose function code is `fc` and length `len`,
## read as a request or as a reply. `bc` is the octet after the code, or
## UNSEEN if the chunk ends before it.
function framing_ok(fc: count, len: count, reply: bool, bc: count): bool
	{
	if ( reply && fc >= 0x80 )
		return (fc - 0x80) in codes;
	if ( fc !in codes )
		return F;
	if ( ! reply && fc <= 6 )
		return len == 6;
	if ( reply && fc <= 4 && bc != UNSEEN )
		return len == 3 + bc;
	return T;
	}

## [transaction ID, function code] of each ADU in `data`, read as requests
## or as replies, the last one possibly cut short; or an empty vector if
## any ADU breaks [T1], [A1], [A2] or [A3].
function adus(data: string, reply: bool): vector of vector of count
	{
	local none: vector of vector of count = vector();
	local out: vector of vector of count = vector();
	local n = |data|;
	local i = 0;
	local len = 0;
	local fc = 0;
	local bc = 0;
	while ( i < n )
		{
		if ( n - i < 6 )
			return i > 0 ? out : none;
		len = bytestring_to_count(data[i+4:i+6]);
		if ( bytestring_to_count(data[i+2:i+4]) != 0 || len < 2 || len > 254 )
			return none;
		fc = n - i > 7 ? bytestring_to_count(data[i+7:i+8]) : UNSEEN;
		bc = n - i > 8 ? bytestring_to_count(data[i+8:i+9]) : UNSEEN;
		if ( fc != UNSEEN && ! framing_ok(fc, len, reply, bc) )
			return none;
		out[|out|] = vector(bytestring_to_count(data[i:i+2]), fc);
		i += 6 + len;
		}
	return out;
	}

function request_ok(state: signature_state, data: string): bool
	{
	local a = adus(data, F);
	if ( |a| == 0 )
		return F;
	first_request[state$conn$uid] = a[0];
	return T;
	}

function response_ok(state: signature_state, data: string): bool
	{
	local uid = state$conn$uid;
	if ( uid !in first_request )
		return F;
	local q = first_request[uid];
	delete first_request[uid];
	local a = adus(data, T);
	if ( |a| == 0 || a[0][0] != q[0] )
		return F;
	return q[1] == UNSEEN || a[0][1] == UNSEEN || a[0][1] == q[1] || a[0][1] == q[1] + 0x80;
	}

function replies_ok(state: signature_state, data: string): bool
	{
	return |adus(data, T)| > 0;
	}

function requests_ok(state: signature_state, data: string): bool
	{
	return |adus(data, F)| > 0;
	}
