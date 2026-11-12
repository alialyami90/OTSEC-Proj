##! P4-4-E2 (D4): a Modbus/TCP content signature, as an experiment. It is
##! not adopted: D1 adopts it, or does not, on a counted run against D6's
##! pass conditions (D4-90). Loaded with probe.zeek in the `zeek-modbus-sig`
##! configuration only, which is "Zeek with the project's script and the
##! Modbus signature" in every table. It names no port, no address and no
##! capture (D6's rule 8), and registers no port.
##!
##! What it matches. Zeek's Modbus analyzer is registered on 502/tcp only
##! (base/protocols/modbus/main.zeek at v9.0.1), so a server on another port
##! is not parsed (E-D4-03). modbus-sig.sig enables that same analyzer by
##! content, on any port, when both of these hold in the first payload of
##! each side of a TCP flow (D2's strict check, notes 3 and 4 and finding G
##! on #637):
##!   - the originator's payload is a whole number, one or more, of MBAP
##!     ADUs: each has protocol ID 0, a length of 2 to 254 that its bytes
##!     fill exactly, and a function code from the public set below;
##!   - the responder's payload is a whole number of MBAP ADUs, and the
##!     first one carries the first request's transaction ID and its
##!     function code, or that code plus 0x80 (an exception).
##! Why that is Modbus/TCP and not other binary traffic is D2's `inference`
##! on #637: DNP3 (05 64), IEC 104 (68), TPKT (03 00 and a nonzero length),
##! C37.118 (AA), EtherNet/IP (a nonzero length at octets 2 and 3), TLS,
##! SSH and text protocols fail the first octets; a payload that passes them must also
##! have its lengths add up to the payload exactly, use a public function
##! code, and be answered with the same transaction ID and code.
##!
##! What it does on a parse violation. Nothing of its own. Once enabled,
##! the analyzer is Zeek's, and Zeek's stock DPD rule applies: a parse
##! violation in the first 10 KiB of the connection removes the analyzer,
##! conn.log drops `modbus` from `service`, and analyzer.log records the
##! violation (base/frameworks/analyzer/dpd.zeek at v9.0.1). This script
##! does not add Modbus to `DPD::ignore_violations` (D2's finding C), so
##! that removal stays the check against a false match.
##!
##! Limits, by construction: only the first payload of each side is read,
##! so a first segment that ends partway through an ADU does not match;
##! both sides must be seen, so a capture of one direction does not match;
##! a function code outside the public set (Schneider's 0x5A among them)
##! does not match; Modbus RTU carried in raw TCP has no MBAP header and
##! does not match.

@load-sigs ./modbus-sig.sig

module OtsecModbusSig;

export {
	## The public function codes: the "Standard defined" codes of Zeek's own
	## `Modbus::function_codes` (base/protocols/modbus/consts.zeek at
	## v9.0.1), without 0x5B, which Zeek cites to a separate extension
	## document. The Modbus application protocol specification is not held
	## (`desk`).
	const public_codes: set[count] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C,
		0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B,
	};
}

## The first request's transaction ID and function code, by connection,
## kept until the responder's first payload is read.
global first_request: table[string] of vector of count &create_expire=10 min;

## Each ADU's transaction ID and function code, or an empty vector unless
## `data` is a whole number, one or more, of MBAP ADUs whose protocol ID is
## 0 and whose length is 2 to 254.
function adus(data: string): vector of vector of count
	{
	local none: vector of vector of count = vector();
	local out: vector of vector of count = vector();
	local n = |data|;
	local i = 0;
	local len = 0;
	while ( i < n )
		{
		if ( n - i < 8 )
			return none;
		len = bytestring_to_count(data[i+4:i+6]);
		if ( bytestring_to_count(data[i+2:i+4]) != 0 || len < 2 || len > 254 || i + 6 + len > n )
			return none;
		out[|out|] = vector(bytestring_to_count(data[i:i+2]), bytestring_to_count(data[i+7:i+8]));
		i += 6 + len;
		}
	return out;
	}

function request_ok(state: signature_state, data: string): bool
	{
	local a = adus(data);
	if ( |a| == 0 )
		return F;
	for ( k in a )
		if ( a[k][1] !in public_codes )
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
	local a = adus(data);
	if ( |a| == 0 )
		return F;
	return a[0][0] == q[0] && ( a[0][1] == q[1] || a[0][1] == q[1] + 0x80 );
	}
