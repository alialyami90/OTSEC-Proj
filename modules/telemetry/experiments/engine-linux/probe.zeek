##! E-D4-03 probe (D4, P4-4-S2): what Zeek's own DNP3 and SNMP events expose,
##! beside what its default logs record. It handles documented events only,
##! changes no analyzer and no port registration, and writes one log of its
##! own, otsec_probe.log. Loaded in the `zeek-probe` configuration only.
##! It names no port, no address and no capture (D6's rule 8 on #625).
##! For SNMPv3 it logs the header flags, the USM engine boots and time, and
##! the lengths of the engine ID and user name, never their bytes. Written
##! for Zeek 9.0.1, whose SNMP::HeaderV3 carries user_security_parameters.

module OtsecProbe;

export {
	redef enum Log::ID += { LOG };

	## F gives HR-23's control C0, the script as it was before part (a):
	## no link_dir on any row (docs/phase4/D4-hr23-design.md, section 4.1).
	const log_dir = T &redef;

	## C13 0.1 section 10's `flow_idle_s` and `sa_reply_timeout_ms`, at
	## their defaults (CH-53, CH-57; D4-102 item 6).
	const flow_idle = 60 sec &redef;
	const sa_reply_timeout = 5 sec &redef;

	## A DNP3 request that waits for its response (C13 0.1 section 4.3):
	## the flow that carried it, its time and code, and whether its sender
	## was the flow's originator. Keyed by master, outstation and the
	## request's application sequence number, never by flow, so a flow's
	## idle cut neither discards nor completes it (CH-57).
	type Pending: record {
		uid: string;
		ts: time;
		fc: count;
		is_orig: bool;
	};
	global dnp3_pending: table[addr, addr, count] of Pending;
	global dnp3_timeout: event(m: addr, o: addr, seq: count, ts: time);
	## Ends a pending request and writes its "done" row.
	global dnp3_complete: function(m: addr, o: addr, seq: count, how: string);

	type Info: record {
		ts: time &log;
		uid: string &log;
		is_orig: bool &log;
		## "link" (a DNP3 link header), "fc" (a DNP3 application header),
		## "obj" (a DNP3 object header), "snmp" (an SNMP message header) or
		## "done" (a DNP3 request completed, CH-57: uid, is_orig and fc are
		## the request's, ts is when it completed).
		kind: string &log;
		## The Zeek event that wrote the row.
		ev: string &log;
		link_src: count &log &optional;
		link_dst: count &log &optional;
		## The link header's DIR bit (ctrl & 0x80), on "link" rows (HR-23
		## part (a)): T when the frame's sender says it is a master. The
		## judge takes a DNP3 flow's servers from it. Not a C13 field.
		link_dir: bool &log &optional;
		fc: count &log &optional;
		group: count &log &optional;
		variation: count &log &optional;
		snmp_version: count &log &optional;
		v3_auth: bool &log &optional;
		v3_priv: bool &log &optional;
		v3_reportable: bool &log &optional;
		v3_security_model: count &log &optional;
		v3_security_params_len: count &log &optional;
		v3_context_engine_id_len: count &log &optional;
		v3_encrypted_pdu: bool &log &optional;
		## Zeek 9.0's parsed USM fields (RFC 3414).
		v3_usm_parsed: bool &log &optional;
		v3_usm_engine_id_len: count &log &optional;
		v3_usm_user_name_len: count &log &optional;
		v3_usm_boots: int &log &optional;
		v3_usm_time: int &log &optional;
		## On "done" rows: "response" (the outstation's 129 with the
		## request's sequence number) or "timeout" (sa_reply_timeout after
		## the request, on network time), the sequence number, and the
		## request's time.
		done: string &log &optional;
		seq: count &log &optional;
		req_ts: time &log &optional;
	};
}

# CH-53 (C13 0.3; D4-102 item 6; D1's ruling 1 on #715). The timer cap:
# with 0, Zeek expires every timer due at a frame's time before it processes
# that frame (TimerMgr::InitPostScript reads 0 as dispatch_all_expired). The
# engine's inactivity cut of a tracked TCP flow is the frame stage's idle
# cut, flow_idle. This script defines no connection_timing_out hook, which
# could stop that cut.
redef max_timer_expires = 0;
redef tcp_inactivity_timeout = flow_idle;

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="otsec_probe"));
	}

# CH-57: the DNP3 timeout runs as an engine timer (`schedule`), which fires
# on network time, the frames' time, never on a wall clock. A request
# completes at its response or at the timeout, whichever comes first; no
# flow event touches dnp3_pending.
function dnp3_complete(m: addr, o: addr, seq: count, how: string)
	{
	local p = dnp3_pending[m, o, seq];
	delete dnp3_pending[m, o, seq];
	Log::write(LOG, Info($ts=network_time(), $uid=p$uid, $is_orig=p$is_orig, $kind="done", $ev=how,
	                     $fc=p$fc, $done=how, $seq=seq, $req_ts=p$ts));
	}

event dnp3_timeout(m: addr, o: addr, seq: count, ts: time)
	{
	if ( [m, o, seq] in dnp3_pending && dnp3_pending[m, o, seq]$ts == ts )
		dnp3_complete(m, o, seq, "timeout");
	}

event dnp3_header_block(c: connection, is_orig: bool, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
	local r = Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="link", $ev="dnp3_header_block",
	               $link_src=src_addr, $link_dst=dest_addr);
	if ( log_dir )
		r$link_dir = ctrl >= 128;
	Log::write(LOG, r);
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc",
	                     $ev="dnp3_application_request_header", $fc=fc));
	# A confirm (0) is no request that waits for a reply.
	if ( fc == 0 )
		return;
	local m = is_orig ? c$id$orig_h : c$id$resp_h;
	local o = is_orig ? c$id$resp_h : c$id$orig_h;
	local seq = application % 16;
	# A second request with the same key ends the first, which is logged as
	# "replaced", never dropped unlogged.
	if ( [m, o, seq] in dnp3_pending )
		dnp3_complete(m, o, seq, "replaced");
	dnp3_pending[m, o, seq] = Pending($uid=c$uid, $ts=network_time(), $fc=fc, $is_orig=is_orig);
	schedule sa_reply_timeout { OtsecProbe::dnp3_timeout(m, o, seq, network_time()) };
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc",
	                     $ev="dnp3_application_response_header", $fc=fc));
	local o = is_orig ? c$id$orig_h : c$id$resp_h;
	local m = is_orig ? c$id$resp_h : c$id$orig_h;
	local seq = application % 16;
	if ( fc == 129 && [m, o, seq] in dnp3_pending )
		dnp3_complete(m, o, seq, "response");
	}

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="obj", $ev="dnp3_object_header",
	                     $group=obj_type / 256, $variation=obj_type % 256));
	}

function log_snmp(c: connection, is_orig: bool, h: SNMP::Header, ev: string, encrypted: bool)
	{
	local r = Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="snmp", $ev=ev, $snmp_version=h$version);
	if ( h?$v3 )
		{
		r$v3_auth = h$v3$auth_flag;
		r$v3_priv = h$v3$priv_flag;
		r$v3_reportable = h$v3$reportable_flag;
		r$v3_security_model = h$v3$security_model;
		r$v3_security_params_len = |h$v3$security_params|;
		if ( h$v3?$pdu_context )
			r$v3_context_engine_id_len = |h$v3$pdu_context$engine_id|;
		r$v3_encrypted_pdu = encrypted;
		r$v3_usm_parsed = h$v3?$user_security_parameters;
		if ( h$v3?$user_security_parameters )
			{
			r$v3_usm_engine_id_len = |h$v3$user_security_parameters$AuthoritativeEngineID|;
			r$v3_usm_user_name_len = |h$v3$user_security_parameters$UserName|;
			r$v3_usm_boots = h$v3$user_security_parameters$AuthoritativeEngineBoots;
			r$v3_usm_time = h$v3$user_security_parameters$AuthoritativeEngineTime;
			}
		}
	Log::write(LOG, r);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_get_request", F); }

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_get_next_request", F); }

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU)
	{ log_snmp(c, is_orig, header, "snmp_get_bulk_request", F); }

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_response", F); }

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_set_request", F); }

event snmp_trap(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::TrapPDU)
	{ log_snmp(c, is_orig, header, "snmp_trap", F); }

event snmp_trapV2(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_trapV2", F); }

event snmp_inform_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_inform_request", F); }

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, "snmp_report", F); }

event snmp_unknown_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
	{ log_snmp(c, is_orig, header, "snmp_unknown_pdu", F); }

event snmp_unknown_scoped_pdu(c: connection, is_orig: bool, header: SNMP::Header, tag: count)
	{ log_snmp(c, is_orig, header, "snmp_unknown_scoped_pdu", F); }

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header)
	{ log_snmp(c, is_orig, header, "snmp_encrypted_pdu", T); }

## A message whose version Zeek cannot parse carries no header, only the
## version number it read.
event snmp_unknown_header_version(c: connection, is_orig: bool, version: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="snmp",
	                     $ev="snmp_unknown_header_version", $snmp_version=version));
	}
