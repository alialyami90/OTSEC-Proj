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

	type Info: record {
		ts: time &log;
		uid: string &log;
		is_orig: bool &log;
		## "link" (a DNP3 link header), "fc" (a DNP3 application header),
		## "obj" (a DNP3 object header) or "snmp" (an SNMP message header).
		kind: string &log;
		## The Zeek event that wrote the row.
		ev: string &log;
		link_src: count &log &optional;
		link_dst: count &log &optional;
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
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="otsec_probe"));
	}

event dnp3_header_block(c: connection, is_orig: bool, len: count, ctrl: count, dest_addr: count, src_addr: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="link", $ev="dnp3_header_block",
	                     $link_src=src_addr, $link_dst=dest_addr));
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc",
	                     $ev="dnp3_application_request_header", $fc=fc));
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc",
	                     $ev="dnp3_application_response_header", $fc=fc));
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
