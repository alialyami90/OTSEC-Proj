##! E-D4-03 probe (D4, P4-4-S2): what Zeek's own DNP3 and SNMP events expose,
##! beside what its default logs record. It handles documented events only,
##! changes no analyzer and no port registration, and writes one log of its
##! own, otsec_probe.log. Loaded in the `zeek-probe` configuration only.
##! It logs no SNMP value: for SNMPv3 it records which header fields are
##! present and their lengths, never their bytes. Written for Zeek 9.0.1,
##! whose SNMP::HeaderV3 carries user_security_parameters.

module OtsecProbe;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		is_orig: bool &log;
		## "fc" (a DNP3 application header), "obj" (a DNP3 object header)
		## or "snmp" (an SNMP message header).
		kind: string &log;
		fc: count &log &optional;
		group: count &log &optional;
		variation: count &log &optional;
		snmp_version: count &log &optional;
		v3_auth: bool &log &optional;
		v3_priv: bool &log &optional;
		v3_security_model: count &log &optional;
		v3_security_params_len: count &log &optional;
		v3_context_engine_id_len: count &log &optional;
		v3_encrypted_pdu: bool &log &optional;
		## Zeek 9.0's parsed USM fields (RFC 3414), as lengths only.
		v3_usm_parsed: bool &log &optional;
		v3_usm_engine_id_len: count &log &optional;
		v3_usm_user_name_len: count &log &optional;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="otsec_probe"));
	}

event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc", $fc=fc));
	}

event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="fc", $fc=fc));
	}

event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="obj",
	                     $group=obj_type / 256, $variation=obj_type % 256));
	}

function log_snmp(c: connection, is_orig: bool, h: SNMP::Header, encrypted: bool)
	{
	local r = Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="snmp", $snmp_version=h$version);
	if ( h?$v3 )
		{
		r$v3_auth = h$v3$auth_flag;
		r$v3_priv = h$v3$priv_flag;
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
			}
		}
	Log::write(LOG, r);
	}

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_get_next_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_get_bulk_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::BulkPDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_set_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_report(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{ log_snmp(c, is_orig, header, F); }

event snmp_encrypted_pdu(c: connection, is_orig: bool, header: SNMP::Header)
	{ log_snmp(c, is_orig, header, T); }
