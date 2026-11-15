##! Test helper for script_reqs.py (D4, #715): logs each connection's start
##! and removal, in event order (n), with the network time. Loaded only in
##! script_reqs.py's configurations, never in one that measures.

module OtsecReqTest;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		n: count &log;
		ts: time &log;
		ev: string &log;
		uid: string &log;
		orig_p: port &log;
		resp_p: port &log;
	};
}

global n = 0;

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="otsec_reqtest"));
	}

event new_connection(c: connection)
	{
	++n;
	Log::write(LOG, Info($n=n, $ts=network_time(), $ev="new", $uid=c$uid, $orig_p=c$id$orig_p, $resp_p=c$id$resp_p));
	}

event connection_state_remove(c: connection)
	{
	++n;
	Log::write(LOG, Info($n=n, $ts=network_time(), $ev="remove", $uid=c$uid, $orig_p=c$id$orig_p, $resp_p=c$id$resp_p));
	}
