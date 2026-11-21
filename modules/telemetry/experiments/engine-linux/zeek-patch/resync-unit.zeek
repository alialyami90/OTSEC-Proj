##! HR-25 option A, part HR25-B1: one row in otsec_resync_unit.log for every
##! dnp3_resync event, as the patch raises it, for D4's unit tests of the
##! patch (hr25_unit.py) only. Loaded by run.sh's hr25-unit mode on C2A and
##! its controls, which define the event; never by C2, and never by the
##! sensor's script (the shipped rows are HR25-B2's). Causes and counts only,
##! never a payload octet.

module OtsecResyncUnit;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log;
		is_orig: bool &log;
		why: string &log;
		cause: string &log;
		counts: index_vec &log;
		scanned_octets: count &log;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="otsec_resync_unit"]);
	}

event dnp3_resync(c: connection, is_orig: bool, why: string, cause: string, counts: index_vec, scanned_octets: count)
	{
	Log::write(LOG, Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $why=why, $cause=cause,
	                     $counts=counts, $scanned_octets=scanned_octets));
	}
