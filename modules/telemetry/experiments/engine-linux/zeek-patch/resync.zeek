##! HR-25 option A's script part (HR25-B2; docs/phase4/D4-hr25-design.md,
##! section 2.8): loaded after probe.zeek, on C2A and its controls only,
##! since only A's patch defines the two events it handles. It is the part
##! of the shipped script that cfg-c2a names: the weirds' bound, the resync
##! rows in otsec_probe.log under the host cap, and the cause of the last
##! resync on the next fc row of its end. Causes and counts only, never a
##! payload octet. It holds no table, set or other container: the pending
##! cause lives on the connection record (D3's BM; D1's ruling 6893581874).

module DNP3;

export {
	## The interval of a flow's resync rows (design 2.8; val-interval). The
	## analyzer reads it at its first use.
	const resync_report_interval = 60 sec &redef;
}

module OtsecResync;

export {
	## K, the host cap: resync rows per interval across the host, the
	## overflow row not counted (design 2.8; val-K).
	const host_cap = 100 &redef;
}

# The weirds' bound (design 2.8, N8 and T10): every weird of the closed set
# of causes, the existing ones included, is rate-limited across the host.
redef Weird::sampling_global_list += {
	"dnp3_header_lacks_magic",
	"dnp3_corrupt_header_checksum",
	"dnp3_invalid_link_length",
	"dnp3_corrupt_app_chunk_checksum",
	"dnp3_embedded_header",
	"dnp3_first_application_layer_chunk_missing",
	"dnp3_fragment_restarted",
	"dnp3_transport_sequence",
	"dnp3_max_application_layer_fragment_size_exceeded",
	"dnp3_app_parse_failed",
	"dnp3_content_gap",
	"dnp3_truncated_frame",
	"dnp3_resync_budget_exhausted",
	"dnp3_invariant"
};

# The probe-log record (design 2.8, D6's B2 item 1): kind "resync" rows,
# and the cause on fc rows. Exactly these fields.
redef record OtsecProbe::Info += {
	why: string &log &optional;
	cause: string &log &optional;
	counts: index_vec &log &optional;
	scanned_octets: count &log &optional;
	overflow: count &log &optional;
	resync_cause: string &log &optional;
};

# The pending cause of each end, on the connection record only.
redef record connection += {
	otsec_resync_orig: string &optional;
	otsec_resync_resp: string &optional;
};

# The host's intervals: a grid of network time anchored at the first resync
# row; the interval now open, the rows written in it and the rows held back.
global grid_set = F;
global grid_start: time;
global open_n = 0;
global written = 0;
global held = 0;

global overflow_due: event(n: count);

# A time before the grid's start (a capture clock stepped back) takes the
# open interval, as the analyzer does with a negative time since its first
# row.
function grid_index(t: time): count
	{
	if ( t < grid_start )
		return open_n;
	return double_to_count(floor((t - grid_start) / DNP3::resync_report_interval));
	}

# The overflow row of interval n, if any row was held back in it. It is
# charged to no interval (D6's B6).
function flush(n: count)
	{
	if ( n != open_n || held == 0 )
		return;
	Log::write(OtsecProbe::LOG, OtsecProbe::Info($ts=network_time(), $uid="", $is_orig=F, $kind="resync",
	                                             $ev="overflow", $why="overflow", $overflow=held));
	held = 0;
	}

event overflow_due(n: count)
	{
	flush(n);
	}

event zeek_done()
	{
	flush(open_n);
	}

event dnp3_resync(c: connection, is_orig: bool, why: string, cause: string, counts: index_vec, scanned_octets: count)
	{
	if ( ! grid_set )
		{
		grid_set = T;
		grid_start = network_time();
		}
	local n = grid_index(network_time());
	if ( n != open_n )
		{
		flush(open_n);
		open_n = n;
		written = 0;
		}
	# Every row but the overflow row counts against K, whatever its why.
	if ( written >= host_cap )
		{
		if ( held == 0 )
			schedule grid_start + (n + 1) * DNP3::resync_report_interval - network_time() { overflow_due(n) };
		++held;
		return;
		}
	++written;
	Log::write(OtsecProbe::LOG, OtsecProbe::Info($ts=network_time(), $uid=c$uid, $is_orig=is_orig, $kind="resync",
	                                             $ev="dnp3_resync", $why=why, $cause=cause, $counts=counts,
	                                             $scanned_octets=scanned_octets));
	}

# A later mark on the same end overwrites the pending cause; nothing is
# queued.
event dnp3_resync_mark(c: connection, is_orig: bool, cause: string)
	{
	if ( is_orig )
		c$otsec_resync_orig = cause;
	else
		c$otsec_resync_resp = cause;
	}

# The next fc row of that end takes the cause and clears it.
hook OtsecProbe::fc_row(c: connection, is_orig: bool, r: OtsecProbe::Info)
	{
	if ( is_orig && c?$otsec_resync_orig )
		{
		r$resync_cause = c$otsec_resync_orig;
		delete c$otsec_resync_orig;
		}
	else if ( ! is_orig && c?$otsec_resync_resp )
		{
		r$resync_cause = c$otsec_resync_resp;
		delete c$otsec_resync_resp;
		}
	}
