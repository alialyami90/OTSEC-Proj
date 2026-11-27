##! HR-23 (B') (D1's ruling on #715, condition 1): one row in otsec_viol.log
##! for every analyzer_violation_info event, whatever the analyzer, so that
##! D4's unit tests count violations as raised, before dpd.zeek's and
##! logging.zeek's filters decide which reach analyzer.log. Loaded by
##! run.sh's hr23-unit and hr25-unit modes and its HR-23 feed (hr23_feed),
##! and named by row judge-viol of resync-conditions.tsv; never by the
##! sensor's script. It logs the reason, never the violation's data.

module OtsecViol;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		uid: string &log &optional;
		analyzer: string &log;
		reason: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="otsec_viol"]);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	local r = Info($ts=network_time(), $analyzer=Analyzer::name(atype), $reason=info$reason);
	if ( info?$c )
		r$uid = info$c$uid;
	Log::write(LOG, r);
	}
