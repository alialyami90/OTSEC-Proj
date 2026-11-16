##! Control for script_reqs.py (D4, #715): a script whose idle cut discards
##! the flow's pending DNP3 requests, which CH-57 forbids. Never loaded in a
##! configuration that measures.

event connection_state_remove(c: connection)
	{
	local gone: set[addr, addr, count] = set();
	for ( [m, o, s] in OtsecProbe::dnp3_pending )
		if ( (m == c$id$orig_h && o == c$id$resp_h) || (m == c$id$resp_h && o == c$id$orig_h) )
			add gone[m, o, s];
	for ( [m, o, s] in gone )
		delete OtsecProbe::dnp3_pending[m, o, s];
	}
