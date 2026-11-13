##! P4-4-E2 (D4): prints Zeek's `likely_server_ports`, the set with which
##! TCP.cc decides whether to swap a flow's two ends when it holds no SYN
##! (D6's note, section 1; D2's B1 and N3 on #642). The set is read once,
##! on IsLikelyServerPort's first call (IPBasedAnalyzer.cc l.144 to l.161
##! at v9.0.1), and analyzers add their ports in zeek_init (analyzer/
##! main.zeek l.256 and l.257), so it is printed after every other zeek_init
##! handler, at priority -1000, and again at zeek_done (D2's N2 on #647).
##! Loaded beside S0's or S1's scripts in a run of its own, never in the
##! runs that are judged. It changes nothing.

function ports_of(proto: transport_proto): vector of count
	{
	local v: vector of count = vector();
	for ( p in likely_server_ports )
		if ( get_port_transport_proto(p) == proto )
			v[|v|] = port_to_count(p);
	return sort(v);
	}

function show(at: string)
	{
	print fmt("likely_server_ports at %s: tcp %s; udp %s", at, ports_of(tcp), ports_of(udp));
	}

event zeek_init() &priority=-1000
	{
	show("zeek_init, priority -1000");
	}

event zeek_done()
	{
	show("zeek_done");
	}
