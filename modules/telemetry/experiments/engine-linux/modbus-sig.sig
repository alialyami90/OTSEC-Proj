# P4-4-E2 (D4): a Modbus/TCP content signature, an experiment and not
# adopted. Loaded by modbus-sig.zeek in the `zeek-modbus-sig` configuration
# only. It names no port, no address and no capture (D6's rule 8).
#
# A Modbus/TCP ADU is a 7-octet MBAP header (transaction ID, protocol ID,
# length, unit ID) and then a function code (D2 on #637). Every pattern
# below matches the first ADU's header at the start of one side's stream:
# any transaction ID, protocol ID 0, a length of 2 to 254 (its high octet
# 0), any unit ID. The eval functions then read every ADU in that payload
# against the framing the Modbus specification fixes (modbus-sig.zeek).
# Zeek anchors a payload pattern at the start of the side's stream.
#
# Two orientations, each needing both sides, and only the second signature
# of each pair enables Zeek's own Modbus analyzer:
#   - the client's side is the originator's: requests, then a reply that
#     answers the first request (D2's strict check);
#   - the server's side is the originator's, as Zeek keeps it for a flow
#     whose first frame is the server's, with no SYN, off a port Zeek holds
#     as a likely server port (D2's B1 on #642): replies, then requests.
#     D1's ruling 6839544318 on #642: the roles are lost, not the protocol.

signature otsec_modbus_client {
	ip-proto == tcp
	payload /^[\x00-\xff]{2}\x00\x00\x00[\x02-\xfe]/
	tcp-state originator
	eval OtsecModbusSig::request_ok
}

signature otsec_modbus_server {
	ip-proto == tcp
	payload /^[\x00-\xff]{2}\x00\x00\x00[\x02-\xfe]/
	tcp-state responder
	requires-reverse-signature otsec_modbus_client
	eval OtsecModbusSig::response_ok
	enable "modbus"
}

signature otsec_modbus_server_first {
	ip-proto == tcp
	payload /^[\x00-\xff]{2}\x00\x00\x00[\x02-\xfe]/
	tcp-state originator
	eval OtsecModbusSig::replies_ok
}

signature otsec_modbus_client_second {
	ip-proto == tcp
	payload /^[\x00-\xff]{2}\x00\x00\x00[\x02-\xfe]/
	tcp-state responder
	requires-reverse-signature otsec_modbus_server_first
	eval OtsecModbusSig::requests_ok
	enable "modbus"
}
