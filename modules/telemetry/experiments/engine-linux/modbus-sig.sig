# P4-4-E2 (D4): a Modbus/TCP content signature, an experiment and not
# adopted. Loaded by modbus-sig.zeek in the `zeek-modbus-sig` configuration
# only. It names no port, no address and no capture (D6's rule 8).
#
# A Modbus/TCP ADU is a 7-octet MBAP header (transaction ID, protocol ID,
# length, unit ID) and then a function code (D2 on #637). The two patterns
# below match the first ADU's header in the first payload of each side:
# any transaction ID, protocol ID 0, a length of 2 to 254 (its high octet
# 0), any unit ID. The eval functions then read every ADU in that payload.
# Zeek anchors a payload pattern at the start of the side's stream.
#
# The client's side matches first. The server's side matches only after it,
# and only it enables Zeek's own Modbus analyzer, so a flow is handed to
# the analyzer only when both sides look like Modbus/TCP and the reply
# answers the request (D2's strict check).

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
