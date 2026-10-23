#!/bin/sh
# Slow consumer for rsyslog omprog: appends each line to $1 after a short
# delay, so that the receiver's queues fill up during the RELP test. Prints
# "OK" at start and after each stored line for omprog confirmMessages="on".
echo OK
while IFS= read -r line; do
  sleep 0.002
  printf '%s\n' "$line" >> "$1"
  echo OK
done
