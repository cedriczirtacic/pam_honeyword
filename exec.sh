#!/bin/bash
# example executable for pam_honeyword.so
RHOST=$2
iptables -A INPUT --source $RHOST -j REJECT
