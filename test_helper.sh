#!/bin/bash
# A script that writes mock log lines

set -e
set -u

TEST_LINES="\
<134>DATE pfsense filterlog: 104,,,1607568163,igb1,match,block,in,4,0x0,,64,0,0,DF,1,icmp,84,RANDOM_IP,RANDOM_IP,request,3226,764+\
<134>DATE pfsense filterlog: 105,,,1609264002,igb1,match,block,in,4,0x0,,64,54307,0,DF,6,tcp,60,RANDOM_IP,RANDOM_IP,50200,12345,0,S,3632777206,,64240,,mss;sackOK;TS;nop;wscale+\
<134>DATE pfsense filterlog: 105,,,1607568163,igb1,match,block,in,4,0x0,,64,0,0,DF,17,udp,164,RANDOM_IP,RANDOM_IP,48020,33434,144+\
<134>DATE pfsense dhcpd: uid lease RANDOM_IP for client RANDOM_MAC is duplicate on RANDOM_IP/24+\
<134>DATE pfsense dhcpd: DHCPREQUEST for RANDOM_IP from RANDOM_MAC via igb1+\
<134>DATE pfsense dhcpd: DHCPACK on RANDOM_IP to RANDOM_MAC via igb1"


IFS='+'

# Returns the current date in the BSD log format
function now {
    date +"%b %e %H:%M:%S"
}


# Returns a randomly generated IP address
function random_ip {
    echo $((1 + RANDOM % 255)).$((1 + RANDOM % 255)).$((1 + RANDOM % 255)).$((1 + RANDOM % 255))
}

# Returns a randomly generated MAC address
function random_mac {
    printf "%x:%x:%x:%x:%x:%x" $((1 + RANDOM % 255)) $((1 + RANDOM % 255)) $((1 + RANDOM % 255)) $((1 + RANDOM % 255)) $((1 + RANDOM % 255)) $((1 + RANDOM % 255))
}

while true; do
    read -ra LOG_LINES <<< "$TEST_LINES"
    for line in "${LOG_LINES[@]}"; do
        line=${line/DATE/$(now)}
        line=${line/RANDOM_IP/$(random_ip)}
        line=${line/RANDOM_IP/$(random_ip)}
        line=${line/RANDOM_MAC/$(random_mac)}
        echo "$line"
        sleep 1
    done
done

