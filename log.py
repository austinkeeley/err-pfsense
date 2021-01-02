"""Log entry types"""

import logging
import re

from mac_vendor_lookup import MacLookup
from syslogmp import parse

ICMP = 1
TCP = 6
UDP = 17

class LogParser:
    """Parses a line and returns the formatted entry"""

    def __init__(self, resolver, ignore_regex=None):
        self.resolver = resolver
        self.regex_patterns = [re.compile(r) for r in ignore_regex] if ignore_regex else []

    def parse(self, line):
        """Turns the line into a LogEntry"""

        # Are we ignoring this?
        for p in self.regex_patterns:
            if p.search(line):
                return None

        # syslogmp expects a byte string
        line_bytes = str.encode(line)
        syslog_msg = parse(line_bytes)

        if b'filterlog:' in syslog_msg.message:
            return FirewallLogEntry(syslog_msg.message.decode('utf-8'), self.resolver)
        elif b'dhcpd:' in syslog_msg.message:
            e = DHCPDLogEntry(line)
            # We only care about DHCPACK and DHCPRequest. All other lease logs
            # are not interesting.
            if 'DHCPACK' in str(e)  or 'DHCPREQUEST' in str(e):
                return e
            else:
                return None
        else:
            return LogEntry(f'Cannot process line {line}')


class LogEntry:
    def __init__(self, line):
        self.line = line

    def __str__(self):
        return self.line


class FirewallLogEntry(LogEntry):

    def field_iter(self, line):
        for token in line.split(','):
            yield token

    def __init__(self, line, resolver):
        super().__init__(line)

        # Split the line to get the actual syslog content
        #date, hostname, process, content = line.split(' ')
        tag, content = line.split(' ')

        fields = self.field_iter(content)
        self.rule_num = next(fields)
        self.sub_rule_num = next(fields)      # Sub rule this matched, can be empty
        self.anchor = next(fields)            # Usually empty
        self.tracker = next(fields)           # Unique ID per rule
        self.interface = next(fields)         # Interface name
        self.reason = next(fields)            # Reason, e.g. "match"
        self.action = next(fields)            # Action taken, e.g. "block"
        self.direction = next(fields)         # Direction, "in" or "out"
        self.ip_version = int(next(fields))   # IP version, "4" for IPv4 or "6" for IPv6

        if self.ip_version == 4:
            self.ipv4_tos = next(fields)
            self.ipv4_ecn = next(fields)
            self.ipv4_ttl = next(fields)
            self.ipv4_id = next(fields)
            self.ipv4_offset = next(fields)
            self.ipv4_flags = next(fields)
            self.ipv4_protocol_id = int(next(fields))
            self.ipv4_protocol_text = next(fields)
        else:
            raise Exception('IPv6 not supported yet')

        self.length = next(fields)
        self.src_ip = next(fields)
        self.dst_ip = next(fields)

        # TCP and UDP
        if self.ipv4_protocol_id == TCP or self.ipv4_protocol_id == UDP:
            self.src_port = next(fields)
            self.dst_port = next(fields)
            self.data_length = next(fields)

        # TCP only
        if self.ipv4_protocol_id == TCP:
            self.tcp_flags = next(fields)
            self.seq_number = next(fields)
            self.ack = next(fields)
            self.window = next(fields)
            self.urg = next(fields)
            self.options = next(fields)

        if self.ipv4_protocol_id == ICMP:
            self.icmp_type = next(fields)

        if resolver:
            self.src_hostname = resolver.resolve(self.src_ip, self.src_resolver_cb)
            self.dst_hostname = resolver.resolve(self.dst_ip, self.dst_resolver_cb)
        else:
            self.src_hostname = None
            self.dst_hostname = None

    def src_resolver_cb(self, ip, hostname):
        self.src_hostname = hostname

    def dst_resolver_cb(self, ip, hostname):
        self.dst_hostname = hostname


    def __str__(self):
        if self.ipv4_protocol_id == UDP:
            return f'{self.ipv4_protocol_text} {self.src_hostname if self.src_hostname else self.src_ip}:{self.src_port} --> {self.dst_hostname if self.dst_hostname else self.dst_ip}:{self.dst_port} -- rule {self.rule_num}'
        elif self.ipv4_protocol_id == TCP:
            return f'{self.ipv4_protocol_text} {self.src_hostname if self.src_hostname else self.src_ip}:{self.src_port} --> {self.dst_hostname if self.dst_hostname else self.dst_ip}:{self.dst_port} {self.tcp_flags} -- rule {self.rule_num}'
        elif self.ipv4_protocol_id == ICMP:
            return f'{self.ipv4_protocol_text} {self.src_hostname if self.src_hostname else self.src_ip} --> {self.dst_hostname if self.dst_hostname else self.dst_ip}, {self.icmp_type} -- rule {self.rule_num}'

        else:
            return f'Protocol not handled: {self.ipv4_protocol_id}'


class DHCPDLogEntry(LogEntry):

    mac_regex = re.compile(r'''([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})''')
    mac_lookup = MacLookup()

    def __init__(self, line):
        super().__init__(line)
        self.line = line.split('dhcpd: ')[1]
        result = re.search(DHCPDLogEntry.mac_regex, line)
        if result:
            mac = result.group(0)
            try:
                vendor = DHCPDLogEntry.mac_lookup.lookup(mac)
                self.line += f' ({vendor})'
            except:
                self.line += ' (unknown vendor)'

    def __str__(self):
        return self.line

