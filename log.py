ICMP = 1
TCP = 6
UDP = 17

class LogParser:
    """Parses a line and returns the formatted entry"""

    def parse(self, line):
        try:
            #date, hostname, process, content = line.split(' ')
            tokens = line.split(' ')
            process = tokens[2]
            if process == 'filterlog:':
                return FirewallLogEntry(line)
            elif process == 'dhcpd:':
                return DHCPDLogEntry(line)
            else:
                return f'Unknown process name {process}'
        except ValueError as e:
            print(f'Could not parse line: {line}')
            return f'ERROR: Could not parse line {line}'

class LogEntry:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None

class FirewallLogEntry(LogEntry):

    def field_iter(self, line):
        for token in line.split(','):
            yield token

    def __init__(self, line):
        """Parses a line such as·
         2019-07-20T14:29:41+00:00 pfsense1.flavortown.space filterlog: 101,,,1558485159,bge1,match,block,in,4,0x0,,63,35995,0,DF,6,tcp,60,192.168.3.13,172.217.7.132,33374,8080,0,S,1414818328,,64240,,mss;sackOK;TS;nop;wscale"""

        super().__init__()

        # Split the line to get the actual syslog content
        date, hostname, process, content = line.split(' ')

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

        self.src_hostname = None
        self.dst_hostname = None




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

    def __init__(self, line):
        self.line = line.split('dhcpd: ')[1]

    def __str__(self):
        return self.line


if __name__ == '__main__':
    test_data = '''2020-12-21T04:47:56 pfsense filterlog: 104,,,1607568163,igb1,match,block,in,4,0x0,,64,23250,0,DF,6,tcp,60,192.168.3.116,142.250.31.188,51436,5228,0,S,2467571369,,14600,,mss;sackOK;TS;nop;wscale
2020-12-21T18:15:18 pfsense filterlog: 105,,,1607568163,igb1,match,block,in,4,0x0,,64,0,0,DF,17,udp,164,192.168.3.127,23.23.78.10,50121,40317,144
2020-12-21T23:41:54 pfsense filterlog: 105,,,1607568163,igb1,match,block,in,4,0x0,,64,28156,0,DF,6,tcp,83,192.168.3.22,3.225.189.191,60967,443,31,PA,2920519110:2920519141,597669648,590,,nop;nop;TS
2020-12-21T04:47:29 pfsense filterlog: 104,,,1607568163,igb1,match,block,in,4,0x0,,64,60842,0,DF,1,icmp,84,192.168.3.20,172.217.2.110,request,2,464'''


    for line in test_data.split('\n'):
        entry = LogEntry(line)
        print(entry)
