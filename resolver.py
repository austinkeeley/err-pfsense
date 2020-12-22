import threading

import dns
from dns import reversename, resolver
from queue import Queue

class DNSCache(object):
    """A simple DNS cache"""

    def __init__(self):
        self.cache = {}
        self.queue = Queue()

    def start(self):
        print('Starting DNSCache')
        t = threading.Thread(target=self.resolve_queue_thread)
        t.start()


    def resolve_queue_thread(self):
        print('Running resolve queue thread')
        while True:
            ip_address = self.queue.get(True)
            print('Received request to resolve {}'.format(ip_address))
            rev_name = reversename.from_address(ip_address)
            try:
                hostname = str(resolver.query(rev_name, "PTR")[0])
                self.cache[ip_address] = (hostname, 'resolved')
                print('Done resolving! {} --> {}'.format(ip_address, hostname))
            except resolver.NoNameservers:
                self.cache[ip_address] = (None, 'bad')
            except dns.resolver.Timeout:
                self.cache[ip_address] = (None, 'bad')
            except dns.resolver.NXDOMAIN:
                self.cache[ip_address] = (None, 'bad')


    def resolve(self, ip_address):
        """Resolves an IP to an address"""
        entry = self.cache.get(ip_address, None)

        if not entry:
            self.add_to_resolve_queue(ip_address)
            return None

        if entry[1] == 'queued' or entry[1] == 'bad':
            return None

        else:
            return entry[0]

    def add_to_resolve_queue(self, ip_address):
        print('Adding {} to resolve queue'.format(ip_address))
        self.cache[ip_address] = (None, 'queued')
        self.queue.put(ip_address)

if __name__ == '__main__':
    cache = DNSCache()
    cache.start()
    cache.add_to_resolve_queue('8.8.8.8')


