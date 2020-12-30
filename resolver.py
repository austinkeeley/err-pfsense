import threading
import logging

import dns
from dns import reversename, resolver
from queue import Queue

class DNSCache(object):
    """A simple DNS cache"""

    def __init__(self):
        self.cache = {}
        self.queue = Queue()

    def start(self):
        logging.info('Starting DNSCache')
        t = threading.Thread(target=self.resolve_queue_thread)
        t.start()

    def resolve_queue_thread(self):
        logging.debug('Running resolve queue thread')
        while True:
            ip_address, cb = self.queue.get(True)
            logging.debug('Received request to resolve {}'.format(ip_address))
            rev_name = reversename.from_address(ip_address)
            try:
                hostname = str(resolver.query(rev_name, "PTR")[0])
                self.cache[ip_address] = (hostname, 'resolved')
                logging.debug('Done resolving! {} --> {}'.format(ip_address, hostname))
                if cb:
                    cb(ip_address, hostname)
            except resolver.NoNameservers:
                self.cache[ip_address] = (None, 'bad')
                if cb:
                    cb(ip_address, None)
            except dns.resolver.Timeout:
                self.cache[ip_address] = (None, 'bad')
                if cb:
                    cb(ip_address, None)
            except dns.resolver.NXDOMAIN:
                self.cache[ip_address] = (None, 'bad')
                if cb:
                    cb(ip_address, None)


    def resolve(self, ip_address, cb=None):
        """Resolves an IP to an address. This either returns a hostname or
        returns None and adds the IP address to the resolve queue."""
        entry = self.cache.get(ip_address, None)

        if not entry:
            self.add_to_resolve_queue(ip_address, cb)
            return None

        if entry[1] == 'queued' or entry[1] == 'bad':
            return None

        else:
            return entry[0]

    def add_to_resolve_queue(self, ip_address, cb=None):
        """Adds an IP address to the queue to be resolved asynchronously. 
        Args:
            ip_address - The IP to resolve
            cb - Callback that will receive ip, hostname
        """
        logging.debug('Adding {} to resolve queue'.format(ip_address))
        self.cache[ip_address] = (None, 'queued')
        self.queue.put((ip_address, cb))

if __name__ == '__main__':
    cache = DNSCache()
    cache.start()
    cache.add_to_resolve_queue('8.8.8.8')


