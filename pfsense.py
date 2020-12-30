from itertools import chain
import threading
from time import sleep
from os import path

from errbot import BotPlugin, botcmd, arg_botcmd, webhook, ValidationException
import tailer

from resolver import DNSCache
from log import LogParser

CONFIG_TEMPLATE = {
    'LOG_FILE': '/does/not/exist',     # pfSense log file to display
    'DELAY': 2,                        # Delay, in seconds, to give the DNS resolver time to resolve
    'REVERSE_DNS_LOOKUP': True,        # Do reverse DNS lookup on IP addresses
    'DEFAULT_IDENTIFIER_STR': '#bots'  # Where to send the log entry messages
}

def log_thread(bot):

    log_file = bot.config.get('LOG_FILE')
    default_identifier = bot.config.get('DEFAULT_IDENTIFIER_STR')
    reverse_dns_lookup = bot.config.get('REVERSE_DNS_LOOKUP', False)

    identifier = bot.build_identifier(default_identifier)

    bot.send(identifier, f'Starting thread using {log_file}')

    if reverse_dns_lookup:
        parser = LogParser(bot.dns_cache)
    else:
        parser = LogParser(None)

    for line in tailer.follow(open(bot.config.get('LOG_FILE'), 'r')):
        try:
            entry = parser.parse(line)
            if not entry:  # The parse method will return None if it thinks we won't care about the line
                continue

            # Give the resolver a few seconds
            sleep(bot.config.get('DELAY', 2))
            bot.send(identifier, str(entry))

        except Exception as e:
            bot.log.error(e)
            raise e


class Pfsense(BotPlugin):
    """
    An errbot plugin for displaying pfSense firewall logs
    """

    @botcmd
    def start_log(self, message, args):
        """Starts displaying the logs"""
        if not self.running:
            self.running = True
            self.thread.start()
            return 'Starting'
        else:
            return 'Already running'

    @botcmd
    def stop_log(self, message, args):
        if not self.running:
            return 'Not running'
        self.running = False
        return 'Stopped'

    def activate(self):
        """
        Triggers on plugin activation
        """
        super(Pfsense, self).activate()
        default_identifier = self.config.get('DEFAULT_IDENTIFIER_STR', '')
        if not default_identifier:
            self.log.warn('No default identifier set')

        self.default_identifier = self.build_identifier(default_identifier)
        self.thread = threading.Thread(target=log_thread, args=(self,))

        self.dns_cache = DNSCache()
        self.dns_cache.start()
        self.running = False

    def configure(self, configuration):
        if configuration is not None and configuration != {}:
            config = dict(chain(CONFIG_TEMPLATE.items(), configuration.items()))
        else:
            config = CONFIG_TEMPLATE
        super(Pfsense, self).configure(config)

    def deactivate(self):
        """
        Triggers on plugin deactivation

        You should delete it if you're not using it to override any default behaviour
        """
        super(Pfsense, self).deactivate()

    def get_configuration_template(self):
        """
        Defines the configuration structure this plugin supports
        """
        return CONFIG_TEMPLATE

    def check_configuration(self, configuration):
        """
        Triggers when the configuration is checked, shortly before activation
        """
        # If we specified a LOG_FILE path, check to see if it actually exists
        if configuration.get('LOG_FILE') and not path.isfile(configuration.get('LOG_FILE')):
            raise ValidationException(f'Could not find file {configuration["LOG_FILE"]}')

    def callback_connect(self):
        """
        Triggers when bot is connected
        """
        pass

    def callback_message(self, message):
        """
        Triggered for every received message that isn't coming from the bot itself
        """
        pass

    def callback_botmessage(self, message):
        """
        Triggered for every message that comes from the bot itself
        """
        pass

