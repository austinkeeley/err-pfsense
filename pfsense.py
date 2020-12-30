from itertools import chain
import logging
import threading
from time import sleep
from os import path

from errbot import BotPlugin, botcmd, arg_botcmd, webhook, ValidationException
import tailer

from resolver import DNSCache
#from log import FirewallLogEntry
from log import LogParser

CONFIG_TEMPLATE = {
    'LOG_FILE': '/does/not/exist',     # pfSense log file to display
    'DELAY': 2,                        # Delay, in seconds, to give the DNS resolver time to resolve
    'REVERSE_DNS_LOOKUP': True,        # Do reverse DNS lookup on IP addresses
    'DEFAULT_IDENTIFIER_STR': '#bots'  # Where to send the log entry messages
}

def log_thread(bot):
    if not bot.config:
        bot.send(bot.default_identifier, 'Not configured')
        return

    bot.send(bot.default_identifier, f"Starting thread using {bot.config['LOG_FILE']}")
    bot.running = True

    if bot.config.get('REVERSE_DNS_LOOKUP', False):
        parser = LogParser(bot.dns_cache)
    else:
        parser = LogParser(None)

    for line in tailer.follow(open(bot.config.get('LOG_FILE'), 'r')):
        try:
            entry = parser.parse(line)
            if not entry:
                continue

            # Give the resolver a few seconds
            sleep(bot.config.get('DELAY', 2))
            bot.send(bot.default_identifier, str(entry))

        except Exception as e:
            print(e)
            raise e


class Pfsense(BotPlugin):
    """
    An errbot plugin for displaying pfSense firewall logs
    """

    @botcmd
    def start_log(self, message, args):
        """Starts displaying the logs"""
        if not self.running:
            self.thread.start()
            return 'Starting'
        else:
            return 'Already running'

    @botcmd
    def stop_log(self, message, args):
        pass

    def activate(self):
        """
        Triggers on plugin activation
        """
        super(Pfsense, self).activate()
        self.default_identifier = self.build_identifier(self.config.get('DEFAULT_IDENTIFIER_STR', ''))
        self.thread = threading.Thread(target=log_thread, args=(self,))

        self.running = False   # is running and displaying
        self.dns_cache = DNSCache()
        self.dns_cache.start()

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

        You should delete it if your plugin doesn't use any configuration like this
        """
        return CONFIG_TEMPLATE

    def check_configuration(self, configuration):
        """
        Triggers when the configuration is checked, shortly before activation
        """
        #super(Pfsense, self).check_configuration(configuration)
        if not path.isfile(configuration.get('LOG_FILE')):
            raise ValidationException(f'Could not find file {configuration["LOG_FILE"]}')

    def callback_connect(self):
        """
        Triggers when bot is connected

        You should delete it if you're not using it to override any default behaviour
        """
        pass

    def callback_message(self, message):
        """
        Triggered for every received message that isn't coming from the bot itself

        You should delete it if you're not using it to override any default behaviour
        """
        pass

    def callback_botmessage(self, message):
        """
        Triggered for every message that comes from the bot itself

        You should delete it if you're not using it to override any default behaviour
        """
        pass

