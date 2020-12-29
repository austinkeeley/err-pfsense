from itertools import chain
import threading
from time import sleep

from errbot import BotPlugin, botcmd, arg_botcmd, webhook
import tailer

from resolver import DNSCache
#from log import FirewallLogEntry
from log import LogParser

CONFIG_TEMPLATE = {
    'LOG_FILE': '/does/not/exist',  # pfSense log file to display
    'DELAY': 2,                     # Delay, in seconds, to give the DNS resolver time to resolve
    'REVERSE_DNS_LOOKUP': True      # Do reverse DNS lookup on IP addresses
}

def log_thread(bot):
    if not bot.config:
        bot.send(bot.default_identifier, 'Not configured')
        return

    bot.send(bot.default_identifier, f"Starting thread using {bot.config['LOG_FILE']}")
    bot.running = True
    parser = LogParser()

    for line in tailer.follow(open(bot.config['LOG_FILE'], 'r')):
        try:
            entry = parser.parse(line)

            if bot.config.get('REVERSE_DNS_LOOKUP', True):
                if entry.src_ip:
                    bot.dns_cache.resolve(entry.src_ip)
                if entry.dst_ip:
                    bot.dns_cache.resolve(entry.dst_ip)

                # Give the DNS resolver a few seconds
                sleep(bot.config.get('DELAY', 2))

                entry.src_hostname = bot.dns_cache.resolve(entry.src_ip)
                entry.dst_hostname = bot.dns_cache.resolve(entry.dst_ip)
            bot.send(bot.default_identifier, str(entry))
        except ValueError as e:
            print(e)
            raise e
        except IndexError as e:
            print(e)
            raise e
        # As we find more weird errors add them here.


class Pfsense(BotPlugin):
    """
    An errbot plugin for displaying pfSense firewall logs
    """

    @botcmd
    def start_log(self, message, args):
        """Starts displaying the logs"""
        self.thread.start()

    def activate(self):
        """
        Triggers on plugin activation

        You should delete it if you're not using it to override any default behaviour
        """
        super(Pfsense, self).activate()
        self.default_identifier = self.build_identifier('#flavortown')
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

        Raise a errbot.ValidationException in case of an error

        You should delete it if you're not using it to override any default behaviour
        """
        super(Pfsense, self).check_configuration(configuration)

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

