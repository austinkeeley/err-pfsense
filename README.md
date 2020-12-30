err-pfsense
============

An Errbot plugin for displaying pfSense firewall and DHCP logs.

## Install

Run the following Errbot command

    !repos install https://github.com/austinkeeley/err-pfsense.git

## Setup

Configure the bot by running 

    !plugin config pfsense {'LOG_FILE': '/path/to/your/syslog/file'}

The plugin expects the logs to be in the RFC3164 "BSD Style" syslog output, e.g.

    <134>Dec 30 22:40:34 pfsense.hostname tag: message_contents_here

Begin the log streaming with the command

    !start log

## Configuration Options

| Option                   | Type    | Value                                                                               |
|--------------------------|---------|-------------------------------------------------------------------------------------|
| `LOG_FILE`               | string  | Path to the syslog file to display                                                  |
| `REVERSE_DNS_LOOKUP`     | Boolean | Perform the IP to hostname lookup                                                   |
| `DELAY`                  | integer | Delay, in seconds, to allow the DNS lookup to happen                                |
| `DEFAULT_IDENTIFIER_STR` | integer | Errbot identifier string (e.g. the room name) to send log messages to, e.g. `#bots` |
