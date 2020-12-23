err-pfsense
============

An errbot plugin for displaying pfSense firewall logs.

## Setup

Configure the bot by running 

    `!plugin config pfsense {'LOG_FILE': '/path/to/your/syslog/file'}`

The plugin expects the logs to be in the format of

    DATE HOST LOG_NAME: PFSENSE_LOG_CONTENT



## Configuration Options

| Option               | Type    | Value                                                |
|----------------------|---------|------------------------------------------------------|
| `LOG_FILE`           | string  | Path to the syslog file to display                   |
| `REVERSE_DNS_LOOKUP` | Boolean | Perform the IP to hostname lookup                    |
| `DELAY`              | integer | Delay, in seconds, to allow the DNS lookup to happen |
