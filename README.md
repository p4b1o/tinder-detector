# tinder-detector

This repository contains a simple script for monitoring a Pi-hole instance for DNS queries to selected dating domains (`tinder.com`, `badoo.com`, `sympatia.pl`).

The script `pihole_monitor.py` reads only new lines from `/var/log/pihole.log` since the previous run and sends notifications via Mailgun when a new client IP is detected querying one of these domains. State is stored in `/var/tmp/pihole_monitor_state.json`.

## Usage

```bash
pip install --user requests  # first time only
python3 pihole_monitor.py [-d]
```

Use the `-d` or `--debug` flag to print additional debugging information.

Mailgun API credentials must be provided via the following environment variables:

- `MAILGUN_API_KEY`
- `MAILGUN_DOMAIN`
- `MAILGUN_FROM`
- `MAILGUN_TO`

The script is designed to be lightweight and can be scheduled via cron for periodic monitoring.
