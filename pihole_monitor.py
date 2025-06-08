import argparse
import json
import os
import re
import sys
from typing import Dict, List, Tuple
import time

import requests

# Ensure the working directory is the script's directory so that relative
# paths (like the configuration file) resolve correctly when the script is
# run from cron or other automated jobs.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'tinder-detector.conf')

def load_config(path: str) -> Dict[str, str]:
    config: Dict[str, str] = {}
    if os.path.exists(path):
        with open(path, 'r') as cfg:
            for line in cfg:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    return config

_cfg = load_config(CONFIG_PATH)

LOG_PATH = '/var/log/pihole/pihole.log'
STATE_PATH = '/var/tmp/pihole_monitor_state.json'
TARGET_DOMAINS = ['tinder.com', 'badoo.com', 'sympatia.pl']
EMAIL_INTERVAL = 30 * 60  # 30 minutes
LOG_PATTERN = re.compile(
    r"^(?P<time>\w+\s+\d+\s+\d+:\d+:\d+).*?query\[[^\]]+\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)"
)

MAILGUN_API_KEY = _cfg.get('api_key') or os.getenv('MAILGUN_API_KEY')
MAILGUN_DOMAIN = _cfg.get('mg_domain') or os.getenv('MAILGUN_DOMAIN')
MAILGUN_API_URL = _cfg.get('api_url') or os.getenv('MAILGUN_API_URL', 'https://api.mailgun.net')
MAILGUN_FROM = _cfg.get('from_addr') or os.getenv('MAILGUN_FROM')
MAILGUN_TO = _cfg.get('to_addr') or os.getenv('MAILGUN_TO')

def load_state(path: str) -> Dict:
    if os.path.exists(path):
        with open(path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_state(path: str, state: Dict) -> None:
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w') as f:
        json.dump(state, f)
    os.replace(tmp_path, path)

def send_mail(domain: str, ip: str, events: List[Tuple[str, str]], debug: bool = False) -> bool:
    api_key = MAILGUN_API_KEY
    mg_domain = MAILGUN_DOMAIN
    from_addr = MAILGUN_FROM
    to_addr = MAILGUN_TO
    if not all([api_key, mg_domain, from_addr, to_addr]):
        if debug:
            print('Mailgun configuration not fully set')
        return False
    if not events:
        return True
    subject = f'Wykryto {len(events)} odwo\u0142a\u0144 do domeny {domain} z adresu {ip}'
    lines = [
        f"{idx}. {raw} o {ts}" for idx, (raw, ts) in enumerate(events, 1)
    ]
    text = (
        f"Wykryte odwo\u0142ania do domeny {domain} z adresu {ip}:\n" +
        "\n".join(lines)
    )
    if debug:
        print('Sending email:', subject)
    try:
        resp = requests.post(
            f'{MAILGUN_API_URL}/v3/{mg_domain}/messages',
            auth=('api', api_key),
            data={
                'from': from_addr,
                'to': [to_addr],
                'subject': subject,
                'text': text,
            },
            timeout=10,
        )
        if debug:
            print('Mailgun response:', resp.status_code, resp.text)
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        if debug:
            print('Failed to send email:', e)
        return False

def process_log(debug: bool = False) -> None:
    state = load_state(STATE_PATH)
    offset = state.get('offset', 0)
    last_sent: Dict[str, Dict[str, float]] = state.get('last_sent', {})
    pending: Dict[str, Dict[str, List[Tuple[str, str]]]] = state.get('pending', {})

    try:
        f = open(LOG_PATH, 'r')
    except FileNotFoundError:
        if debug:
            print('Log file not found:', LOG_PATH)
        return

    with f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if offset > end:
            offset = 0  # log rotated
        f.seek(offset)
        for line in f:
            # Print only relevant events in debug mode, not full log lines
            # to avoid cluttering the output with raw log contents.
            m = LOG_PATTERN.search(line)
            if not m:
                continue
            raw_domain = m.group('domain').lower()
            ip = m.group('ip')
            event_time = m.group('time')
            for target in TARGET_DOMAINS:
                if raw_domain == target or raw_domain.endswith('.' + target):
                    if debug:
                        print('Match:', raw_domain, 'from', ip)
                    pending.setdefault(ip, {}).setdefault(target, []).append((raw_domain, event_time))
        new_offset = f.tell()

    now = time.time()
    for ip, domains in list(pending.items()):
        for domain, events in list(domains.items()):
            last = last_sent.get(ip, {}).get(domain, 0)
            if events and now - last >= EMAIL_INTERVAL:
                if send_mail(domain, ip, events, debug):
                    pending[ip][domain] = []
                    last_sent.setdefault(ip, {})[domain] = now
                elif debug:
                    print('Notification not sent for', domain, 'from', ip)
        pending[ip] = {d: ev for d, ev in domains.items() if ev}
        if not pending[ip]:
            pending.pop(ip, None)

    state = {
        'offset': new_offset,
        'last_sent': last_sent,
        'pending': pending,
    }
    save_state(STATE_PATH, state)
    if debug:
        print('State saved. Offset:', new_offset)

def main():
    parser = argparse.ArgumentParser(description='Monitor Pi-hole log for specific domains')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()
    process_log(debug=args.debug)

if __name__ == '__main__':
    main()
