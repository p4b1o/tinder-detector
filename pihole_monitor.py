import argparse
import json
import os
import re
import sys
from typing import Dict, Set

import requests

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
LOG_PATTERN = re.compile(r"query\[[^\]]+\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)")

MAILGUN_API_KEY = _cfg.get('api_key') or os.getenv('MAILGUN_API_KEY')
MAILGUN_DOMAIN = _cfg.get('mg_domain') or os.getenv('MAILGUN_DOMAIN')
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

def send_mail(domain: str, ip: str, raw_domain: str, debug: bool = False) -> None:
    api_key = MAILGUN_API_KEY
    mg_domain = MAILGUN_DOMAIN
    from_addr = MAILGUN_FROM
    to_addr = MAILGUN_TO
    if not all([api_key, mg_domain, from_addr, to_addr]):
        if debug:
            print('Mailgun configuration not fully set')
        return
    subject = f'Pi-hole detection: {raw_domain} from {ip}'
    text = f'Domain: {raw_domain}\nClient IP: {ip}\nMatched pattern: {domain}'
    if debug:
        print('Sending email:', subject)
    try:
        resp = requests.post(
            f'https://api.mailgun.net/v3/{mg_domain}/messages',
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
    except Exception as e:
        if debug:
            print('Failed to send email:', e)

def process_log(debug: bool = False) -> None:
    state = load_state(STATE_PATH)
    offset = state.get('offset', 0)
    seen: Dict[str, Set[str]] = {k: set(v) for k, v in state.get('seen', {}).items()}

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
            if debug:
                print('LINE:', line.strip())
            m = LOG_PATTERN.search(line)
            if not m:
                continue
            raw_domain = m.group('domain').lower()
            ip = m.group('ip')
            for target in TARGET_DOMAINS:
                if raw_domain == target or raw_domain.endswith('.' + target):
                    if ip not in seen or target not in seen[ip]:
                        send_mail(target, ip, raw_domain, debug)
                        seen.setdefault(ip, set()).add(target)
        new_offset = f.tell()

    state = {
        'offset': new_offset,
        'seen': {k: list(v) for k, v in seen.items()},
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
