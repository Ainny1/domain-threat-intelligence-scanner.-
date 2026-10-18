"""Defensive, low-impact public domain metadata checks."""
from __future__ import annotations
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
import ssl
from urllib.request import Request, urlopen

LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')

def normalize_domain(value: str) -> str:
    """Accept a hostname, not a URL or IP literal; return an ASCII DNS name."""
    if not isinstance(value, str):
        raise ValueError('A domain name is required')
    name = value.strip().rstrip('.').lower()
    if not name or any(c in name for c in '/:@?#\\'):
        raise ValueError('Enter a domain name, not a URL')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError('IP addresses are not supported')
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise ValueError('Invalid internationalized domain') from e
    labels = name.split('.')
    if len(name) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(s) for s in labels) or labels[-1].isdigit():
        raise ValueError('Invalid domain name')
    return name

def dns_addresses(domain: str) -> dict:
    addresses = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.add(sockaddr[0])
        return {'addresses': sorted(addresses), 'error': None}
    except (socket.gaierror, OSError) as exc:
        return {'addresses': [], 'error': type(exc).__name__}

def tls_metadata(domain: str, timeout: float = 4) -> dict:
    """Read public TLS certificate metadata; no port scanning."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as session:
                cert = session.getpeercert()
                expires_str = cert.get('notAfter')
                expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires_str), timezone.utc) if expires_str else None
                remaining = (expires - datetime.now(timezone.utc)).days if expires else None
                return {'valid_for_hostname': True, 'expires_utc': expires.isoformat() if expires else None,
                        'days_remaining': remaining, 'protocol': session.version(), 'error': None}
    except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
        return {'valid_for_hostname': False, 'expires_utc': None, 'days_remaining': None,
                'protocol': None, 'error': type(exc).__name__}

def rdap_metadata(domain: str, timeout: float = 4) -> dict:
    """Query the public RDAP endpoint; retain only dates and status."""
    from urllib.parse import quote
    req = Request('https://rdap.org/domain/' + quote(domain, safe=''), headers={'User-Agent': 'domain-intel-portfolio/0.1'})
    try:
        with urlopen(req, timeout=timeout) as response:
            if response.status != 200 or int(response.headers.get('Content-Length', '0')) > 1_000_000:
                raise ValueError('Unexpected RDAP response')
            data = json.loads(response.read(1_000_001))
        dates = {}
        for item in data.get('events', []):
            if item.get('eventAction') in ('registration', 'expiration', 'last changed'):
                dates[item['eventAction']] = item.get('eventDate')
        return {'events': dates, 'status': data.get('status', []), 'error': None}
    except (OSError, ValueError, KeyError, TimeoutError) as exc:
        return {'events': {}, 'status': [], 'error': type(exc).__name__}

def findings(dns: dict, tls: dict, rdap: dict) -> list[dict]:
    result = []
    if not dns['addresses']:
        result.append({'severity': 'info', 'finding': 'Domain did not resolve during this check'})
    if tls['error']:
        result.append({'severity': 'review', 'finding': 'TLS certificate could not be verified'})
    elif tls['days_remaining'] is not None and tls['days_remaining'] < 30:
        result.append({'severity': 'review', 'finding': 'TLS certificate expires within 30 days'})
    if rdap['error']:
        result.append({'severity': 'info', 'finding': 'RDAP details unavailable'})
    return result

def scan(domain: str, timeout: float = 4) -> dict:
    name = normalize_domain(domain)
    dns = dns_addresses(name)
    tls = tls_metadata(name, timeout)
    rdap = rdap_metadata(name, timeout)
    return {'domain': name, 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
            'dns': dns, 'tls': tls, 'rdap': rdap, 'findings': findings(dns, tls, rdap),
            'scope': 'public DNS, standard HTTPS endpoint, and public RDAP only',
            'disclaimer': 'Indicators are informational, not proof of malicious activity.'}
