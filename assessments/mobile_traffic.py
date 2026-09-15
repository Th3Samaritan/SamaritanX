"""Passive HAR review and value-free API seeds; never replays captured credentials."""
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl
from .common import result, candidate, read_limited

SENSITIVE = re.compile(r"password|passwd|token|secret|authorization|cookie|api.?key", re.I)


def assess(path, allowed_hosts):
    hosts = {str(host).lower().rstrip('.') for host in allowed_hosts}
    if not hosts or any('/' in host or ':' in host or '*' in host for host in hosts):
        raise ValueError("provide exact API host names for HAR scope")
    data = json.loads(read_limited(path, 32 * 1024 * 1024))
    entries = data.get("log", {}).get("entries", [])
    if not isinstance(entries, list) or len(entries) > 20000:
        raise ValueError("invalid or oversized HAR")
    report = result("mobile_traffic", "scoped HAR")
    seeds, seen, excluded = [], set(), 0
    for index, entry in enumerate(entries):
        request = entry.get("request") or {}
        parsed = urlsplit(request.get("url", ""))
        if parsed.scheme not in {"http", "https"} or parsed.username or (parsed.hostname or '').lower().rstrip('.') not in hosts:
            excluded += 1
            continue
        names = {str(row.get('name', '')) for row in request.get('headers', [])}
        params = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        post = request.get('postData') or {}
        body_keys = {str(row.get('name', '')) for row in post.get('params', [])}
        if post.get('mimeType', '').startswith('application/json'):
            try:
                body = json.loads(post.get('text', '{}'))
                if isinstance(body, dict): body_keys.update(body)
            except (ValueError, TypeError):
                pass
        if parsed.scheme == 'http':
            sensitive = any(SENSITIVE.search(key) for key in names | params | body_keys) or bool(request.get('cookies'))
            candidate(report, 'mobile_cleartext_traffic', 'Observed unencrypted application request',
                      f"HAR entry {index} used HTTP; credential-like fields present: {sensitive}.",
                      'Use HTTPS and validate transport behavior on the supported device versions.')
        method = str(request.get('method', 'GET')).upper()
        if method not in {'GET', 'HEAD'}:
            continue
        # Authentication inputs must come from a separate scoped auth recipe.
        if any(SENSITIVE.search(key) for key in params):
            continue
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))
        key = (method, url, tuple(sorted(params)))
        if key not in seen:
            seen.add(key)
            seeds.append({'url': url, 'params': sorted(params), 'method': method, 'form': None})
    report['api_seeds'] = seeds
    report['checks'].append({'check': 'scoped_har', 'status': 'observed', 'entries': len(entries),
                             'excluded': excluded, 'read_only_seeds': len(seeds)})
    report['limitations'].append('Captured traffic covers recorded flows only. HTTPS in HAR does not prove certificate validation or pinning. Cookies, headers and body values are not replayed.')
    return report


def load_seeds(path):
    seeds = json.loads(read_limited(path))
    if not isinstance(seeds, list) or len(seeds) > 2000:
        raise ValueError('API seeds must be a list with at most 2000 entries')
    output = []
    for seed in seeds:
        parsed = urlsplit(seed.get('url', ''))
        method = seed.get('method', 'GET').upper()
        params = seed.get('params', [])
        if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError('API seed must contain an HTTP URL without credentials, query values or fragments')
        if method not in {'GET','HEAD'} or seed.get('form') or not isinstance(params, list) or len(params) > 100:
            raise ValueError('only bounded read-only API seeds are supported')
        if any(not isinstance(key, str) or len(key) > 128 or SENSITIVE.search(key) for key in params):
            raise ValueError('API seed contains sensitive or malformed parameter names')
        output.append({'url': seed['url'], 'params': params, 'method': method, 'form': None})
    return output


async def enqueue_seeds(path, queue, controller, target, *, passive=False):
    from core.transport import TransportBlocked
    if passive:
        return {'queued': 0, 'excluded': 0}
    counts = {'queued': 0, 'excluded': 0}
    for payload in load_seeds(path):
        try:
            await controller.check_scope(payload['url'])
        except TransportBlocked:
            counts['excluded'] += 1
            continue
        await queue.put('scan', payload, target=target, priority=3, producer='mobile-traffic')
        counts['queued'] += 1
    return counts
