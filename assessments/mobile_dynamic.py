"""Appium session assessment for Android/iOS with app identity checks and gated flows."""
import asyncio
import hashlib
import os
import re
from urllib.parse import urlsplit, quote
import httpx
from .common import result, candidate
from .android_xml import parse


class AppiumError(RuntimeError):
    pass


class Session:
    def __init__(self, server, session_id, platform, app_id, *, transport=None):
        parsed = urlsplit(server)
        if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError('Appium URL must be an explicit HTTP(S) server without credentials or query')
        if platform not in {'android','ios'} or not re.fullmatch(r'[A-Za-z0-9._-]+', app_id):
            raise ValueError('invalid mobile platform or application identifier')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', session_id):
            raise ValueError('invalid Appium session ID')
        self.base = server.rstrip('/') + '/session/' + session_id
        self.platform, self.app_id = platform, app_id
        self.operations = 0
        self.client = httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=False, transport=transport)

    async def call(self, method, path, payload=None):
        if self.operations >= 250:
            raise AppiumError("Appium operation budget exhausted")
        self.operations += 1
        async with self.client.stream(method, self.base + path, json=payload) as response:
            data = bytearray()
            async for block in response.aiter_bytes():
                data.extend(block)
                if len(data) > 8 * 1024 * 1024:
                    raise AppiumError('Appium response exceeds limit')
            import json
            try: message = json.loads(data)
            except ValueError: raise AppiumError('Appium returned a non-JSON response') from None
            value = message.get('value')
            if response.status_code >= 300 or (isinstance(value, dict) and value.get('error')):
                code = value.get('error', 'http_error') if isinstance(value, dict) else 'http_error'
                raise AppiumError(f'Appium {code} (HTTP {response.status_code})')
            return value

    async def assert_app(self):
        if self.platform == 'android':
            actual = await self.call('GET', '/appium/device/current_package')
        else:
            info = await self.call('POST', '/execute/sync', {'script': 'mobile: activeAppInfo', 'args': []})
            actual = info.get('bundleId') if isinstance(info, dict) else None
        if actual != self.app_id:
            raise AppiumError('foreground application does not match the authorized app identifier')

    async def inspect(self, report):
        await self.assert_app()
        source = await self.call('GET', '/source')
        if not isinstance(source, str):
            raise AppiumError('missing UI hierarchy')
        try:
            root = parse(source.encode('utf-8'))
        except (ValueError, SyntaxError):
            raise AppiumError('UI hierarchy could not be parsed') from None
        nodes = list(root.iter())
        for node in nodes:
            label = ' '.join(str(node.get(key, '')) for key in ('resource-id','name','label','content-desc'))
            is_password_name = bool(re.search(r'password|passcode|pin_code', label, re.I))
            android_field = self.platform == 'android' and node.get('class', node.tag).endswith('EditText') and node.get('password') == 'false'
            ios_field = self.platform == 'ios' and node.tag == 'XCUIElementTypeTextField'
            if is_password_name and (android_field or ios_field):
                candidate(report, 'mobile_password_ui', 'Potentially unmasked password input',
                          'The current UI contains a password-named text field without the expected secure-input type. Input contents were not retained.',
                          'Verify the field behavior and use the platform secure password-input control.')
        report['checks'].append({'check':'ui_hierarchy','status':'observed','nodes':len(nodes),
                                'sha256':hashlib.sha256(source.encode()).hexdigest()})
        try:
            contexts = await self.call('GET', '/contexts')
            report['checks'].append({'check':'webview_inventory','status':'observed',
                'webviews':sum(str(item).startswith('WEBVIEW') for item in contexts or [])})
        except AppiumError as exc:
            report['status'] = 'partial'
            report['checks'].append({'check':'webview_inventory','status':'unavailable','reason':str(exc)})

    async def flow(self, steps, report, aggressive=False):
        if steps and not aggressive:
            raise ValueError('UI flows can change app state; --aggressive is required')
        if not isinstance(steps, list) or len(steps) > 30:
            raise ValueError('flow must contain at most 30 steps')
        for index, step in enumerate(steps):
            if step.get('action') not in {'click','type'} or step.get('using') not in {'id','accessibility id','xpath'}:
                raise ValueError('flow supports click/type and id/accessibility id/xpath selectors')
            if not isinstance(step.get('selector'), str) or len(step['selector']) > 2000:
                raise ValueError('invalid selector')
            if step['action'] == 'type' and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', str(step.get('value_env',''))):
                raise ValueError('typed values must reference an environment variable via value_env')
            if step['action'] == 'type' and (step['value_env'] not in os.environ or len(os.environ[step['value_env']]) > 8192):
                raise ValueError('flow environment variable is missing or exceeds the input limit')
        for index, step in enumerate(steps):
            await self.assert_app()
            element = await self.call('POST', '/element', {'using':step['using'],'value':step['selector']})
            identifier = element.get('element-6066-11e4-a52e-4f735466cecf') or element.get('ELEMENT')
            if not identifier:
                raise AppiumError('element lookup returned no identifier')
            path = '/element/' + quote(str(identifier), safe='')
            if step['action'] == 'click':
                await self.call('POST', path + '/click', {})
            else:
                value = os.environ.get(step['value_env'])
                if value is None:
                    raise ValueError('flow environment variable is missing')
                await self.call('POST', path + '/value', {'text':value})
            await self.assert_app()
            report['checks'].append({'check':'flow_step','index':index,'status':'completed','action':step['action']})
            await self.inspect(report)


async def assess(server, session_id, platform, app_id, *, steps=None, aggressive=False, transport=None):
    report = result('mobile_dynamic', app_id)
    report['platform'] = platform
    session = Session(server, session_id, platform, app_id, transport=transport)
    try:
        if steps and not aggressive:
            raise ValueError('UI flows require --aggressive')
        async def workflow():
            await session.inspect(report)
            await session.flow(steps or [], report, aggressive)
        await asyncio.wait_for(workflow(), timeout=180)
    except (httpx.HTTPError, AppiumError, asyncio.TimeoutError) as exc:
        report['status'] = 'blocked' if not report['checks'] else 'partial'
        report['checks'].append({'check':'appium_session','status':'unavailable',
                                'reason':str(exc) if isinstance(exc, AppiumError) else type(exc).__name__})
    finally:
        await session.client.aclose()
    report['operations'] = session.operations
    report['limitations'].append('Attaches to an existing session; no app installation, rooting, jailbreak, certificate bypass or runtime code injection. UI observations cover inspected screens only; use scoped HAR review for captured network behavior.')
    return report
