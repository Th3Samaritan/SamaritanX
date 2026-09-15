"""Offline regression cases for the implementation audit defects."""
import asyncio, json, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock, patch
import httpx
from core.http_client import StealthHttpClient
from core.transport import TransportController, current_transport, guard_browser
from core.run_manifest import template_selection_digest
from core.circuit import CircuitBreaker, CircuitConfig
from core.retention import apply
from core.grouping import group_key
from core.decision_trace import build_trace
from agents.vuln_agent import VulnerabilityAgent

async def main():
    results = {}
    cfg = {'stealth': {'enabled': False}, 'transport': {'circuit_breaker': {'enabled': False}}}
    client = StealthHttpClient(cfg)
    await client.close()
    seen = []

    def respond(req):
        seen.append((str(req.url), req.headers.get('x-api-key')))
        return httpx.Response(302, headers={'Location': 'http://second.test/'}) if req.url.host == 'first.test' else httpx.Response(200, text='ok')
    raw = httpx.AsyncClient(transport=httpx.MockTransport(respond), event_hooks={'request': [client._transport_request_guard]}, follow_redirects=True)
    client._client = raw
    client._clients = [raw]
    client.session = SimpleNamespace(headers={'X-Api-Key': 'fixture-only-key'}, cookies={}, origin='first.test', maybe_refresh=AsyncMock())
    await client.get('http://first.test/')
    await client.close()
    results['credential_forwarded_on_cross_origin_redirect'] = seen
    ctrl = TransportController({'transport': {'strict_mutations': True}, 'safety': {'aggressive': False}})
    context = SimpleNamespace(route=AsyncMock(), route_web_socket=AsyncMock())
    tok = current_transport.set(ctrl)
    try:
        await guard_browser(context)
        handler = context.route.call_args.args[1]
        route = SimpleNamespace(request=SimpleNamespace(url='http://fixture.test/save', method='POST'), continue_=AsyncMock(), abort=AsyncMock())
        await handler(route)
        results['browser_post_with_strict_mutations'] = {'forwarded': route.continue_.await_count, 'aborted': route.abort.await_count, 'operations': ctrl.used}
    finally:
        current_transport.reset(tok)
    base = Path('workspace').resolve()
    base.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='audit-', dir=base) as d:
        root = Path(d).resolve()
        assert root.is_relative_to(base)
        templates = root / 'templates'
        templates.mkdir()
        (templates / 'a.yaml').write_text('a')
        (templates / 'z.yaml').write_text('z')
        config = {'external_tools': {'nuclei_templates': str(templates)}}
        before = template_selection_digest(config, cap=1)
        (templates / 'z.yaml').write_text('changed content')
        results['unhashed_template_change_detected'] = before != template_selection_digest(config, cap=1)
        evidence = root / 'proof.json'
        evidence.write_text('{}')
        memory = Mock()
        memory.list_findings.return_value = [{'id': 1, 'metadata': {'evidence_bundle': {'file': str(evidence)}}}]
        plan = {'policy': {'enabled': True}, 'workspace': str(root), 'target': 'fixture', 'actions': [{'class': 'bundles', 'path': str(evidence), 'reason': 'expired'}]}
        with patch.object(Path, 'unlink', side_effect=PermissionError('fixture deletion denied')):
            result = apply(plan, confirm=True, memory=memory)
        results['failed_retention_delete'] = {'file_exists': evidence.exists(), 'deleted': result['deleted'], 'findings_marked': result['findings_marked']}
        catalog = root / 'catalog'
        catalog.mkdir()
        for name in ('one', 'two'):
            g = catalog / name
            g.mkdir()
            (g / 'template.yaml').write_text('id: fixture')
        (root / 'vulns').mkdir()
        agent = VulnerabilityAgent()
        conf = {'external_tools': {'nuclei_templates': str(catalog)}}
        ctx = SimpleNamespace(config=conf, workspace=root, dashboard=Mock(), memory=Mock(), target_slug='fixture', run_id='test', resume=False)
        proc = SimpleNamespace(wait=AsyncMock(return_value=0), returncode=0)
        with patch('agents.vuln_agent.external_tool_path', return_value='nuclei'), patch('agents.vuln_agent.managed_create_subprocess_exec', AsyncMock(return_value=proc)):
            await agent._run_nuclei('fixture.test', 'http://fixture.test/', ctx)
        results['catalog_config_mutated'] = {'before': str(catalog), 'after': conf['external_tools']['nuclei_templates']}
    now = [0.0]
    breaker = CircuitBreaker(CircuitConfig(failure_threshold=2, window_s=1, cooldown_s=2, half_open_probes=1), clock=lambda: now[0])
    breaker.record_failure()
    breaker.record_failure()
    now[0] = 3
    breaker.allows('GET')
    breaker.record_failure()
    now[0] = 100
    results['half_open_failed_probe'] = {'state': breaker.state, 'later_recovery_allowed': breaker.allows('GET')}
    a = {'id': 1, 'category': 'idor', 'url': 'http://fixture.test/obj', 'metadata': {'session_a': 'alice', 'session_b': 'bob'}}
    b = {'id': 2, 'category': 'idor', 'url': 'http://fixture.test/obj', 'metadata': {'session_a': 'alice', 'session_b': 'charlie'}}
    results['distinct_viewers_share_exact_group'] = group_key(a) == group_key(b)
    results['trace_without_clean_baseline'] = build_trace({'category': 'xss', 'response': 'attack response only', 'metadata': {}})['baseline']
    return results

class AuditRegressions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.r = asyncio.run(main())

    def test_redirect(self):
        self.assertIsNone(self.r['credential_forwarded_on_cross_origin_redirect'][1][1])

    def test_browser(self):
        self.assertEqual(self.r['browser_post_with_strict_mutations']['aborted'], 1)

    def test_digest(self):
        self.assertTrue(self.r['unhashed_template_change_detected'])

    def test_retention(self):
        self.assertTrue(self.r['failed_retention_delete']['file_exists'])
        self.assertEqual(self.r['failed_retention_delete']['findings_marked'], 0)

    def test_catalog(self):
        r = self.r['catalog_config_mutated']
        self.assertEqual(r['before'], r['after'])

    def test_circuit(self):
        self.assertEqual(self.r['half_open_failed_probe']['state'], 'open')
        self.assertTrue(self.r['half_open_failed_probe']['later_recovery_allowed'])

    def test_identity(self):
        self.assertFalse(self.r['distinct_viewers_share_exact_group'])

    def test_baseline(self):
        self.assertFalse(self.r['trace_without_clean_baseline']['response_captured'])

    def test_explicit_baseline(self):
        from core.decision_trace import evidence_hash
        r = build_trace({'response': 'attack', 'metadata': {'verification_baseline': {'response_excerpt': 'clean'}}})
        self.assertEqual(r['baseline']['baseline_hash'], evidence_hash('clean'))
        self.assertEqual(r['observation']['response_hash'], evidence_hash('attack'))

class AdditionalFailurePaths(unittest.IsolatedAsyncioTestCase):

    async def test_origin_redirect_boundaries(self):
        for destination, expected in [('http://first.test/next', 'fixture-key'), ('http://first.test:8080/', None), ('https://first.test/', None), ('http://sub.first.test/', None)]:
            with self.subTest(destination=destination):
                client = StealthHttpClient({'stealth': {'enabled': False}})
                await client.close()
                seen = []

                def respond(request):
                    seen.append(request.headers.get('x-api-key'))
                    return httpx.Response(302, headers={'Location': destination}) if len(seen) == 1 else httpx.Response(200)
                raw = httpx.AsyncClient(transport=httpx.MockTransport(respond), event_hooks={'request': [client._transport_request_guard]})
                client._client = raw
                client._clients = [raw]
                try:
                    await client.get('http://first.test/', headers={'X-Api-Key': 'fixture-key'})
                    self.assertEqual(seen, ['fixture-key', expected])
                    from core.http_client import _credential_origin
                    self.assertIsNone(_credential_origin.get())
                finally:
                    await client.close()

    def test_retention_journal_failure_preserves_file(self):
        base = Path('workspace').resolve()
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(base))
            evidence = root / 'proof.json'
            evidence.write_text('{}')
            memory = Mock()
            plan = {'workspace': str(root), 'policy': {'enabled': True}, 'actions': [{'path': str(evidence), 'class': 'bundles', 'reason': 'expired'}]}
            with patch('core.retention.os.fsync', side_effect=OSError('journal failure')):
                result = apply(plan, confirm=True, memory=memory)
            self.assertTrue(evidence.exists())
            self.assertEqual(result['findings_marked'], 0)
            self.assertTrue(result['errors'])
            memory.update_finding.assert_not_called()

    def test_single_file_digest(self):
        base = Path('workspace').resolve()
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(base))
            template = root / 'single.yaml'
            template.write_text('first')
            config = {'external_tools': {'nuclei_templates': str(template)}}
            before = template_selection_digest(config)
            template.write_text('second')
            self.assertTrue(before)
            self.assertNotEqual(before, template_selection_digest(config))
