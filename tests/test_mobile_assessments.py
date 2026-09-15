"""Paired safe/risky mobile artifacts and Appium protocol boundary tests."""
import asyncio
import io
import json
import os
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import httpx
from assessments.mobile_static import assess as static_assess
from assessments.mobile_dynamic import assess as dynamic_assess
from assessments.mobile_traffic import assess as traffic_assess, load_seeds
from assessments.local_privilege import assess as local_assess
from core.proof_gate import poc_status


def binary_manifest(debug):
    words = ['manifest','application','package','com.fixture','debuggable',
             'http://schemas.android.com/apk/res/android','allowBackup']
    encoded, offsets = b'', []
    for word in words:
        raw = word.encode(); offsets.append(len(encoded)); encoded += bytes([len(raw),len(raw)]) + raw + b'\0'
    encoded += b'\0' * (-len(encoded) % 4)
    start = 28 + len(words) * 4
    pool = struct.pack('<HHIIIIII',1,28,start+len(encoded),len(words),0,0x100,start,0)
    pool += struct.pack('<'+'I'*len(words),*offsets) + encoded
    def begin(name, attrs):
        body = struct.pack('<II',1,0xffffffff) + struct.pack('<IIHHHHHH',0xffffffff,name,20,20,len(attrs),0,0,0)
        for ns,key,typ,value in attrs:
            body += struct.pack('<IIIHBBI',ns,key,0xffffffff,8,0,typ,value)
        return struct.pack('<HHI',0x102,16,8+len(body))+body
    def end(name):
        return struct.pack('<HHIIIII',0x103,16,24,1,0xffffffff,0xffffffff,name)
    body = pool + begin(0,[(0xffffffff,2,3,3)]) + begin(1,[(5,4,0x12,int(debug)),(5,6,0x12,0)]) + end(1) + end(0)
    return struct.pack('<HHI',3,8,8+len(body)) + body


class StaticTests(unittest.TestCase):
    def test_compiled_android_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            for enabled in (False, True):
                path = Path(directory) / f'{enabled}.apk'
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('AndroidManifest.xml', binary_manifest(enabled))
                report = static_assess(path)
                self.assertEqual(report['package_id'], 'com.fixture')
                self.assertEqual(len(report['candidates']), int(enabled))
                for candidate in report['candidates']:
                    self.assertEqual(poc_status(candidate)[0], 'candidate')

    def test_ios_binary_plist_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            for unsafe in (False, True):
                path = Path(directory) / f'{unsafe}.ipa'
                data = {'CFBundleIdentifier':'com.fixture', 'NSAppTransportSecurity':{'NSAllowsArbitraryLoads':unsafe}}
                with zipfile.ZipFile(path,'w') as archive:
                    archive.writestr('Payload/Fixture.app/Info.plist',plistlib.dumps(data,fmt=plistlib.FMT_BINARY))
                self.assertEqual(len(static_assess(path)['candidates']), int(unsafe))

    def test_unsafe_archive_and_entity_input_rejected(self):
        from assessments.android_xml import parse
        with self.assertRaises(ValueError):
            parse(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
        with self.assertRaises(ValueError):
            parse(struct.pack('<HHIHHI',3,8,16,1,8,0))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.apk'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('../outside',b'never extract')
            with self.assertRaises(ValueError): static_assess(path)

    def test_local_privilege_pairs(self):
        for mode, expected in ((0o755,0),(0o777,1)):
            report = local_assess({'platform':'linux','files':[{'path':'/opt/service','uid':0,'mode':mode}]})
            self.assertEqual(len(report['candidates']),expected)
        for command, expected in ((r'C:/Program Files/Fixture/svc.exe --flag',1),('"C:/Program Files/Fixture/svc.exe" --flag',0)):
            report = local_assess({'platform':'windows','services':[{'Name':'fixture','PathName':command,'StartName':'LocalSystem'}]})
            self.assertEqual(len(report['candidates']),expected)

    def test_har_scope_and_secrets_do_not_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'flow.har'
            entries=[{'request':{'url':'http://api.fixture.test/a?q=PRIVATE_VALUE','method':'GET','headers':[{'name':'Authorization','value':'SECRET_VALUE'}]}},
                     {'request':{'url':'https://outside.test/a','method':'GET'}},
                     {'request':{'url':'https://api.fixture.test/a?token=SECRET_VALUE','method':'GET'}}]
            path.write_text(json.dumps({'log':{'entries':entries}}))
            report=traffic_assess(path,['api.fixture.test'])
            self.assertEqual(len(report['candidates']),1)
            self.assertEqual(len(report['api_seeds']),1)
            self.assertNotIn('SECRET_VALUE',json.dumps(report))
            self.assertNotIn('PRIVATE_VALUE',json.dumps(report))
            seeds=Path(directory)/'seeds.json';seeds.write_text(json.dumps(report['api_seeds']))
            self.assertEqual(load_seeds(seeds)[0]['params'],['q'])
            seeds.write_text(json.dumps([{'url':'https://api.fixture.test/a','method':'POST'}]))
            with self.assertRaises(ValueError): load_seeds(seeds)


class DynamicTests(unittest.IsolatedAsyncioTestCase):
    def transport(self, platform, secure=True, app='com.fixture', fail=False):
        self.requests=[]
        def respond(request):
            self.requests.append(request)
            if fail: return httpx.Response(500,json={'value':{'error':'unsupported operation','message':'PRIVATE_VALUE'}})
            if request.url.path.endswith('/current_package'): value=app
            elif request.url.path.endswith('/execute/sync'): value={'bundleId':app}
            elif request.url.path.endswith('/source'):
                value = ('<hierarchy><node class="android.widget.EditText" resource-id="password" password="'+str(secure).lower()+'" text="PRIVATE_VALUE"/></hierarchy>') if platform=='android' else ('<App><'+('XCUIElementTypeSecureTextField' if secure else 'XCUIElementTypeTextField')+' name="password" value="PRIVATE_VALUE"/></App>')
            elif request.url.path.endswith('/contexts'): value=['NATIVE_APP','WEBVIEW_fixture']
            elif request.url.path.endswith('/element'): value={'element-6066-11e4-a52e-4f735466cecf':'field'}
            else: value=None
            return httpx.Response(200,json={'value':value})
        return httpx.MockTransport(respond)

    async def test_android_and_ios_runtime_pairs(self):
        for platform in ('android','ios'):
            for secure in (False,True):
                report=await dynamic_assess('http://127.0.0.1:4723','fixture',platform,'com.fixture',transport=self.transport(platform,secure))
                self.assertEqual(report['status'],'completed')
                self.assertEqual(len(report['candidates']),int(not secure))
                self.assertNotIn('PRIVATE_VALUE',json.dumps(report))

    async def test_foreground_mismatch_stops_before_reading_ui(self):
        report=await dynamic_assess('http://127.0.0.1:4723','fixture','ios','com.fixture',transport=self.transport('ios',app='com.other'))
        self.assertEqual(report['status'],'blocked')
        self.assertEqual(len(self.requests),1)

    async def test_unavailable_runtime_is_not_a_pass(self):
        report=await dynamic_assess('http://127.0.0.1:4723','fixture','android','com.fixture',transport=self.transport('android',fail=True))
        self.assertEqual(report['status'],'blocked')
        self.assertNotIn('PRIVATE_VALUE',json.dumps(report))

    async def test_flow_requires_aggressive_and_keeps_values_out_of_report(self):
        steps=[{'action':'type','using':'id','selector':'password','value_env':'SX_FIXTURE_PASSWORD'}]
        with self.assertRaises(ValueError):
            await dynamic_assess('http://127.0.0.1:4723','fixture','android','com.fixture',steps=steps,transport=self.transport('android'))
        self.assertEqual(self.requests,[])
        with patch.dict(os.environ,{'SX_FIXTURE_PASSWORD':'SECRET_VALUE'}):
            report=await dynamic_assess('http://127.0.0.1:4723','fixture','android','com.fixture',steps=steps,aggressive=True,transport=self.transport('android'))
        self.assertEqual(report['status'],'completed')
        self.assertTrue(any(request.url.path.endswith('/value') for request in self.requests))
        self.assertNotIn('SECRET_VALUE',json.dumps(report))


class AppiumSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_loopback_appium_protocol_for_both_platforms(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def send_value(self, value):
                raw=json.dumps({'value':value}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_GET(self):
                if self.path.endswith('/current_package'): self.send_value('com.fixture')
                elif self.path.endswith('/contexts'): self.send_value(['NATIVE_APP'])
                else: self.send_value('<hierarchy/>')
            def do_POST(self):
                request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if request.get('script')=='mobile: activeAppInfo': self.send_value({'bundleId':'com.fixture'})
                else: self.send_value(None)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            for platform in ('android','ios'):
                report=await dynamic_assess(f'http://127.0.0.1:{server.server_port}','fixture',platform,'com.fixture')
                self.assertEqual(report['status'],'completed')
                self.assertTrue(report['checks'])
        finally:
            await asyncio.to_thread(server.shutdown)
            server.server_close();worker.join(timeout=2)


class ApiSeedTests(unittest.IsolatedAsyncioTestCase):
    async def test_scope_and_passive_mode_before_queueing(self):
        from assessments.mobile_traffic import enqueue_seeds
        from core.scope import ScopePolicy
        from core.transport import TransportController
        from core.task_queue import TaskQueue
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'seeds.json'
            path.write_text(json.dumps([{'url':'https://api.fixture.test/items','params':['id']},
                                       {'url':'https://outside.test/items','params':[]}]))
            scope=ScopePolicy(default_allow=False)
            scope.allow_globs.append('api.fixture.test')
            controller=TransportController({},scope,'https://api.fixture.test')
            queue=TaskQueue()
            counts=await enqueue_seeds(path,queue,controller,'fixture',passive=True)
            self.assertTrue(queue.empty())
            counts=await enqueue_seeds(path,queue,controller,'fixture')
            self.assertEqual(counts,{'queued':1,'excluded':1})
            task=await queue.get();queue.task_done()
            self.assertEqual(task.payload['url'],'https://api.fixture.test/items')
            self.assertEqual(task.kind,'scan')
