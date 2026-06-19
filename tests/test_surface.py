"""Unit tests for the API-surface discovery and BOLA marker logic.

These cover the pure (network-free) functions so the high/critical-bug
plumbing is regression-tested offline by `selftest.py`.
"""
from __future__ import annotations

import unittest

from core.surface import parse_openapi, mine_js_text, synthesize_json_points
from scanners.idor_deep import identity_markers, _id_points, _neighbours


class TestOpenAPIParsing(unittest.TestCase):
    def test_openapi_v3_path_query_and_body(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users/{id}": {
                    "get": {"parameters": [
                        {"name": "id", "in": "path"},
                        {"name": "expand", "in": "query"},
                    ]},
                    "put": {"requestBody": {"content": {"application/json": {
                        "schema": {"properties": {"email": {}, "role": {}}}}}}},
                },
            },
        }
        tasks = parse_openapi(spec, "https://api.example.com/openapi.json")
        # one GET task (query+path) and one PUT task (json body)
        get = [t for t in tasks if t["method"] == "GET"]
        put = [t for t in tasks if t["method"] == "PUT"]
        self.assertTrue(get and put)
        self.assertIn("https://api.example.com/v1/users/1", get[0]["url"])
        self.assertIn("expand", get[0]["params"])
        self.assertIn("path:1", get[0]["params"])  # /v1(0)/users(1)... id is seg idx 1
        self.assertIn("json:email", put[0]["params"])
        self.assertIn("json:role", put[0]["params"])

    def test_swagger_v2_body_param(self):
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/api",
            "schemes": ["https"],
            "paths": {
                "/orders": {
                    "post": {"parameters": [
                        {"name": "body", "in": "body",
                         "schema": {"properties": {"amount": {}, "account": {}}}},
                    ]},
                },
            },
        }
        tasks = parse_openapi(spec, "https://api.example.com/v2/api-docs")
        post = [t for t in tasks if t["method"] == "POST"]
        self.assertTrue(post)
        self.assertEqual(post[0]["url"].rstrip("/"), "https://api.example.com/api/orders")
        self.assertIn("json:amount", post[0]["params"])

    def test_path_segment_index_mapping(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.test"}],
            "paths": {"/a/{b}/c/{d}": {"get": {"parameters": [
                {"name": "b", "in": "path"}, {"name": "d", "in": "path"}]}}},
        }
        tasks = parse_openapi(spec, "https://x.test/openapi.json")
        pts = tasks[0]["params"]
        # segments: a(0) {b}(1) c(2) {d}(3)
        self.assertIn("path:1", pts)
        self.assertIn("path:3", pts)

    def test_non_spec_returns_empty(self):
        self.assertEqual(parse_openapi({"nope": 1}, "https://x.test"), [])
        self.assertEqual(parse_openapi("not a dict", "https://x.test"), [])


class TestJSMining(unittest.TestCase):
    def test_finds_api_paths(self):
        js = """
        const A = "/api/v2/users/profile";
        fetch('/api/orders?status=open&limit=10');
        const css = "/static/app.css";
        const img = "/assets/logo.png";
        """
        found = dict(mine_js_text(js, "https://app.example.com/"))
        urls = list(found)
        self.assertTrue(any("/api/v2/users/profile" in u for u in urls))
        # query keys harvested
        orders = [u for u in urls if "/api/orders" in u]
        self.assertTrue(orders)
        self.assertIn("status", found[orders[0]])
        self.assertIn("limit", found[orders[0]])
        # static assets filtered out
        self.assertFalse(any("app.css" in u or "logo.png" in u for u in urls))

    def test_offsite_filtered(self):
        js = '"https://evil.com/api/steal"; "/api/keep"'
        found = dict(mine_js_text(js, "https://app.example.com/"))
        self.assertTrue(any("/api/keep" in u for u in found))
        self.assertFalse(any("evil.com" in u for u in found))


class TestJSONSynthesis(unittest.TestCase):
    def test_top_level_scalars(self):
        body = '{"id": 5, "email": "a@b.com", "active": true, "nested": {"x": 1}}'
        pts = synthesize_json_points(body)
        self.assertIn("json:id", pts)
        self.assertIn("json:email", pts)
        self.assertIn("json:active", pts)
        self.assertNotIn("json:nested", pts)  # object value skipped

    def test_list_of_objects(self):
        body = '[{"id": 1, "name": "x"}, {"id": 2}]'
        pts = synthesize_json_points(body)
        self.assertIn("json:id", pts)
        self.assertIn("json:name", pts)

    def test_garbage(self):
        self.assertEqual(synthesize_json_points("<html>"), [])
        self.assertEqual(synthesize_json_points(""), [])


class TestBOLAMarkers(unittest.TestCase):
    def test_identity_markers(self):
        text = '{"email": "victim@corp.com", "uid": "550e8400-e29b-41d4-a716-446655440000"}'
        m = identity_markers(text)
        self.assertIn("victim@corp.com", m)
        self.assertIn("550e8400-e29b-41d4-a716-446655440000", m)

    def test_id_points_numeric_path(self):
        # /api(0)/users(1)/123(2)
        pts = _id_points("https://x.test/api/users/123", ["path:2"])
        self.assertEqual(pts, [("path:2", "123")])

    def test_id_points_query(self):
        pts = _id_points("https://x.test/get?user_id=42&q=hi", ["user_id", "q"])
        self.assertIn(("user_id", "42"), pts)
        self.assertFalse(any(k == "q" for k, _ in pts))

    def test_neighbours(self):
        self.assertEqual(set(_neighbours("10")), {"9", "11"})
        self.assertEqual(_neighbours("abc"), [])


if __name__ == "__main__":
    unittest.main()
