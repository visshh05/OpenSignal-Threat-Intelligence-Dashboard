import os
import socket
import unittest
from unittest.mock import patch

import integrity_checker


class MockResponse:
	def __init__(self, payload, status_code=200):
		self.payload = payload
		self.status_code = status_code

	def raise_for_status(self):
		return None

	def json(self):
		return self.payload


class NormalizeTargetTests(unittest.TestCase):
	def test_accepts_url_with_long_path(self):
		target, is_ip = integrity_checker.normalize_target(
			f"https://example.com/{'x' * 300}"
		)
		self.assertEqual((target, is_ip), ("example.com", False))

	def test_accepts_ipv6_url_with_port(self):
		target, is_ip = integrity_checker.normalize_target(
			"http://[2001:db8::1]:8080/path"
		)
		self.assertEqual((target, is_ip), ("2001:db8::1", True))

	def test_rejects_malformed_url_and_port(self):
		for target in ("http://[", "example.com:99999"):
			with self.subTest(target=target), self.assertRaises(integrity_checker.TargetError):
				integrity_checker.normalize_target(target)


class ProviderResponseTests(unittest.TestCase):
	def test_shodan_uses_public_internetdb_for_ipv4_without_key(self):
		payload = {
			"ip": "8.8.8.8",
			"ports": [443, 53],
			"hostnames": ["dns.google"],
			"vulns": [],
		}
		with patch.dict(os.environ, {}, clear=True):
			with patch.object(integrity_checker.HTTP, "get", return_value=MockResponse(payload)) as get:
				result = integrity_checker.query_shodan("8.8.8.8", True)
		self.assertEqual(result["status"], "ok")
		self.assertEqual(result["ports"], [53, 443])
		self.assertEqual(result["source"], "InternetDB")
		self.assertIn("internetdb.shodan.io/8.8.8.8", get.call_args.args[0])

	def test_shodan_resolves_domain_and_aggregates_public_ipv4_data(self):
		dns_results = [
			(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
			(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
		]

		responses = [
			MockResponse({"ip": "1.1.1.1", "ports": [443], "hostnames": [], "vulns": []}),
			MockResponse({"ip": "8.8.8.8", "ports": [53], "hostnames": [], "vulns": []}),
		]

		with patch.dict(os.environ, {}, clear=True):
			with patch.object(integrity_checker.socket, "getaddrinfo", return_value=dns_results):
				with patch.object(integrity_checker.HTTP, "get", side_effect=responses):
					result = integrity_checker.query_shodan("example.com", False)
		self.assertEqual(result["status"], "ok")
		self.assertEqual(result["ips"], ["1.1.1.1", "8.8.8.8"])
		self.assertEqual(result["ports"], [53, 443])

	def test_shodan_does_not_query_private_domain_addresses(self):
		dns_results = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 0))]
		with patch.dict(os.environ, {}, clear=True):
			with patch.object(integrity_checker.socket, "getaddrinfo", return_value=dns_results):
				with patch.object(integrity_checker.HTTP, "get") as get:
					result = integrity_checker.query_shodan("example.com", False)
		self.assertEqual(result["status"], "not_applicable")
		get.assert_not_called()

	def test_shodan_requires_key_for_ipv6_internetdb_fallback(self):
		with patch.dict(os.environ, {}, clear=True):
			result = integrity_checker.query_shodan("2001:db8::1", True)
		self.assertEqual(result["status"], "needs_key")

	def test_shodan_skips_private_ip_internetdb_lookup(self):
		with patch.dict(os.environ, {}, clear=True):
			with patch.object(integrity_checker.HTTP, "get") as get:
				result = integrity_checker.query_shodan("192.168.1.10", True)
		self.assertEqual(result["status"], "not_applicable")
		get.assert_not_called()

	def test_virustotal_rejects_malformed_response_without_raising(self):
		with patch.dict(os.environ, {"VT_API_KEY": "test"}, clear=True):
			with patch.object(integrity_checker.HTTP, "get", return_value=MockResponse([])):
				result = integrity_checker.query_virustotal("example.com", False)
		self.assertEqual(result["status"], "error")

	def test_shodan_rejects_malformed_port_list_without_raising(self):
		with patch.dict(os.environ, {"SHODAN_API_KEY": "test"}, clear=True):
			with patch.object(
				integrity_checker.HTTP,
				"get",
				return_value=MockResponse({"ports": None}),
			):
				result = integrity_checker.query_shodan("192.0.2.1", True)
		self.assertEqual(result["status"], "error")

	def test_crtsh_handles_empty_certificate_fields(self):
		certificate = {"id": 1, "name_value": None, "issuer_name": None}
		with patch.object(
			integrity_checker.HTTP,
			"get",
			return_value=MockResponse([certificate]),
		):
			result = integrity_checker.query_crtsh("example.com", False)
		self.assertEqual(result["status"], "ok")
		self.assertEqual(result["certificates"][0]["name"], "")
		self.assertEqual(result["certificates"][0]["issuer"], "")


class LookupRouteTests(unittest.TestCase):
	def setUp(self):
		self.client = integrity_checker.app.test_client()

	def test_rejects_non_object_json(self):
		response = self.client.post("/api/lookup", json=["example.com"])
		self.assertEqual(response.status_code, 400)
		self.assertIn("error", response.get_json())

	def test_rejects_non_string_target(self):
		response = self.client.post("/api/lookup", json={"target": ["example.com"]})
		self.assertEqual(response.status_code, 400)
		self.assertIn("error", response.get_json())


if __name__ == "__main__":
	unittest.main()
