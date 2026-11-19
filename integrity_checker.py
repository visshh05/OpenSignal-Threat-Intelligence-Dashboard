"""Public-source threat intelligence dashboard."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

HTTP = requests.Session()
HTTP.headers.update({"User-Agent": "OpenSignal-IntelDashboard/1.0"})
TIMEOUT = 9
MAX_INTERNETDB_ADDRESSES = 4
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class TargetError(ValueError):
	"""Raised when a submitted indicator is not a hostname or IP address."""


def normalize_target(value: str) -> tuple[str, bool]:
	"""Return a normalized host and whether it is an IP address."""
	raw = value.strip()
	if not raw:
		raise TargetError("Enter a domain name or IP address.")

	candidate: str | None
	if "://" in raw:
		try:
			parsed = urlparse(raw)
			candidate = parsed.hostname
			parsed.port
		except ValueError as exc:
			raise TargetError("That URL contains an invalid host or port.") from exc
		if parsed.scheme not in {"http", "https"} or not candidate:
			raise TargetError("Use a hostname or an http(s) URL.")
	else:
		candidate = raw.split("/", 1)[0].strip().rstrip(".")
		try:
			return str(ipaddress.ip_address(candidate)), True
		except ValueError:
			pass
		try:
			parsed = urlparse(f"//{candidate}")
			candidate = parsed.hostname
			parsed.port
		except ValueError as exc:
			raise TargetError("That hostname contains an invalid port.") from exc
		if not candidate:
			raise TargetError("Enter a domain name or IP address.")

	try:
		candidate = candidate.encode("idna").decode("ascii").lower().rstrip(".")
	except UnicodeError as exc:
		raise TargetError("That hostname contains invalid characters.") from exc
	try:
		return str(ipaddress.ip_address(candidate)), True
	except ValueError:
		pass

	if len(candidate) > 253 or "." not in candidate:
		raise TargetError("Enter a fully qualified domain name or IP address.")
	labels = candidate.split(".")
	if any(not HOST_LABEL.fullmatch(label) for label in labels):
		raise TargetError("That hostname contains an invalid label.")
	return candidate, False


def provider_error(provider: str, status: str, message: str) -> dict:
	return {"provider": provider, "status": status, "message": message}


def first_line(value: object, limit: int) -> str:
	lines = str(value or "").splitlines()
	return lines[0][:limit] if lines else ""


def query_virustotal(target: str, is_ip: bool) -> dict:
	key = os.getenv("VT_API_KEY")
	if not key:
		return provider_error("VirusTotal", "needs_key", "Set VT_API_KEY to enable this source.")
	kind = "ip_addresses" if is_ip else "domains"
	url = f"https://www.virustotal.com/api/v3/{kind}/{quote(target, safe='')}"
	try:
		response = HTTP.get(url, headers={"x-apikey": key}, timeout=TIMEOUT)
		if response.status_code == 404:
			return {"provider": "VirusTotal", "status": "clear", "message": "No report found for this indicator."}
		response.raise_for_status()
		payload = response.json()
		data = payload.get("data") if isinstance(payload, dict) else None
		attributes = data.get("attributes") if isinstance(data, dict) else None
		if not isinstance(attributes, dict):
			return provider_error("VirusTotal", "error", "Provider returned an unexpected response format.")
		stats = attributes.get("last_analysis_stats", {})
		if not isinstance(stats, dict):
			return provider_error("VirusTotal", "error", "Provider returned an unexpected response format.")
		return {
			"provider": "VirusTotal",
			"status": "ok",
			"malicious": stats.get("malicious", 0),
			"suspicious": stats.get("suspicious", 0),
			"harmless": stats.get("harmless", 0),
			"undetected": stats.get("undetected", 0),
			"reputation": attributes.get("reputation"),
			"last_analysis_date": attributes.get("last_analysis_date"),
		}
	except requests.HTTPError as exc:
		code = exc.response.status_code if exc.response is not None else "unknown"
		return provider_error("VirusTotal", "error", f"Provider returned HTTP {code}.")
	except (requests.RequestException, ValueError):
		return provider_error("VirusTotal", "error", "Could not retrieve a valid provider response.")


def query_shodan_internetdb(target: str) -> dict:
	url = f"https://internetdb.shodan.io/{quote(target, safe='')}"
	try:
		response = HTTP.get(url, timeout=TIMEOUT)
		if response.status_code == 404:
			return provider_error("Shodan", "clear", "No InternetDB data found for this IP address.")
		response.raise_for_status()
		data = response.json()
		if not isinstance(data, dict):
			return provider_error("Shodan", "error", "InternetDB returned an unexpected response format.")
		ports = data.get("ports", [])
		hostnames = data.get("hostnames", [])
		vulnerabilities = data.get("vulns", [])
		if (
			not isinstance(ports, list)
			or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports)
			or not isinstance(hostnames, list)
			or any(not isinstance(hostname, str) for hostname in hostnames)
			or not isinstance(vulnerabilities, list)
			or any(not isinstance(vulnerability, str) for vulnerability in vulnerabilities)
		):
			return provider_error("Shodan", "error", "InternetDB returned an unexpected response format.")
		return {
			"provider": "Shodan",
			"source": "InternetDB",
			"status": "ok",
			"ip": data.get("ip", target),
			"ports": sorted(set(ports)),
			"hostnames": hostnames[:8],
			"vulnerabilities": vulnerabilities[:12],
			"organization": "Not provided by InternetDB",
			"country": "Not provided",
			"city": None,
			"last_update": None,
		}
	except requests.HTTPError as exc:
		code = exc.response.status_code if exc.response is not None else "unknown"
		return provider_error("Shodan", "error", f"InternetDB returned HTTP {code}.")
	except (requests.RequestException, ValueError):
		return provider_error("Shodan", "error", "Could not retrieve a valid InternetDB response.")


def query_shodan_domain(target: str) -> dict:
	try:
		addresses = set()
		for result in socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM):
			address = ipaddress.ip_address(result[4][0])
			if address.version == 4 and address.is_global:
				addresses.add(address)
	except (OSError, ValueError):
		return provider_error("Shodan", "error", "Could not resolve this domain to a public IPv4 address.")

	if not addresses:
		return provider_error("Shodan", "not_applicable", "This domain has no public IPv4 addresses to check.")

	addresses = sorted(addresses)[:MAX_INTERNETDB_ADDRESSES]
	with ThreadPoolExecutor(max_workers=len(addresses)) as pool:
		results = list(pool.map(query_shodan_internetdb, (str(address) for address in addresses)))

	successful = [result for result in results if result["status"] == "ok"]
	if successful:
		resolved_ips = list(dict.fromkeys(
			result["ip"] for result in successful if isinstance(result.get("ip"), str)
		))
		return {
			"provider": "Shodan",
			"source": "InternetDB",
			"status": "ok",
			"ips": resolved_ips,
			"ports": sorted({port for result in successful for port in result["ports"]}),
			"hostnames": list(dict.fromkeys(hostname for result in successful for hostname in result["hostnames"]))[:8],
			"vulnerabilities": list(dict.fromkeys(vuln for result in successful for vuln in result["vulnerabilities"]))[:12],
			"organization": "Public InternetDB data",
			"country": "Not provided",
			"city": None,
			"last_update": None,
		}

	if any(result["status"] == "error" for result in results):
		return provider_error("Shodan", "error", "Could not retrieve InternetDB data for the domain's public IPv4 addresses.")
	return provider_error("Shodan", "clear", "No InternetDB data found for the domain's public IPv4 addresses.")


def query_shodan(target: str, is_ip: bool) -> dict:
	key = os.getenv("SHODAN_API_KEY")
	if not key:
		if is_ip:
			try:
				address = ipaddress.ip_address(target)
			except ValueError:
				return provider_error("Shodan", "error", "The target is not a valid IP address.")
			if address.version != 4:
				return provider_error("Shodan", "needs_key", "Set SHODAN_API_KEY to look up IPv6 hosts.")
			if not address.is_global:
				return provider_error("Shodan", "not_applicable", "InternetDB checks public IP addresses only.")
			return query_shodan_internetdb(str(address))
		return query_shodan_domain(target)
	if not is_ip:
		return query_shodan_domain(target)
	url = f"https://api.shodan.io/shodan/host/{quote(target, safe='')}"
	try:
		response = HTTP.get(url, params={"key": key}, timeout=TIMEOUT)
		response.raise_for_status()
		data = response.json()
		if not isinstance(data, dict):
			return provider_error("Shodan", "error", "Provider returned an unexpected response format.")
		ports = data.get("ports", [])
		hostnames = data.get("hostnames", [])
		vulnerabilities = data.get("vulns", [])
		if (
			not isinstance(ports, list)
			or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports)
			or not isinstance(hostnames, list)
			or any(not isinstance(hostname, str) for hostname in hostnames)
			or not isinstance(vulnerabilities, list)
			or any(not isinstance(vulnerability, str) for vulnerability in vulnerabilities)
		):
			return provider_error("Shodan", "error", "Provider returned an unexpected response format.")
		return {
			"provider": "Shodan",
			"source": "Shodan Host API",
			"status": "ok",
			"ip": data.get("ip_str", target),
			"organization": data.get("org") or data.get("isp") or "Unknown",
			"country": data.get("country_name") or "Unknown",
			"city": data.get("city"),
			"ports": sorted(set(ports)),
			"hostnames": hostnames[:8],
			"vulnerabilities": vulnerabilities[:12],
			"last_update": data.get("last_update"),
		}
	except requests.HTTPError as exc:
		code = exc.response.status_code if exc.response is not None else "unknown"
		message = "No host data found." if code == 404 else f"Provider returned HTTP {code}."
		return provider_error("Shodan", "clear" if code == 404 else "error", message)
	except (requests.RequestException, ValueError):
		return provider_error("Shodan", "error", "Could not retrieve a valid provider response.")


def query_crtsh(target: str, is_ip: bool) -> dict:
	if is_ip:
		return provider_error("crt.sh", "not_applicable", "Certificate transparency search requires a domain.")
	try:
		response = HTTP.get(
			"https://crt.sh/",
			params={"q": f"%.{target}", "output": "json"},
			timeout=TIMEOUT,
		)
		response.raise_for_status()
		certificates = response.json()
		if not isinstance(certificates, list) or any(not isinstance(item, dict) for item in certificates):
			return provider_error("crt.sh", "error", "Provider returned an unexpected response format.")
		unique: dict[tuple[str, str], dict] = {}
		for certificate in certificates:
			key = (str(certificate.get("id", "")), str(certificate.get("name_value", "")))
			unique[key] = certificate
		rows = sorted(unique.values(), key=lambda item: str(item.get("not_before") or ""), reverse=True)
		return {
			"provider": "crt.sh",
			"status": "ok",
			"count": len(unique),
			"certificates": [
				{
					"name": first_line(item.get("name_value"), 180),
					"issuer": first_line(item.get("issuer_name"), 140),
					"issued": item.get("not_before"),
					"expires": item.get("not_after"),
				}
				for item in rows[:8]
			],
		}
	except (requests.RequestException, ValueError, TypeError):
		return provider_error("crt.sh", "error", "Could not retrieve a valid certificate search response.")


@app.get("/")
def dashboard():
	return render_template("index.html")


@app.post("/api/lookup")
def lookup():
	payload = request.get_json(silent=True)
	if not isinstance(payload, dict):
		return jsonify({"error": "Submit a JSON object containing a target."}), 400
	try:
		raw_target = payload.get("target", "")
		if not isinstance(raw_target, str):
			raise TargetError("Enter a domain name or IP address.")
		target, is_ip = normalize_target(raw_target)
	except (TargetError, UnicodeError) as exc:
		return jsonify({"error": str(exc)}), 400

	tasks = (query_virustotal, query_shodan, query_crtsh)
	with ThreadPoolExecutor(max_workers=3) as pool:
		results = list(pool.map(lambda task: task(target, is_ip), tasks))

	return jsonify({
		"target": target,
		"target_type": "ip" if is_ip else "domain",
		"checked_at": datetime.now(timezone.utc).isoformat(),
		"results": results,
	})


if __name__ == "__main__":
	app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
