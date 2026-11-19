# OpenSignal Threat Intelligence Dashboard

A Flask dashboard for on-demand public threat intelligence lookups. It queries VirusTotal for reputation, Shodan for IP host/service data, and crt.sh for domain certificate-transparency records.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python integrity_checker.py
```

Open `http://127.0.0.1:5000` in a browser. An illustrative IP demo with reputation and exposed ports is shown on startup. Use **Load domain demo** to preview certificate results, or **Load IP demo** to restore the IP example. Demo values are illustrative and do not make external requests.

## Configure providers

VirusTotal requires an API key. Configure Shodan's optional API key for its full host data; open ports are also checked using Shodan InternetDB without a key. Domain lookups resolve only public IPv4 addresses before checking InternetDB. Set these environment variables before starting Flask:

```powershell
$env:VT_API_KEY = "your-virustotal-key"
$env:SHODAN_API_KEY = "your-shodan-key"
python integrity_checker.py
```

crt.sh is queried as a public source and does not require a key. Providers without keys or without a matching indicator type return an explanatory status in the dashboard. API keys are read only on the server and are never sent to the browser.

## Notes

- The lookup endpoint accepts a domain, IP address, or `http(s)` URL and queries only the extracted host.
- Provider requests run concurrently and use a nine-second timeout.
- This is a local development server. Put it behind a production WSGI server and add authentication and rate limiting before exposing it to a network.