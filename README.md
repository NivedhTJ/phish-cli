# PHISH-CLI

A **simple command-line tool** to analyze URLs for phishing risks. PHISH-CLI evaluates URLs based on HTTPS usage, IP addresses, subdomains, URL length, hyphens, redirects, and HTTP response codes to give a **risk score** and verdict.

---

## Features

- Checks if a URL uses **HTTPS**.
- Detects **IP address usage** instead of domain names.
- Counts **subdomains** and hyphens.
- Measures **URL length**.
- Checks the number of **redirects**.
- Retrieves the **HTTP status code**.
- Gives a **risk score** and a verdict:
  - Likely Safe
  - Suspicious
  - Likely Phishing
- Color-coded output for better readability.
- ASCII banner with **pyfiglet**.
