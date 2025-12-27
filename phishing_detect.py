import requests
from urllib.parse import urlparse
import pyfiglet
from colorama import Fore, init

init(autoreset=True)

# Banner Printing
def show_banner():
    banner = pyfiglet.figlet_format("PHISH-CLI", font="slant")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "Simple Phishing URL Analyzer\n")

# Functions
def is_ip_address(domain):
    parts = domain.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False
        if int(part) < 0 or int(part) > 255:
            return False

    return True

def count_subdomains(domain):
    parts = domain.split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2

def get_redirect_count(url):
    try:
        response = requests.get(url, timeout=6, allow_redirects=True)
        return len(response.history)
    except:
        return -1

def get_status_code(url):
    try:
        response = requests.get(url, timeout=6)
        return response.status_code
    except:
        return -1

# Analyzing
def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    # HTTPS Check
    if parsed.scheme != "https":
        score += 2
        reasons.append("Does not use HTTPS")
        print(Fore.RED + "HTTPS not used")
    else:
        print(Fore.GREEN + "HTTPS enabled")

    # IP Address Check
    if is_ip_address(domain):
        score += 3
        reasons.append("Uses IP address instead of domain")
        print(Fore.RED + "IP address used")
    else:
        print(Fore.GREEN + "Domain name used")

    # Subdomain Check
    subdomains = count_subdomains(domain)
    print(Fore.YELLOW + f"Subdomains: {subdomains}")
    if subdomains >= 3:
        score += 2
        reasons.append("Too many subdomains")

    # URL Length Check
    print(Fore.YELLOW + f"URL length: {len(url)}")
    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    # Hyphen Check
    hyphens = domain.count("-")
    print(Fore.YELLOW + f"Hyphens in domain: {hyphens}")
    if hyphens >= 3:
        score += 1
        reasons.append("Too many hyphens in domain")

    # Redirect Check
    redirects = get_redirect_count(url)
    if redirects != -1:
        print(Fore.YELLOW + f"Redirects: {redirects}")
        if redirects >= 4:
            score += 2
            reasons.append("Too many redirects")
    else:
        score += 1
        reasons.append("Could not check redirects")

    # HTTP Status Check
    status = get_status_code(url)
    if status != -1:
        print(Fore.YELLOW + f"HTTP status code: {status}")
        if status >= 400:
            score += 1
            reasons.append("Suspicious HTTP response")
    else:
        score += 1
        reasons.append("Website not reachable")

    # Scoring
    print("\n" + "-" * 45)
    print(Fore.CYAN + f"Risk Score : {score}")

    if score <= 2:
        verdict = Fore.GREEN + "Likely Safe"
    elif score <= 5:
        verdict = Fore.YELLOW + "Suspicious"
    else:
        verdict = Fore.RED + "Likely Phishing"

    print("Verdict    :", verdict)

    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(Fore.RED + " - " + r)

if __name__ == "__main__":
    show_banner()
    target = input(Fore.WHITE + "Enter URL to analyze: ").strip()
    print("\n" + "-" * 50)
    analyze_url(target)