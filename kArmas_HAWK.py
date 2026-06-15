#!/usr/bin/env python3
"""
kArmas_HAWK - Authorized Web Reconnaissance Tool
=================================================
For use ONLY on systems/domains you own or are explicitly authorized to test.

Features:
  - DNS resolution (A, AAAA, MX, NS, TXT via dnspython if available, else socket fallback)
  - WHOIS lookup (via python-whois if available)
  - HTTP header inspection
  - robots.txt and sitemap.xml fetch
  - Basic technology fingerprinting (server headers, common frameworks)
  - SSL certificate info
"""

import sys
import socket
import ssl
import json
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

SKULL = r"""
                       _.-^^---....,,--
                   _--                  --_
                  <                        >)
                  |                         |
                   \._                   _./
                      ```--. . , ; .--'''
                            | |   |
                         .-=||  | |=-.
                         `-=#$%&%$#=-'
                            | ;  :|
                   _____.,-#%&$@%#&#~,._____

       __  _________  ____  _________________   _   ____ _       __ ____
      / / / / ____/ \/ /  |/  / __ /__  / ___/  / | / / / |     / // / //_/
     / / / / /     \  / /|_/ / /_/ / / /\__ \  /  |/ / /| | /| / // // ,<
    / /_/ / /___    / / /  / ____/ / /___/ /  / /|  / / | |/ |/ // // /| |
    \____/\____/   /_/_/  /_/   /_//_/____/  /_/ |_/_/  |__/|__//_//_/ |_|

                kArmas_HAWK :: Recon & Footprinting Toolkit
                Authorized testing only. Don't be a clown.
"""

def banner():
    print(SKULL)


def get_dns_info(domain):
    print("\n[+] DNS Information")
    try:
        ips = socket.gethostbyname_ex(domain)
        print(f"    Hostname : {ips[0]}")
        print(f"    Aliases  : {ips[1]}")
        print(f"    Addresses: {ips[2]}")
    except socket.gaierror as e:
        print(f"    [!] Resolution failed: {e}")

    try:
        import dns.resolver
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                print(f"    {rtype:5}: " + ", ".join(str(r) for r in answers))
            except Exception:
                pass
    except ImportError:
        print("    [i] Install 'dnspython' for full DNS record enumeration (A/AAAA/MX/NS/TXT)")


def get_whois_info(domain):
    print("\n[+] WHOIS Information")
    try:
        import whois
        w = whois.whois(domain)
        for field in ["domain_name", "registrar", "creation_date", "expiration_date",
                       "updated_date", "name_servers", "emails", "org", "country"]:
            val = w.get(field) if hasattr(w, "get") else getattr(w, field, None)
            if val:
                print(f"    {field:14}: {val}")
    except ImportError:
        print("    [i] Install 'python-whois' for WHOIS data: pip install python-whois")
    except Exception as e:
        print(f"    [!] WHOIS lookup failed: {e}")


def get_headers(url):
    print("\n[+] HTTP Headers")
    try:
        req = Request(url, headers={"User-Agent": "kArmas_HAWK/1.0"})
        with urlopen(req, timeout=10) as resp:
            print(f"    Status: {resp.status} {resp.reason}")
            for k, v in resp.headers.items():
                print(f"    {k}: {v}")
            return dict(resp.headers)
    except HTTPError as e:
        print(f"    [!] HTTP Error: {e.code} {e.reason}")
        return dict(e.headers) if e.headers else {}
    except URLError as e:
        print(f"    [!] Connection failed: {e.reason}")
        return {}


def fingerprint(headers):
    print("\n[+] Technology Fingerprint (heuristic)")
    if not headers:
        print("    [!] No headers to analyze")
        return

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server:
        print(f"    Server header     : {server}")
    if powered:
        print(f"    X-Powered-By      : {powered}")

    hints = {
        "cf-ray": "Cloudflare",
        "x-drupal-cache": "Drupal",
        "x-generator": "Generic CMS marker",
        "x-aspnet-version": "ASP.NET",
        "x-sourcefiles": "ASP",
        "set-cookie": None,  # handled separately
    }
    for h, tech in hints.items():
        if h in (k.lower() for k in headers):
            actual_key = next(k for k in headers if k.lower() == h)
            if tech:
                print(f"    Detected via {actual_key}: {tech}")

    cookies = headers.get("Set-Cookie", "")
    if "wordpress" in cookies.lower():
        print("    Cookie hint       : WordPress")
    if "PHPSESSID" in cookies:
        print("    Cookie hint       : PHP")
    if "laravel_session" in cookies.lower():
        print("    Cookie hint       : Laravel")

    if not server and not powered and not cookies:
        print("    [i] No obvious tech fingerprints in headers")


def get_robots_sitemap(base_url):
    print("\n[+] robots.txt & sitemap.xml")
    for path in ["/robots.txt", "/sitemap.xml"]:
        url = base_url.rstrip("/") + path
        try:
            req = Request(url, headers={"User-Agent": "kArmas_HAWK/1.0"})
            with urlopen(req, timeout=10) as resp:
                content = resp.read(2000).decode(errors="replace")
                print(f"\n    [{path}] (status {resp.status}):")
                for line in content.splitlines()[:25]:
                    print(f"      {line}")
        except HTTPError as e:
            print(f"    [{path}] not found ({e.code})")
        except URLError as e:
            print(f"    [{path}] error: {e.reason}")


def get_ssl_info(domain, port=443):
    print("\n[+] SSL Certificate Info")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                print(f"    Subject     : {subject}")
                print(f"    Issuer      : {issuer}")
                print(f"    Valid from  : {cert.get('notBefore')}")
                print(f"    Valid until : {cert.get('notAfter')}")
                print(f"    SANs        : {cert.get('subjectAltName')}")
    except Exception as e:
        print(f"    [!] SSL check failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="kArmas_HAWK - Authorized web recon tool. Use only on systems you own or have written permission to test."
    )
    parser.add_argument("target", help="Domain or URL (e.g. example.com or https://example.com)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    parser.add_argument("-o", "--output", help="Save results as JSON to this file")
    args = parser.parse_args()

    if not args.no_banner:
        banner()

    target = args.target
    if not target.startswith(("http://", "https://")):
        url = "https://" + target
    else:
        url = target
    domain = urlparse(url).netloc or target

    print(f"[*] Target domain : {domain}")
    print(f"[*] Target URL    : {url}")
    print("=" * 60)

    get_dns_info(domain)
    get_whois_info(domain)
    headers = get_headers(url)
    fingerprint(headers)
    get_robots_sitemap(url)
    get_ssl_info(domain)

    print("\n" + "=" * 60)
    print("[*] Scan complete. Remember: authorized use only.")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"target": domain, "headers": headers}, f, indent=2)
        print(f"[*] Headers saved to {args.output}")


if __name__ == "__main__":
    main()
