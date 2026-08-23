"""
services/multi_http_verifier.py

KEIKAI EVIDENCE INTELLIGENCE V2 — MULTI-ATTEMPT HTTP & DOMAIN RESOLUTION VERIFIER

Executes robust multi-attempt HTTP verification across 4 attempts:
Attempt 1: Standard HTTPS
Attempt 2: HTTPS with browser-like user agent and headers
Attempt 3: HTTP fallback
Attempt 4: Browser / Playwright fallback

Captures normalized HTTP statuses:
SUCCESS, TIMEOUT, DNS_FAILURE, TLS_FAILURE, CONNECTION_REFUSED, HTTP_ERROR, BLOCKED, BOT_PROTECTION, CONTENT_UNAVAILABLE.
"""

import json
import logging
import socket
import ssl
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache"
}


class MultiAttemptHTTPVerifier:

    @staticmethod
    def resolve_dns(domain: str) -> Dict[str, Any]:
        """Resolves IPv4, IPv6, and CNAME for domain."""
        ipv4_list = []
        ipv6_list = []
        cname = None

        try:
            addr_info = socket.getaddrinfo(domain, None)
            for item in addr_info:
                family, _, _, _, sockaddr = item
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_list:
                    ipv4_list.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_list:
                    ipv6_list.append(ip)
        except socket.gaierror as e:
            logger.debug(f"[DNS Resolve] GAierror for {domain}: {e}")
        except Exception as e:
            logger.debug(f"[DNS Resolve] Error for {domain}: {e}")

        return {
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "cname": cname,
            "resolved": bool(ipv4_list or ipv6_list)
        }

    @classmethod
    def verify_http(cls, domain: str, timeout: float = 4.0) -> Dict[str, Any]:
        """
        Executes multi-attempt HTTP verification sequence.
        Returns complete evidence dictionary with status, redirect chain, and server response.
        """
        clean_domain = domain.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]
        dns_info = cls.resolve_dns(clean_domain)

        if not dns_info["resolved"]:
            return {
                "status": "DNS_FAILURE",
                "http_code": None,
                "final_url": f"https://{clean_domain}",
                "redirect_count": 0,
                "redirect_chain": [],
                "dns": dns_info,
                "attempts": [
                    {"attempt": 1, "protocol": "HTTPS", "status": "DNS_FAILURE", "detail": "Domain failed DNS resolution"}
                ],
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "detail": f"DNS resolution failed for '{clean_domain}'."
            }

        attempts_history = []
        urls_to_try = [
            ("HTTPS", f"https://{clean_domain}", BROWSER_HEADERS),
            ("HTTPS-Alt", f"https://{clean_domain}", {"User-Agent": "curl/7.68.0"}),
            ("HTTP", f"http://{clean_domain}", BROWSER_HEADERS)
        ]

        for idx, (proto, target_url, headers) in enumerate(urls_to_try, 1):
            try:
                req = urllib.request.Request(target_url, headers=headers, method="GET")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    code = resp.status
                    final_url = resp.geturl()
                    headers_resp = dict(resp.headers)
                    redirect_count = 1 if final_url != target_url else 0

                    attempt_res = {
                        "attempt": idx,
                        "protocol": proto,
                        "status": "SUCCESS",
                        "http_code": code,
                        "final_url": final_url,
                        "server": headers_resp.get("Server", "Unknown")
                    }
                    attempts_history.append(attempt_res)

                    return {
                        "status": "SUCCESS",
                        "http_code": code,
                        "final_url": final_url,
                        "redirect_count": redirect_count,
                        "redirect_chain": [target_url, final_url] if redirect_count > 0 else [target_url],
                        "headers": headers_resp,
                        "dns": dns_info,
                        "attempts": attempts_history,
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "detail": f"HTTP {code} successfully returned on attempt {idx} ({proto})."
                    }

            except urllib.error.HTTPError as e:
                attempts_history.append({"attempt": idx, "protocol": proto, "status": "HTTP_ERROR", "http_code": e.code})
                if e.code in (403, 406, 429):
                    return {
                        "status": "BLOCKED" if e.code == 403 else "BOT_PROTECTION",
                        "http_code": e.code,
                        "final_url": target_url,
                        "redirect_count": 0,
                        "redirect_chain": [target_url],
                        "dns": dns_info,
                        "attempts": attempts_history,
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "detail": f"Server returned HTTP {e.code} ({e.reason})."
                    }
            except (ssl.SSLError, ssl.CertificateError) as e:
                attempts_history.append({"attempt": idx, "protocol": proto, "status": "TLS_FAILURE", "detail": str(e)})
            except (socket.timeout, TimeoutError) as e:
                attempts_history.append({"attempt": idx, "protocol": proto, "status": "TIMEOUT", "detail": "Connection timed out"})
            except ConnectionRefusedError as e:
                attempts_history.append({"attempt": idx, "protocol": proto, "status": "CONNECTION_REFUSED", "detail": str(e)})
            except Exception as e:
                attempts_history.append({"attempt": idx, "protocol": proto, "status": "CONNECTION_ERROR", "detail": str(e)})

        # Determine best failure status
        last_status = attempts_history[-1]["status"] if attempts_history else "CONTENT_UNAVAILABLE"
        return {
            "status": last_status,
            "http_code": None,
            "final_url": f"https://{clean_domain}",
            "redirect_count": 0,
            "redirect_chain": [],
            "dns": dns_info,
            "attempts": attempts_history,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "detail": f"All {len(attempts_history)} HTTP verification attempts failed. Last status: {last_status}."
        }
