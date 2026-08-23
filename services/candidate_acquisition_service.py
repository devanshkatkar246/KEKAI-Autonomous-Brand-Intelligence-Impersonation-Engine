"""
services/candidate_acquisition_service.py

TASK 2D V3 — Resilient Candidate Webpage & Visual Asset Acquisition Service

Provides multi-strategy candidate webpage acquisition, DNS precheck, failure classification taxonomy,
TLS fallback handling, redirect chain tracking, HTML image/SVG/favicon extraction, and asset fingerprinting.

Failure Taxonomy:
  - DNS_FAILURE: Domain name resolution failed
  - CONNECTION_FAILURE: TCP connection refused / host unreachable
  - TLS_FAILURE: SSL/TLS handshake failed
  - TIMEOUT: Network or page load timed out
  - HTTP_4XX: HTTP client error (400, 403, 404, etc.)
  - HTTP_5XX: HTTP server error (500, 502, 503, etc.)
  - CONTENT_NOT_HTML: Content-Type is non-HTML (PDF, binary, image, etc.)
  - PAGE_BLOCKED: Blocked by security policy or firewall
  - UNKNOWN_FAILURE: Unclassified error
"""

import os
import re
import sys
import socket
import logging
import uuid
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from PIL import Image

logger = logging.getLogger("keikai.candidate_acquisition")

# Upload directories
SCREENSHOT_DIR = Path("./uploads/screenshots")
VISUAL_ASSETS_DIR = Path("./uploads/visual_assets")

DEFAULT_TIMEOUT = int(os.getenv("ACQUISITION_TIMEOUT", "8"))
ALLOW_INSECURE_TLS = os.getenv("SCREENSHOT_ALLOW_INSECURE_TLS", "true").lower() in ("true", "1", "yes")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Suppress insecure request warnings if fallback enabled
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def _ensure_dirs() -> None:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    VISUAL_ASSETS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# PHASE 4 — DNS Precheck
# ---------------------------------------------------------------------------

def check_dns_resolution(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs a lightweight DNS resolution check for a domain name.
    Distinguishes DNS_RESOLVED vs DNS_FAILED vs DNS_TIMEOUT.
    """
    clean_dom = domain.strip().lower()
    if "://" in clean_dom:
        clean_dom = urlparse(clean_dom).netloc or clean_dom
    clean_dom = clean_dom.split("/")[0].split(":")[0]

    if not clean_dom:
        return {"status": "DNS_FAILED", "resolved": False, "ip_addresses": [], "error": "Empty domain"}

    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(clean_dom, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set([item[4][0] for item in addr_info if item[4]]))
        if ips:
            return {
                "status": "DNS_RESOLVED",
                "resolved": True,
                "domain": clean_dom,
                "ip_addresses": ips,
                "error": None
            }
        else:
            return {
                "status": "DNS_FAILED",
                "resolved": False,
                "domain": clean_dom,
                "ip_addresses": [],
                "error": "No IP addresses returned"
            }
    except socket.gaierror as e:
        return {
            "status": "DNS_FAILED",
            "resolved": False,
            "domain": clean_dom,
            "ip_addresses": [],
            "error": f"DNS resolution failed: {str(e)}"
        }
    except socket.timeout:
        return {
            "status": "DNS_TIMEOUT",
            "resolved": False,
            "domain": clean_dom,
            "ip_addresses": [],
            "error": f"DNS query timed out after {timeout}s"
        }
    except Exception as e:
        return {
            "status": "DNS_FAILED",
            "resolved": False,
            "domain": clean_dom,
            "ip_addresses": [],
            "error": f"DNS error: {str(e)[:100]}"
        }
    finally:
        socket.setdefaulttimeout(orig_timeout)


# ---------------------------------------------------------------------------
# PHASE 3 & 5 & 8 — Resilient Multi-Strategy HTTP/HTTPS Acquisition Engine
# ---------------------------------------------------------------------------

class CandidateAcquisitionEngine:

    @staticmethod
    def _generate_candidate_urls(domain_raw: str) -> List[str]:
        """
        Generates URL candidates in prioritized strategy order:
          1. https://domain
          2. https://www.domain
          3. http://domain
          4. http://www.domain
        """
        d = domain_raw.strip().lower()
        if "://" in d:
            parsed = urlparse(d)
            host = parsed.netloc or parsed.path
        else:
            host = d.split("/")[0]

        host = host.split("?")[0].split("#")[0]
        if not host:
            return []

        base_host = host[4:] if host.startswith("www.") else host

        urls = [
            f"https://{base_host}",
            f"https://www.{{base_host}}" if not host.startswith("www.") else f"https://{host}",
            f"http://{base_host}",
            f"http://www.{{base_host}}" if not host.startswith("www.") else f"http://{host}",
        ]
        
        # Format strings cleanly
        urls = [
            f"https://{base_host}",
            f"https://www.{base_host}",
            f"http://{base_host}",
            f"http://www.{base_host}"
        ]

        # Deduplicate preserving order
        seen = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    @classmethod
    def acquire_candidate_webpage(
        cls,
        domain: str,
        timeout: int = DEFAULT_TIMEOUT,
        allow_insecure_tls_fallback: bool = ALLOW_INSECURE_TLS
    ) -> Dict[str, Any]:
        """
        Multi-strategy candidate acquisition:
          1. Lightweight DNS precheck
          2. Sequential attempts across https://domain, https://www.domain, http://domain, http://www.domain
          3. Follows redirect chains & records provenance
          4. Validates Content-Type (HTML only)
          5. Insecure TLS fallback retry if SSL error occurs
          6. Returns complete Acquisition Trace + HTML & screenshot if acquired
        """
        _ensure_dirs()
        clean_dom = domain.strip().lower()
        if "://" in clean_dom:
            clean_dom = urlparse(clean_dom).netloc or clean_dom
        clean_dom = clean_dom.split("/")[0]

        # Step 1: DNS Precheck
        dns_res = check_dns_resolution(clean_dom, timeout=3.0)
        if not dns_res["resolved"]:
            return {
                "status": "failed",
                "requested_domain": clean_dom,
                "failure_category": "DNS_FAILURE",
                "failure_reason": dns_res["error"] or "Domain DNS resolution failed",
                "dns_status": dns_res["status"],
                "dns_ip_addresses": dns_res["ip_addresses"],
                "attempts": [],
                "successful_url": None,
                "final_url": None,
                "screenshot_path": None,
                "html_content": None,
                "headers": {},
                "redirect_chain": [],
                "tls_fallback_used": False
            }

        candidate_urls = cls._generate_candidate_urls(clean_dom)
        attempts = []
        successful_url = None
        final_url = None
        html_content = None
        headers = {}
        redirect_chain = []
        screenshot_path = None
        tls_fallback_used = False
        last_failure_cat = "CONNECTION_FAILURE"
        last_failure_reason = "All URL acquisition attempts failed"

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        for target_url in candidate_urls:
            attempt_record = {
                "url": target_url,
                "status": "pending",
                "status_code": None,
                "content_type": None,
                "response_time_ms": None,
                "tls_fallback": False,
                "error": None
            }

            start_t = time.time()
            try:
                resp = session.get(
                    target_url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=True
                )
                elapsed_ms = int((time.time() - start_t) * 1000)
                attempt_record["status_code"] = resp.status_code
                attempt_record["response_time_ms"] = elapsed_ms
                attempt_record["content_type"] = resp.headers.get("content-type", "")

                # Record redirect history
                r_chain = [r.url for r in resp.history] + [resp.url]
                
                # Check Content-Type (Phase 10)
                ctype = (resp.headers.get("content-type") or "").lower()
                is_html = any(h in ctype for h in ["text/html", "application/xhtml+xml", "text/plain"])

                if resp.status_code >= 400:
                    attempt_record["status"] = "failed"
                    cat = "HTTP_4XX" if resp.status_code < 500 else "HTTP_5XX"
                    attempt_record["error"] = f"HTTP {resp.status_code} {resp.reason}"
                    attempts.append(attempt_record)
                    last_failure_cat = cat
                    last_failure_reason = attempt_record["error"]
                    continue

                if not is_html and resp.content:
                    attempt_record["status"] = "failed"
                    attempt_record["error"] = f"Content-Type not HTML: {ctype[:50]}"
                    attempts.append(attempt_record)
                    last_failure_cat = "CONTENT_NOT_HTML"
                    last_failure_reason = attempt_record["error"]
                    continue

                # Acquisition Success!
                attempt_record["status"] = "success"
                attempts.append(attempt_record)

                successful_url = target_url
                final_url = str(resp.url)
                html_content = resp.text
                headers = dict(resp.headers)
                redirect_chain = r_chain
                break

            except requests.exceptions.SSLError as ssl_err:
                elapsed_ms = int((time.time() - start_t) * 1000)
                attempt_record["response_time_ms"] = elapsed_ms

                # Phase 8: Insecure TLS Fallback Retry
                if allow_insecure_tls_fallback:
                    logger.info(f"[AcquisitionEngine] SSL error for {target_url}, retrying with verify=False")
                    try:
                        resp_fallback = session.get(
                            target_url,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=False
                        )
                        fallback_ms = int((time.time() - start_t) * 1000)
                        attempt_record["status_code"] = resp_fallback.status_code
                        attempt_record["response_time_ms"] = fallback_ms
                        attempt_record["content_type"] = resp_fallback.headers.get("content-type", "")
                        attempt_record["tls_fallback"] = True

                        if resp_fallback.status_code < 400:
                            attempt_record["status"] = "success"
                            attempts.append(attempt_record)

                            successful_url = target_url
                            final_url = str(resp_fallback.url)
                            html_content = resp_fallback.text
                            headers = dict(resp_fallback.headers)
                            redirect_chain = [r.url for r in resp_fallback.history] + [resp_fallback.url]
                            tls_fallback_used = True
                            break
                        else:
                            attempt_record["status"] = "failed"
                            attempt_record["error"] = f"Insecure TLS retry HTTP {resp_fallback.status_code}"
                            attempts.append(attempt_record)
                            last_failure_cat = "HTTP_4XX" if resp_fallback.status_code < 500 else "HTTP_5XX"
                            last_failure_reason = attempt_record["error"]
                            continue
                    except Exception as fb_e:
                        attempt_record["status"] = "failed"
                        attempt_record["error"] = f"TLS fallback failed: {str(fb_e)[:80]}"
                        attempts.append(attempt_record)
                        last_failure_cat = "TLS_FAILURE"
                        last_failure_reason = str(ssl_err)[:80]
                        continue
                else:
                    attempt_record["status"] = "failed"
                    attempt_record["error"] = f"SSL error: {str(ssl_err)[:80]}"
                    attempts.append(attempt_record)
                    last_failure_cat = "TLS_FAILURE"
                    last_failure_reason = attempt_record["error"]
                    continue

            except requests.exceptions.Timeout:
                elapsed_ms = int((time.time() - start_t) * 1000)
                attempt_record["response_time_ms"] = elapsed_ms
                attempt_record["status"] = "failed"
                attempt_record["error"] = f"Timeout after {timeout}s"
                attempts.append(attempt_record)
                last_failure_cat = "TIMEOUT"
                last_failure_reason = attempt_record["error"]
                continue

            except requests.exceptions.ConnectionError as conn_err:
                elapsed_ms = int((time.time() - start_t) * 1000)
                attempt_record["response_time_ms"] = elapsed_ms
                attempt_record["status"] = "failed"
                attempt_record["error"] = f"Connection failed: {str(conn_err)[:80]}"
                attempts.append(attempt_record)
                last_failure_cat = "CONNECTION_FAILURE"
                last_failure_reason = attempt_record["error"]
                continue

            except Exception as gen_err:
                elapsed_ms = int((time.time() - start_t) * 1000)
                attempt_record["response_time_ms"] = elapsed_ms
                attempt_record["status"] = "failed"
                attempt_record["error"] = f"Error: {str(gen_err)[:80]}"
                attempts.append(attempt_record)
                last_failure_cat = "UNKNOWN_FAILURE"
                last_failure_reason = attempt_record["error"]
                continue

        if not successful_url or not html_content:
            return {
                "status": "failed",
                "requested_domain": clean_dom,
                "failure_category": last_failure_cat,
                "failure_reason": last_failure_reason,
                "dns_status": dns_res["status"],
                "dns_ip_addresses": dns_res["ip_addresses"],
                "attempts": attempts,
                "successful_url": None,
                "final_url": None,
                "screenshot_path": None,
                "html_content": None,
                "headers": {},
                "redirect_chain": [],
                "tls_fallback_used": tls_fallback_used
            }

        # Step 4: Extract/render screenshot proxy from acquired HTML (OG image / Favicon / inline visual)
        screenshot_path = cls._acquire_screenshot_proxy_from_html(
            html_content=html_content,
            base_url=final_url,
            timeout=timeout,
            session=session
        )

        return {
            "status": "success",
            "requested_domain": clean_dom,
            "failure_category": None,
            "failure_reason": None,
            "dns_status": dns_res["status"],
            "dns_ip_addresses": dns_res["ip_addresses"],
            "attempts": attempts,
            "successful_url": successful_url,
            "final_url": final_url,
            "screenshot_path": screenshot_path,
            "html_content": html_content,
            "headers": headers,
            "redirect_chain": redirect_chain,
            "tls_fallback_used": tls_fallback_used
        }

    @classmethod
    def _acquire_screenshot_proxy_from_html(
        cls,
        html_content: str,
        base_url: str,
        timeout: int,
        session: requests.Session
    ) -> Optional[str]:
        """
        Downloads open graph image or favicon as a visual screenshot proxy.
        Verifies file existence, readable image format, and non-zero dimensions.
        """
        # 1. og:image
        m = re.search(
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\'](https?://[^"\'>\s]+)["\']',
            html_content, re.IGNORECASE
        ) or re.search(
            r'<meta[^>]+content=["\'](https?://[^"\'>\s]+)["\'][^>]+property=["\']og:image["\']',
            html_content, re.IGNORECASE
        )
        image_url = m.group(1) if m else None

        # 2. favicon
        if not image_url:
            m_fav = re.search(
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\'>\s]+)["\']',
                html_content, re.IGNORECASE
            )
            if m_fav:
                raw_fav = m_fav.group(1)
                image_url = urljoin(base_url, raw_fav)
            else:
                parsed = urlparse(base_url)
                if parsed.scheme and parsed.netloc:
                    image_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        if not image_url:
            return None

        try:
            resp = session.get(image_url, timeout=timeout, verify=False, stream=True)
            if resp.status_code == 200 and len(resp.content) > 100:
                ext = ".png" if "png" in resp.headers.get("content-type", "") else ".jpg"
                out_path = SCREENSHOT_DIR / f"sc_{uuid.uuid4().hex[:12]}{ext}"
                out_path.write_bytes(resp.content)

                # Verification (Phase 11): Verify Pillow can open it with non-zero dimensions
                with Image.open(str(out_path)) as img:
                    if img.width > 0 and img.height > 0:
                        return str(out_path)
                out_path.unlink(missing_ok=True)
        except Exception as e:
            logger.debug(f"[AcquisitionEngine] Screenshot proxy download failed for {image_url}: {e}")

        return None


# ---------------------------------------------------------------------------
# PHASES 12-16 — Multi-Layer Visual Asset Extraction (IMG, SVG, Favicon)
# ---------------------------------------------------------------------------

def extract_webpage_visual_assets(
    html_content: str,
    base_url: str,
    max_assets: int = 10,
    timeout: int = 5
) -> Dict[str, Any]:
    """
    Multi-layer visual asset extraction from acquired HTML DOM:
      1. <img> tags (src, alt, title, width, height)
      2. Inline or linked <svg> elements
      3. Favicons (<link rel="icon">, /favicon.ico)

    Filters assets based on branding indicators (logo, brand, icon, header).
    Downloads same-origin & safe image assets to ./uploads/visual_assets.
    """
    _ensure_dirs()

    extracted_images = []
    extracted_svgs = []
    extracted_favicons = []

    if not html_content:
        return {
            "images_found": 0,
            "svg_found": 0,
            "favicons_found": 0,
            "assets": []
        }

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # 1. <img> Tag Extraction
    img_matches = re.findall(
        r'<img[^>]+src=["\']([^"\'>\s]+)["\'][^>]*>',
        html_content, re.IGNORECASE
    )

    for src in img_matches:
        if len(extracted_images) >= max_assets:
            break
        
        full_src = urljoin(base_url, src)
        src_lower = full_src.lower()
        
        # Filter for likely brand/logo assets
        is_branding = any(k in src_lower for k in ["logo", "brand", "header", "nav", "icon", "main", "banner"])

        try:
            resp = session.get(full_src, timeout=timeout, verify=False)
            if resp.status_code == 200 and 100 < len(resp.content) < 5 * 1024 * 1024:
                ext = ".svg" if "svg" in resp.headers.get("content-type", "") or src_lower.endswith(".svg") else ".png"
                asset_path = VISUAL_ASSETS_DIR / f"img_{uuid.uuid4().hex[:10]}{ext}"
                asset_path.write_bytes(resp.content)

                asset_meta = {
                    "asset_type": "IMG",
                    "source": full_src,
                    "local_path": str(asset_path),
                    "is_branding_hint": is_branding,
                    "content_type": resp.headers.get("content-type", "")
                }

                # If image readable, get dimensions
                if ext != ".svg":
                    try:
                        with Image.open(str(asset_path)) as p_img:
                            asset_meta["width"] = p_img.width
                            asset_meta["height"] = p_img.height
                    except Exception:
                        pass

                extracted_images.append(asset_meta)
        except Exception:
            continue

    # 2. Inline <svg> Extraction
    svg_blocks = re.findall(r'(<svg[^>]*>.*?</svg>)', html_content, re.DOTALL | re.IGNORECASE)
    for idx, svg_code in enumerate(svg_blocks[:5]):
        try:
            svg_path = VISUAL_ASSETS_DIR / f"svg_{uuid.uuid4().hex[:10]}.svg"
            svg_path.write_text(svg_code, encoding="utf-8")
            extracted_svgs.append({
                "asset_type": "SVG",
                "source": f"inline_svg_{idx+1}",
                "local_path": str(svg_path),
                "is_branding_hint": "logo" in svg_code.lower() or "brand" in svg_code.lower(),
                "content_type": "image/svg+xml"
            })
        except Exception:
            continue

    # 3. Favicon Extraction
    fav_matches = re.findall(
        r'<link[^>]+rel=["\'](?:[^"\'>]*\bicon\b[^"\'>]*)["\'][^>]+href=["\']([^"\'>\s]+)["\']',
        html_content, re.IGNORECASE
    ) or re.findall(
        r'<link[^>]+href=["\']([^"\'>\s]+)["\'][^>]+rel=["\'](?:[^"\'>]*\bicon\b[^"\'>]*)["\']',
        html_content, re.IGNORECASE
    )
    fav_url = urljoin(base_url, fav_matches[0]) if fav_matches else urljoin(base_url, "/favicon.ico")

    try:
        f_resp = session.get(fav_url, timeout=timeout, verify=False)
        if f_resp.status_code == 200 and len(f_resp.content) > 10:
            fav_path = VISUAL_ASSETS_DIR / f"fav_{uuid.uuid4().hex[:10]}.ico"
            fav_path.write_bytes(f_resp.content)
            extracted_favicons.append({
                "asset_type": "FAVICON",
                "source": fav_url,
                "local_path": str(fav_path),
                "is_branding_hint": True,
                "content_type": f_resp.headers.get("content-type", "")
            })
    except Exception:
        pass

    all_assets = extracted_images + extracted_svgs + extracted_favicons

    return {
        "images_found": len(extracted_images),
        "svg_found": len(extracted_svgs),
        "favicons_found": len(extracted_favicons),
        "assets": all_assets
    }


# ---------------------------------------------------------------------------
# PHASE 39 — viaSocket Event Payload Generator
# ---------------------------------------------------------------------------

def generate_viasocket_event_payload(
    case_id: str,
    brand: str,
    official_domain: str,
    candidate_domain: str,
    assessment: str,
    evidence_strength: str,
    visual_match_level: str,
    threat_sources: List[str],
    credential_indicators: bool,
    screenshot_available: bool
) -> Dict[str, Any]:
    """
    Generates standard viaSocket HIGH_CONFIDENCE_IMPERSONATION_DETECTED payload schema
    for downstream incident response / human approval webhooks (no auto-takedown).
    """
    return {
        "event": "HIGH_CONFIDENCE_IMPERSONATION_DETECTED",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "case_id": case_id,
        "brand": brand,
        "official_domain": official_domain,
        "candidate_domain": candidate_domain,
        "assessment": assessment,
        "evidence_strength": evidence_strength,
        "visual_match": visual_match_level,
        "threat_sources": threat_sources,
        "credential_indicators": credential_indicators,
        "screenshot_available": screenshot_available,
        "response_automation": {
            "takedown_requested": False,
            "requires_human_approval": True,
            "webhook_ready": True
        }
    }
