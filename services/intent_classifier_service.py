import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import httpx

logger = logging.getLogger("intent_classifier")

ALLOWLIST_PATH = Path("./config/domain_allowlist.json").resolve()

# Fixed Intent Classification Label Sets required by KEIKAI Threat Intelligence Specification

# Brand Intent Labels (Standard 6-Label Set)
BRAND_INTENT_LABELS = [
    "Authorized reseller/partner",
    "News/media coverage",
    "Fan page/community content",
    "Parody/commentary",
    "Counterfeit or impersonation",
    "Phishing/credential harvesting"
]

# Individual / Creator Intent Labels
CREATOR_INTENT_LABELS = [
    "Fan account (non-deceptive)",
    "Parody",
    "Impersonation account",
    "Scam/giveaway impersonation"
]

# Primary specification label set (6 labels)
INTENT_LABELS = BRAND_INTENT_LABELS

# Combined Master List across all entity types
ALL_INTENT_LABELS = list(dict.fromkeys(BRAND_INTENT_LABELS + CREATOR_INTENT_LABELS))

LEGITIMATE_LABELS = {
    "Authorized reseller/partner",
    "News/media coverage",
    "Fan page/community content",
    "Parody/commentary",
    "Fan account (non-deceptive)",
    "Parody"
}

# Global cached pipeline instance
_CLASSIFIER_PIPELINE = None
_PIPELINE_ATTEMPTED = False


def load_domain_allowlist() -> List[str]:
    """
    Loads known verified partner/legitimate domain list from config/domain_allowlist.json.
    """
    if ALLOWLIST_PATH.exists():
        try:
            with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [d.strip().lower() for d in data if isinstance(d, str)]
        except Exception as e:
            logger.warning(f"Failed to load domain allowlist from {ALLOWLIST_PATH}: {str(e)}")
    return ["amazon.com", "techcrunch.com", "wikipedia.org", "reuters.com", "official-partner.com"]


def extract_text_from_url(url: str, timeout: float = 5.0) -> str:
    """
    Fetches URL content via httpx and extracts clean text (stripping scripts, styles, and tags).
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KEIKAI-IntentScanner/1.0"
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return f"Webpage content for {url} (HTTP {resp.status_code})"

            html = resp.text
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            title_text = title_match.group(1).strip() if title_match else ""

            cleaned_html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.IGNORECASE | re.DOTALL)
            text_only = re.sub(r"<[^>]+>", " ", cleaned_html)
            text_only = re.sub(r"\s+", " ", text_only).strip()

            combined = f"{title_text}. {text_only[:1500]}" if title_text else text_only[:1500]
            return combined.strip() or f"Content from {url}"
    except Exception as e:
        logger.warning(f"Failed to fetch text from URL {url}: {str(e)}")
        return f"Target webpage URL {url}"


def _get_zero_shot_pipeline():
    """
    Lazy-loads Hugging Face zero-shot classification pipeline.
    """
    global _CLASSIFIER_PIPELINE, _PIPELINE_ATTEMPTED
    if _CLASSIFIER_PIPELINE is not None or _PIPELINE_ATTEMPTED:
        return _CLASSIFIER_PIPELINE

    _PIPELINE_ATTEMPTED = True
    try:
        from transformers import pipeline
        _CLASSIFIER_PIPELINE = pipeline(
            "zero-shot-classification",
            model="valhalla/distilbart-mnli-12-3"
        )
        logger.info("Successfully initialized Hugging Face Zero-Shot Intent Classifier pipeline.")
    except Exception as e1:
        try:
            from transformers import pipeline
            _CLASSIFIER_PIPELINE = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli"
            )
            logger.info("Loaded facebook/bart-large-mnli pipeline.")
        except Exception as e2:
            logger.warning(f"Hugging Face transformers pipeline not loaded ({str(e1)}). Using heuristic fallback.")
            _CLASSIFIER_PIPELINE = None

    return _CLASSIFIER_PIPELINE


def heuristic_intent_classification(text: str, entity_type: str = "brand") -> Dict[str, float]:
    """
    Lightweight rule-based keyword & pattern heuristic classifier.
    Supports both brand and individual creator entity types.
    """
    text_lower = text.lower()
    labels_to_use = CREATOR_INTENT_LABELS if entity_type == "individual" else BRAND_INTENT_LABELS

    scores = {label: 0.05 for label in labels_to_use}

    if entity_type == "individual":
        # Scam / Giveaway Impersonation signals (common creator fraud pattern)
        giveaway_keywords = [
            "giveaway", "free crypto", "eth giveaway", "btc giveaway", "airdrop",
            "claim free", "drop address", "whitelisted", "dm to win", "telegram link",
            "send 0.1 get 1", "gift box", "promo code", "bonus prize"
        ]
        g_hits = sum(1 for k in giveaway_keywords if k in text_lower)
        if g_hits > 0:
            scores["Scam/giveaway impersonation"] += g_hits * 0.40

        # Impersonation account signals
        impersonation_keywords = [
            "official support", "real page", "backup account", "uncensored", "vip channel",
            "management", "assistant", "dm for info", "invest with me"
        ]
        i_hits = sum(1 for k in impersonation_keywords if k in text_lower)
        if i_hits > 0:
            scores["Impersonation account"] += i_hits * 0.35

        # Fan account signals
        fan_keywords = ["fan page", "fan club", "daily dose", "highlights", "clips", "edits", "support page", "unofficial"]
        f_hits = sum(1 for k in fan_keywords if k in text_lower)
        if f_hits > 0:
            scores["Fan account (non-deceptive)"] += f_hits * 0.35

        # Parody signals
        parody_keywords = ["parody", "satire", "memes", "spoof", "humor", "joke account"]
        p_hits = sum(1 for k in parody_keywords if k in text_lower)
        if p_hits > 0:
            scores["Parody"] += p_hits * 0.40
    else:
        # Standard Brand Signals
        phish_keywords = ["verify account", "login", "password", "suspended", "urgent action", "credential", "security alert", "banking", "account locked"]
        phish_hits = sum(1 for k in phish_keywords if k in text_lower)
        if phish_hits > 0:
            scores["Phishing/credential harvesting"] += phish_hits * 0.35

        counterfeit_keywords = ["cheap replica", "fake", "copycat", "discount store", "mirror site", "buy direct", "unauthorized"]
        c_hits = sum(1 for k in counterfeit_keywords if k in text_lower)
        if c_hits > 0:
            scores["Counterfeit or impersonation"] += c_hits * 0.30

        news_keywords = ["press release", "reporters", "published on", "interview", "editor", "journal", "techcrunch", "reuters", "bloomberg", "article", "news", "reporting"]
        news_hits = sum(1 for k in news_keywords if k in text_lower)
        if news_hits > 0:
            scores["News/media coverage"] += news_hits * 0.35

        partner_keywords = ["authorized partner", "official reseller", "distributor", "partner network", "certified store", "approved dealer"]
        partner_hits = sum(1 for k in partner_keywords if k in text_lower)
        if partner_hits > 0:
            scores["Authorized reseller/partner"] += partner_hits * 0.40

        fan_keywords = ["fan page", "community hub", "enthusiast", "forum", "discussion board", "unofficial fan", "appreciation"]
        fan_hits = sum(1 for k in fan_keywords if k in text_lower)
        if fan_hits > 0:
            scores["Fan page/community content"] += fan_hits * 0.35

        parody_keywords = ["parody", "satire", "commentary", "critique", "spoof", "humor", "meme"]
        parody_hits = sum(1 for k in parody_keywords if k in text_lower)
        if parody_hits > 0:
            scores["Parody/commentary"] += parody_hits * 0.35

    # Normalize to probability distribution
    total_score = sum(scores.values())
    probs = {label: round(score / total_score, 4) for label, score in scores.items()}
    return probs


def classify_intent(
    text: Optional[str] = None,
    url: Optional[str] = None,
    domain: Optional[str] = None,
    override_label: Optional[str] = None,
    entity_type: str = "brand"
) -> Dict[str, Any]:
    """
    Main Intent Classification Orchestrator.
    Supports both brand and individual/creator target entity types.
    """
    clean_domain = domain.strip().lower() if domain else None
    if not clean_domain and url:
        clean_domain = url.replace("https://", "").replace("http://", "").split("/")[0].lower()

    target_labels = CREATOR_INTENT_LABELS if entity_type == "individual" else BRAND_INTENT_LABELS

    # Rule-Based Override Layer 1: Manual Investigator Override
    if override_label and override_label in ALL_INTENT_LABELS:
        probs = [{ "label": l, "probability": 1.0 if l == override_label else 0.0 } for l in target_labels]
        return {
            "domain": clean_domain,
            "top_label": override_label,
            "confidence": 100.0,
            "is_legitimate": override_label in LEGITIMATE_LABELS,
            "is_override": True,
            "override_reason": f"Manual investigator override confirmed as '{override_label}'.",
            "probabilities": probs
        }

    # Rule-Based Override Layer 2: Verified Partner Domain Allowlist Check
    allowlist = load_domain_allowlist()
    if clean_domain and any(clean_domain == allowed or clean_domain.endswith(f".{allowed}") for allowed in allowlist):
        override_target = "Authorized reseller/partner" if entity_type == "brand" else "Fan account (non-deceptive)"
        probs = [{ "label": l, "probability": 1.0 if l == override_target else 0.0 } for l in target_labels]
        return {
            "domain": clean_domain,
            "top_label": override_target,
            "confidence": 100.0,
            "is_legitimate": True,
            "is_override": True,
            "override_reason": f"Domain '{clean_domain}' matches verified partner allowlist.",
            "probabilities": probs
        }

    target_text = text.strip() if text else ""
    if not target_text and url:
        target_text = extract_text_from_url(url)

    if not target_text:
        target_text = f"Analysis for domain {clean_domain or 'target property'}"

    # Attempt Zero-Shot ML Classification
    pipeline_obj = _get_zero_shot_pipeline()
    probs_dict: Dict[str, float] = {}

    if pipeline_obj is not None:
        try:
            ml_res = pipeline_obj(target_text, candidate_labels=target_labels, multi_label=False)
            labels = ml_res.get("labels", [])
            scores = ml_res.get("scores", [])
            probs_dict = {l: round(float(s), 4) for l, s in zip(labels, scores)}
        except Exception as e:
            logger.warning(f"Zero-shot ML classification failed: {str(e)}. Shifting to fallback.")
            probs_dict = heuristic_intent_classification(target_text, entity_type=entity_type)
    else:
        probs_dict = heuristic_intent_classification(target_text, entity_type=entity_type)

    sorted_probs = sorted(probs_dict.items(), key=lambda x: -x[1])
    top_label, top_prob = sorted_probs[0]
    prob_items = [{"label": label, "probability": prob} for label, prob in sorted_probs]

    return {
        "domain": clean_domain,
        "top_label": top_label,
        "confidence": round(top_prob * 100.0, 2),
        "is_legitimate": top_label in LEGITIMATE_LABELS,
        "is_override": False,
        "override_reason": None,
        "probabilities": prob_items
    }
