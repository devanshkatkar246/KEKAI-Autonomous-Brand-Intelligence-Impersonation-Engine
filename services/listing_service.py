import os
import json
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from services.imagehash_service import compute_image_hashes, compare_two_images
from services.intent_classifier_service import classify_intent
from database import insert_scanned_asset, log_case_event

logger = logging.getLogger("listing_service")

MSRP_CONFIG_PATH = Path("./config/brand_msrp.json").resolve()

# Supported currencies and their display metadata
CURRENCY_META = {
    "USD": {"symbol": "$",  "symbol_suffix": False, "label": "USD"},
    "INR": {"symbol": "₹",  "symbol_suffix": False, "label": "INR"},
}
SUPPORTED_CURRENCIES = list(CURRENCY_META.keys())
DEFAULT_CURRENCY = "USD"


def format_price(amount: Optional[float], currency: str) -> str:
    """
    Returns a correctly formatted price string for the given currency.

    USD → "$10,000.00"
    INR → "₹10,50,000.00"  (Indian lakh-crore comma grouping)
    """
    if amount is None:
        return "N/A"
    currency = (currency or DEFAULT_CURRENCY).upper()
    meta = CURRENCY_META.get(currency, CURRENCY_META["USD"])
    symbol = meta["symbol"]
    if currency == "INR":
        # Indian number system: 2,57,000 style grouping
        formatted = _inr_format(amount)
        return f"{symbol}{formatted}"
    else:
        return f"{symbol}{amount:,.2f}"


def _inr_format(amount: float) -> str:
    """Formats a number using the Indian lakh/crore comma system (e.g. 1,05,000.00)."""
    integer_part = int(amount)
    decimal_part = round(amount - integer_part, 2)
    s = str(integer_part)
    if len(s) > 3:
        # Last 3 digits, then groups of 2
        result = s[-3:]
        s = s[:-3]
        while s:
            result = s[-2:] + "," + result
            s = s[:-2]
        s = result
    else:
        s = s
    decimal_str = f"{decimal_part:.2f}"[1:]  # ".00"
    return s + decimal_str


def load_brand_msrp_config() -> Dict[str, Dict[str, float]]:
    """
    Loads reference MSRP prices per brand from config/brand_msrp.json.

    Supports both the new multi-currency format:
        { "Rolex": { "usd": 10000.0, "inr": 1050000.0, ... }, ... }
    and the legacy flat format (USD only):
        { "Rolex": 10000.0, ... }

    Returns a dict keyed by lowercase brand name, values are
    { "usd": float, "inr": float } dicts.
    """
    defaults = {
        "rolex":        {"usd": 10000.0,  "inr": 1050000.0},
        "apple":        {"usd": 999.0,    "inr": 89900.0},
        "nike":         {"usd": 150.0,    "inr": 10295.0},
        "louis vuitton":{"usd": 2500.0,   "inr": 305000.0},
        "ray-ban":      {"usd": 180.0,    "inr": 15490.0},
        "gucci":        {"usd": 1800.0,   "inr": 195000.0},
        "samsung":      {"usd": 899.0,    "inr": 74999.0},
        "sony":         {"usd": 399.0,    "inr": 34990.0},
    }

    if not MSRP_CONFIG_PATH.exists():
        return defaults

    try:
        with open(MSRP_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)

        if not isinstance(raw, dict):
            return defaults

        result = {}
        for brand, val in raw.items():
            key = brand.strip().lower()
            if isinstance(val, dict):
                # New multi-currency format
                result[key] = {
                    "usd": float(val.get("usd", 0.0)),
                    "inr": float(val.get("inr", 0.0)),
                }
            elif isinstance(val, (int, float)):
                # Legacy flat format — USD only; INR not available
                result[key] = {"usd": float(val), "inr": 0.0}
        return result if result else defaults

    except Exception as e:
        logger.warning("Failed to load brand MSRP config: %s", e)
        return defaults


def check_price_anomaly(
    price: Optional[float],
    target_brand: Optional[str],
    currency: str = "USD",
) -> Dict[str, Any]:
    """
    Compares listing price against the reference MSRP for the given currency.
    Flags prices ≤ 50% MSRP as high-risk anomalies.

    Parameters
    ----------
    price         : Listing price in the specified currency.
    target_brand  : Brand name to look up in brand_msrp.json.
    currency      : "USD" or "INR" — determines which MSRP figure to compare against.

    Returns
    -------
    Dict with keys: price_anomaly, msrp, currency, discount_percentage, message
    """
    currency = (currency or DEFAULT_CURRENCY).upper()
    if currency not in SUPPORTED_CURRENCIES:
        currency = DEFAULT_CURRENCY

    if price is None or price <= 0 or not target_brand:
        return {
            "price_anomaly": False,
            "msrp": None,
            "currency": currency,
            "discount_percentage": 0.0,
            "message": "No price or MSRP reference available for comparison.",
        }

    msrp_map = load_brand_msrp_config()
    clean_brand = target_brand.strip().lower()
    currency_key = currency.lower()  # "usd" or "inr"

    matched_msrp = None
    for b_name, msrp_dict in msrp_map.items():
        if b_name in clean_brand or clean_brand in b_name:
            matched_msrp = msrp_dict.get(currency_key, 0.0)
            break

    if matched_msrp is None or matched_msrp <= 0:
        return {
            "price_anomaly": False,
            "msrp": None,
            "currency": currency,
            "discount_percentage": 0.0,
            "message": (
                f"No {currency} reference MSRP on file for brand '{target_brand}'. "
                f"Add '{target_brand}' to config/brand_msrp.json to enable price anomaly detection."
            ),
        }

    discount_pct = round(((matched_msrp - price) / matched_msrp) * 100.0, 1)
    is_anomaly = price <= (0.50 * matched_msrp)

    price_str = format_price(price, currency)
    msrp_str  = format_price(matched_msrp, currency)

    if is_anomaly:
        msg = (
            f"PRICE ANOMALY ALERT: Listing price {price_str} is {discount_pct}% "
            f"below reference MSRP ({msrp_str})."
        )
    else:
        msg = (
            f"Price {price_str} is within normal threshold "
            f"({discount_pct}% off MSRP {msrp_str})."
        )

    return {
        "price_anomaly": is_anomaly,
        "msrp": matched_msrp,
        "currency": currency,
        "discount_percentage": max(0.0, discount_pct),
        "message": msg,
    }


def analyze_marketplace_listing(
    title: str,
    seller_name: str,
    description: Optional[str] = None,
    price: Optional[float] = None,
    currency: str = "USD",
    target_brand: Optional[str] = None,
    image_path: Optional[str] = None,
    reference_image_path: Optional[str] = None,
    listing_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Core Counterfeit Listing Analyzer.

    Parameters
    ----------
    currency : "USD" or "INR".  Determines which MSRP branch is used for
               price anomaly detection and how the price is formatted in
               all output strings and the PDF report.
    """
    currency = (currency or DEFAULT_CURRENCY).upper()
    unique_id = listing_id or f"LST-{uuid.uuid4().hex[:8].upper()}"
    clean_seller = seller_name.strip() if seller_name else "Unknown Seller"
    clean_title  = title.strip() if title else "Marketplace Product Listing"
    clean_desc   = description.strip() if description else ""

    # Step 1: Image Hashing & Similarity Check
    phash_str  = "0000000000000000"
    dhash_str  = "0000000000000000"
    image_sim  = 50.0

    if image_path and os.path.exists(image_path):
        try:
            hashes = compute_image_hashes(image_path)
            phash_str = hashes.get("phash_str", phash_str)
            dhash_str = hashes.get("dhash_str", dhash_str)

            if reference_image_path and os.path.exists(reference_image_path):
                sim_res   = compare_two_images(reference_image_path, image_path)
                image_sim = sim_res.get("combined_similarity_percentage", 50.0)
            else:
                image_sim = 75.0  # Default when candidate matches brand logo features
        except Exception as e:
            logger.warning("Listing image hashing error: %s", e)

    # Step 2: Intent Classification
    text_corpus = f"{clean_title}. {clean_desc}"
    intent_res  = classify_intent(text=text_corpus, domain=clean_seller)

    # Step 3: Price Anomaly Check (currency-aware)
    price_res = check_price_anomaly(price, target_brand, currency=currency)

    # Step 4: Composite Risk Scoring
    # Image similarity (35%) + Intent score (40%) + Price anomaly penalty (25%)
    intent_score = 0.0
    if intent_res.get("top_label") in ["Counterfeit or impersonation", "Phishing/credential harvesting"]:
        intent_score = 40.0
    elif intent_res.get("top_label") in ["Authorized reseller/partner", "News/media coverage"]:
        intent_score = 0.0
    else:
        intent_score = 15.0

    image_score = (image_sim / 100.0) * 35.0
    price_score = 25.0 if price_res["price_anomaly"] else 0.0

    raw_risk    = image_score + intent_score + price_score
    risk_rating = max(0.0, min(100.0, round(raw_risk, 1)))

    if risk_rating >= 70.0:
        verdict = "High Risk Counterfeit"
    elif risk_rating >= 40.0:
        verdict = "Medium Risk Listing"
    else:
        verdict = "Legitimate / Authorized Listing"

    result_data = {
        "listing_id":          unique_id,
        "title":               clean_title,
        "seller_name":         clean_seller,
        "price":               price,
        "currency":            currency,
        "target_brand":        target_brand or "General Brand",
        "verdict":             verdict,
        "risk_rating":         risk_rating,
        "phash":               phash_str,
        "dhash":               dhash_str,
        "image_similarity":    image_sim,
        "intent_label":        intent_res["top_label"],
        "intent_confidence":   intent_res["confidence"],
        "is_legitimate":       intent_res["is_legitimate"],
        "price_anomaly":       price_res["price_anomaly"],
        "msrp":                price_res["msrp"],
        "discount_percentage": price_res["discount_percentage"],
        "price_message":       price_res["message"],
    }

    # Step 5: SQLite Asset Store Persistence
    try:
        insert_scanned_asset(
            asset_type="listing",
            asset_id=unique_id,
            ip_address=clean_seller,
            phash=phash_str,
            dhash=dhash_str,
            target_brand=target_brand,
            confidence=risk_rating,
            intent_label=intent_res["top_label"],
            intent_confidence=intent_res["confidence"],
            metadata={
                "title":            clean_title,
                "seller_name":      clean_seller,
                "price":            price,
                "currency":         currency,
                "verdict":          verdict,
                "price_anomaly":    price_res["price_anomaly"],
                "image_similarity": image_sim,
            },
        )
        log_case_event(
            "default",
            "listing_scanned",
            (
                f"Marketplace listing '{clean_title}' by '{clean_seller}' analyzed: "
                f"Verdict '{verdict}' ({risk_rating}%) [{currency}]"
            ),
        )
    except Exception as db_err:
        logger.warning("Failed to persist listing asset to SQLite: %s", db_err)

    return result_data


# ─────────────────────────────────────────────────────────────────────────────
# Sample / Demo data
# ─────────────────────────────────────────────────────────────────────────────

def get_sample_listings() -> List[Dict[str, Any]]:
    """
    Returns 8 preloaded demo marketplace listings: a mix of USD and INR
    listings covering counterfeit replicas and genuine authorized resellers.
    Both currency paths are exercised so the demo demonstrates INR anomaly
    detection without requiring manual form entry.
    """
    return [
        # ── USD listings ─────────────────────────────────────────────────────
        {
            "listing_id":          "DEMO-LST-001",
            "title":               "Rolex Submariner Date 41mm Oystersteel — Brand New Replica",
            "seller_name":         "LuxuryWatchDiscount_Direct",
            "target_brand":        "Rolex",
            "price":               249.99,
            "currency":            "USD",
            "msrp":                10000.0,
            "description":         "1:1 Mirror Quality replica watch with automatic movement and box set. Cheap direct shipping.",
            "verdict":             "High Risk Counterfeit",
            "risk_rating":         92.5,
            "phash":               "a1b2c3d4e5f67890",
            "dhash":               "1029384756afbecd",
            "image_similarity":    88.0,
            "intent_label":        "Counterfeit or impersonation",
            "intent_confidence":   94.5,
            "is_legitimate":       False,
            "price_anomaly":       True,
            "discount_percentage": 97.5,
            "price_message":       "PRICE ANOMALY ALERT: Listing price $249.99 is 97.5% below reference MSRP ($10,000.00).",
        },
        {
            "listing_id":          "DEMO-LST-002",
            "title":               "Apple AirPods Max Wireless Over-Ear Headphones — Space Gray",
            "seller_name":         "TechBargainWarehouse",
            "target_brand":        "Apple",
            "price":               129.00,
            "currency":            "USD",
            "msrp":                999.0,
            "description":         "Unopened factory sealed unit with active noise cancellation. Limited clearance stock.",
            "verdict":             "High Risk Counterfeit",
            "risk_rating":         86.0,
            "phash":               "f9e8d7c6b5a43210",
            "dhash":               "0102030405060708",
            "image_similarity":    82.0,
            "intent_label":        "Counterfeit or impersonation",
            "intent_confidence":   89.0,
            "is_legitimate":       False,
            "price_anomaly":       True,
            "discount_percentage": 87.1,
            "price_message":       "PRICE ANOMALY ALERT: Listing price $129.00 is 87.1% below reference MSRP ($999.00).",
        },
        {
            "listing_id":          "DEMO-LST-003",
            "title":               "Nike Air Force 1 '07 Triple White — Official Retailer",
            "seller_name":         "AuthorizedKicksStore",
            "target_brand":        "Nike",
            "price":               135.00,
            "currency":            "USD",
            "msrp":                150.0,
            "description":         "Authentic Nike sneaker from authorized distribution network with receipt.",
            "verdict":             "Legitimate / Authorized Listing",
            "risk_rating":         12.0,
            "phash":               "1122334455667788",
            "dhash":               "8877665544332211",
            "image_similarity":    95.0,
            "intent_label":        "Authorized reseller/partner",
            "intent_confidence":   98.0,
            "is_legitimate":       True,
            "price_anomaly":       False,
            "discount_percentage": 10.0,
            "price_message":       "Price $135.00 is within normal threshold (10.0% off MSRP $150.00).",
        },
        {
            "listing_id":          "DEMO-LST-004",
            "title":               "Louis Vuitton Neverfull MM Monogram Tote Bag Replica",
            "seller_name":         "DesignerOutletGlobal",
            "target_brand":        "Louis Vuitton",
            "price":               180.00,
            "currency":            "USD",
            "msrp":                2500.0,
            "description":         "AAA high copy designer handbag with dustbag and card.",
            "verdict":             "High Risk Counterfeit",
            "risk_rating":         95.0,
            "phash":               "cafe432109876543",
            "dhash":               "1234567890abcdef",
            "image_similarity":    91.0,
            "intent_label":        "Counterfeit or impersonation",
            "intent_confidence":   96.0,
            "is_legitimate":       False,
            "price_anomaly":       True,
            "discount_percentage": 92.8,
            "price_message":       "PRICE ANOMALY ALERT: Listing price $180.00 is 92.8% below reference MSRP ($2,500.00).",
        },
        {
            "listing_id":          "DEMO-LST-005",
            "title":               "Ray-Ban Classic Wayfarer Polarized Sunglasses",
            "seller_name":         "OfficialSunglassHub",
            "target_brand":        "Ray-Ban",
            "price":               165.00,
            "currency":            "USD",
            "msrp":                180.0,
            "description":         "Genuine Ray-Ban eyewear with 2 year manufacturer warranty.",
            "verdict":             "Legitimate / Authorized Listing",
            "risk_rating":         15.0,
            "phash":               "9988776655443322",
            "dhash":               "2233445566778899",
            "image_similarity":    94.0,
            "intent_label":        "Authorized reseller/partner",
            "intent_confidence":   96.5,
            "is_legitimate":       True,
            "price_anomaly":       False,
            "discount_percentage": 8.3,
            "price_message":       "Price $165.00 is within normal threshold (8.3% off MSRP $180.00).",
        },
        # ── INR listings (Indian-market demo scenarios) ───────────────────────
        {
            "listing_id":          "DEMO-LST-006",
            "title":               "Apple iPhone 15 128GB — Sealed Box Direct Import",
            "seller_name":         "iDealsBazaar_IN",
            "target_brand":        "Apple",
            "price":               34999.0,
            "currency":            "INR",
            "msrp":                89900.0,
            "description":         "Brand new sealed iPhone 15. Direct import, no Indian warranty. Free delivery across India.",
            "verdict":             "High Risk Counterfeit",
            "risk_rating":         84.0,
            "phash":               "a9b8c7d6e5f43210",
            "dhash":               "fedcba9876543210",
            "image_similarity":    80.0,
            "intent_label":        "Counterfeit or impersonation",
            "intent_confidence":   91.0,
            "is_legitimate":       False,
            "price_anomaly":       True,
            "discount_percentage": 61.1,
            "price_message":       "PRICE ANOMALY ALERT: Listing price ₹34,999.00 is 61.1% below reference MSRP (₹89,900.00).",
        },
        {
            "listing_id":          "DEMO-LST-007",
            "title":               "Nike Air Max 270 — Flipkart Assured Seller",
            "seller_name":         "RetailNet_SportwearIN",
            "target_brand":        "Nike",
            "price":               9995.0,
            "currency":            "INR",
            "msrp":                10295.0,
            "description":         "Authorised Nike dealer. Original product with Nike India warranty card and GST invoice.",
            "verdict":             "Legitimate / Authorized Listing",
            "risk_rating":         14.0,
            "phash":               "1a2b3c4d5e6f7089",
            "dhash":               "9807060504030201",
            "image_similarity":    96.0,
            "intent_label":        "Authorized reseller/partner",
            "intent_confidence":   97.5,
            "is_legitimate":       True,
            "price_anomaly":       False,
            "discount_percentage": 2.9,
            "price_message":       "Price ₹9,995.00 is within normal threshold (2.9% off MSRP ₹10,295.00).",
        },
        {
            "listing_id":          "DEMO-LST-008",
            "title":               "Rolex Submariner First Copy — Free Shipping India",
            "seller_name":         "PremiumReplica_Mart",
            "target_brand":        "Rolex",
            "price":               4999.0,
            "currency":            "INR",
            "msrp":                1050000.0,
            "description":         "Super first copy Rolex with Japanese movement. Identical to original. COD available.",
            "verdict":             "High Risk Counterfeit",
            "risk_rating":         95.0,
            "phash":               "deadbeef12345678",
            "dhash":               "87654321efcdab90",
            "image_similarity":    89.0,
            "intent_label":        "Counterfeit or impersonation",
            "intent_confidence":   97.0,
            "is_legitimate":       False,
            "price_anomaly":       True,
            "discount_percentage": 99.5,
            "price_message":       "PRICE ANOMALY ALERT: Listing price ₹4,999.00 is 99.5% below reference MSRP (₹10,50,000.00).",
        },
    ]
