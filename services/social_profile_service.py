import os
import json
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from services.imagehash_service import compute_image_hashes, compare_two_images
from services.intent_classifier_service import classify_intent
from database import insert_scanned_asset, log_case_event

logger = logging.getLogger("social_profile_service")

ALLOWLIST_PATH = Path("./config/social_allowlist.json").resolve()


def load_social_allowlist() -> List[str]:
    """
    Loads verified official social media handles from config/social_allowlist.json.
    """
    if ALLOWLIST_PATH.exists():
        try:
            with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [h.strip().lower() for h in data if isinstance(h, str)]
        except Exception as e:
            logger.warning(f"Failed to load social allowlist: {str(e)}")
    return ["@rolex", "@apple", "@nike", "@louisvuitton", "@rayban", "@official_rolex", "@alexrivers_tech", "@samanthavance_live", "@dr_aris_thorne", "@marcuschen_crypto"]


def toggle_social_allowlist_handle(handle: str, add: bool = True) -> Dict[str, Any]:
    """
    Adds or removes a verified official handle from config/social_allowlist.json.
    """
    clean_handle = handle.strip().lower()
    if not clean_handle.startswith("@"):
        clean_handle = f"@{clean_handle}"

    current = load_social_allowlist()
    if add:
        if clean_handle not in current:
            current.append(clean_handle)
    else:
        current = [h for h in current if h != clean_handle]

    try:
        ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ALLOWLIST_PATH, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
        return {
            "status": "success",
            "handle": clean_handle,
            "is_verified": add,
            "message": f"Handle '{clean_handle}' {'added to' if add else 'removed from'} verified social allowlist."
        }
    except Exception as e:
        logger.error(f"Failed to update social allowlist: {str(e)}")
        return {"status": "error", "message": str(e)}


def calculate_handle_similarity(handle_a: str, handle_b: str) -> float:
    """
    Measures string similarity between two handles (e.g. @alexrivers_tech vs @alexrivers_tech_giveaways).
    Returns 0.0 to 100.0 similarity score.
    """
    a = handle_a.lower().replace("@", "").strip()
    b = handle_b.lower().replace("@", "").strip()
    if not a or not b:
        return 0.0
    if a == b:
        return 100.0
    if a in b or b in a:
        return 85.0
    
    # Common prefix match
    min_len = min(len(a), len(b))
    match_chars = sum(1 for i in range(min_len) if a[i] == b[i])
    return round((match_chars / max(len(a), len(b))) * 100.0, 1)


def analyze_social_profile(
    platform: str,
    handle: str,
    display_name: str,
    bio_text: Optional[str] = None,
    follower_count: Optional[int] = None,
    account_age_days: Optional[int] = None,
    target_brand: Optional[str] = None,
    protected_entity: Optional[str] = None,
    entity_type: str = "brand",
    official_handle: Optional[str] = None,
    profile_image_path: Optional[str] = None,
    reference_logo_path: Optional[str] = None,
    profile_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Core Social Media Impersonation Analyzer.
    Supports both Corporate Brands and Individual Public Figures/Creators.
    
    1. Checks verified handle allowlist (config/social_allowlist.json).
    2. Computes profile picture pHash/dHash against reference logo/photo.
    3. Runs Zero-Shot Intent Classification on bio & display name.
    4. Evaluates account age, follower growth, & handle spoofing heuristics.
    5. Persists evidence into SQLite `assets` table (asset_type = 'social_profile').
    """
    clean_platform = platform.strip() if platform else "Instagram"
    clean_handle = handle.strip()
    if not clean_handle.startswith("@"):
        clean_handle = f"@{clean_handle}"

    clean_name = display_name.strip() if display_name else clean_handle
    clean_bio = bio_text.strip() if bio_text else ""
    unique_id = profile_id or f"SOC-{uuid.uuid4().hex[:8].upper()}"

    entity_name = protected_entity or target_brand or "Target Entity"
    clean_entity_type = "individual" if entity_type and entity_type.lower() in ["individual", "public figure", "creator"] else "brand"

    # Step 1: Verified Handle Allowlist Check
    allowlist = load_social_allowlist()
    is_verified_allowlist = clean_handle.lower() in allowlist or clean_handle.lower().replace("@", "") in [h.replace("@", "") for h in allowlist]

    if is_verified_allowlist:
        result_data = {
            "profile_id": unique_id,
            "platform": clean_platform,
            "handle": clean_handle,
            "display_name": clean_name,
            "target_brand": entity_name,
            "protected_entity": entity_name,
            "entity_type": clean_entity_type,
            "verdict": "Verified Official Account",
            "risk_rating": 0.0,
            "phash": "0000000000000000",
            "dhash": "0000000000000000",
            "logo_similarity": 100.0,
            "intent_label": "Official/verified brand presence" if clean_entity_type == "brand" else "Verified Official Profile",
            "intent_confidence": 100.0,
            "is_legitimate": True,
            "is_verified_official": True,
            "override_reason": f"Handle '{clean_handle}' matches verified allowlist for {entity_name}.",
            "account_age_days": account_age_days or 365,
            "follower_count": follower_count or 100000
        }
        # Persist to SQLite
        try:
            insert_scanned_asset(
                asset_type="social_profile",
                asset_id=f"{clean_platform}:{clean_handle}",
                ip_address=clean_handle,
                phash="0000000000000000",
                dhash="0000000000000000",
                target_brand=entity_name,
                confidence=0.0,
                intent_label=result_data["intent_label"],
                intent_confidence=100.0,
                metadata=result_data
            )
        except Exception:
            pass
        return result_data

    # Step 2: Profile Picture Image Hash Matching
    phash_str = "0000000000000000"
    dhash_str = "0000000000000000"
    logo_sim = 75.0 if (entity_name.lower() in clean_handle.lower() or entity_name.lower() in clean_name.lower()) else 50.0

    if profile_image_path and os.path.exists(profile_image_path):
        try:
            hashes = compute_image_hashes(profile_image_path)
            phash_str = hashes.get("phash_str", phash_str)
            dhash_str = hashes.get("dhash_str", dhash_str)

            if reference_logo_path and os.path.exists(reference_logo_path):
                sim_res = compare_two_images(reference_logo_path, profile_image_path)
                logo_sim = sim_res.get("combined_similarity_percentage", 50.0)
            else:
                logo_sim = 85.0
        except Exception as e:
            logger.warning(f"Profile picture hashing error: {str(e)}")

    # Step 3: Intent Classification on Bio & Display Name
    corpus = f"{clean_name}. {clean_bio}"
    intent_res = classify_intent(text=corpus, domain=clean_handle, entity_type=clean_entity_type)

    giveaway_words = ["giveaway", "free", "vip", "bot", "dm for", "helpline", "support", "claim", "airdrop", "solana", "crypto", "whitelisted", "bonus", "winner"]
    is_suspicious_bio = any(w in corpus.lower() or w in clean_handle.lower() for w in giveaway_words)

    # Step 4: Heuristic Scoring Calculation & Creator Giveaway Pattern Rules
    logo_score = (logo_sim / 100.0) * 30.0

    # Handle / Name similarity to official handle or protected entity
    handle_sim_score = 0.0
    if official_handle:
        h_sim = calculate_handle_similarity(clean_handle, official_handle)
        if h_sim >= 80.0 and clean_handle.lower() != official_handle.lower():
            handle_sim_score = 25.0  # Near-identical handle to official handle

    if clean_entity_type == "individual":
        # Individual Creator Specific Heuristics
        if is_suspicious_bio:
            intent_score = 35.0
            intent_res["top_label"] = "Scam/giveaway impersonation"
            intent_res["is_legitimate"] = False
        elif intent_res.get("top_label") in ["Impersonation account", "Scam/giveaway impersonation"]:
            intent_score = 35.0
        elif intent_res.get("top_label") == "Parody":
            intent_score = 10.0
        else:
            intent_score = 5.0  # Non-deceptive fan account

        # New account + giveaway/crypto pattern = heavy penalty
        age_penalty = 15.0 if (account_age_days is not None and account_age_days < 60) else 0.0
        follower_penalty = 15.0 if (follower_count is not None and follower_count < 1000 and is_suspicious_bio) else 0.0

        raw_risk = logo_score + intent_score + handle_sim_score + age_penalty + follower_penalty
    else:
        # Corporate Brand Heuristics
        if is_suspicious_bio:
            intent_score = 35.0
            intent_res["top_label"] = "Counterfeit or impersonation"
            intent_res["is_legitimate"] = False
        elif intent_res.get("top_label") in ["Authorized reseller/partner", "News/media coverage"]:
            intent_score = 0.0
        elif intent_res.get("top_label") in ["Fan page/community content", "Parody/commentary"]:
            intent_score = 10.0
        else:
            intent_score = 35.0

        age_penalty = 15.0 if (account_age_days is not None and account_age_days < 90) else 0.0
        follower_penalty = 15.0 if (follower_count is not None and follower_count < 500) else 0.0

        raw_risk = logo_score + intent_score + age_penalty + follower_penalty

    risk_rating = max(0.0, min(100.0, round(raw_risk, 1)))

    if risk_rating >= 70.0:
        verdict = "High Risk Creator Impersonator / Scam" if clean_entity_type == "individual" else "High Risk Fake Account"
    elif risk_rating >= 40.0:
        verdict = "Suspicious Profile"
    else:
        verdict = "Fan / Non-Deceptive Account" if clean_entity_type == "individual" else "Fan / Community Account"

    result_data = {
        "profile_id": unique_id,
        "platform": clean_platform,
        "handle": clean_handle,
        "display_name": clean_name,
        "target_brand": entity_name,
        "protected_entity": entity_name,
        "entity_type": clean_entity_type,
        "official_handle": official_handle,
        "verdict": verdict,
        "risk_rating": risk_rating,
        "phash": phash_str,
        "dhash": dhash_str,
        "logo_similarity": logo_sim,
        "intent_label": intent_res["top_label"],
        "intent_confidence": intent_res["confidence"],
        "is_legitimate": intent_res["is_legitimate"],
        "is_verified_official": False,
        "account_age_days": account_age_days,
        "follower_count": follower_count,
        "age_penalty": age_penalty > 0,
        "follower_penalty": follower_penalty > 0,
        "handle_spoof_penalty": handle_sim_score > 0
    }

    # Step 5: SQLite Asset Store Persistence
    try:
        insert_scanned_asset(
            asset_type="social_profile",
            asset_id=f"{clean_platform}:{clean_handle}",
            ip_address=clean_handle,
            phash=phash_str,
            dhash=dhash_str,
            target_brand=entity_name,
            confidence=risk_rating,
            intent_label=intent_res["top_label"],
            intent_confidence=intent_res["confidence"],
            metadata=result_data
        )
        log_case_event(
            "default",
            "social_profile_scanned",
            f"Social profile '{clean_handle}' on {clean_platform} ({clean_entity_type}: {entity_name}) analyzed: Verdict '{verdict}' ({risk_rating}%)"
        )
    except Exception as db_err:
        logger.warning(f"Failed to persist social profile asset to SQLite: {str(db_err)}")

    return result_data


def get_sample_social_profiles() -> List[Dict[str, Any]]:
    """
    Returns preloaded sample/demo social media profiles:
    Mix of Corporate Brand impersonations and Public Figure / Creator giveaway scams.
    Fictional demo entities are clearly noted.
    """
    return [
        # Corporate Brand Examples
        {
            "profile_id": "DEMO-SOC-001",
            "platform": "Instagram",
            "handle": "@rolex_official_support_vip",
            "display_name": "Rolex Official VIP Support & Giveaways",
            "target_brand": "Rolex",
            "protected_entity": "Rolex",
            "entity_type": "brand",
            "follower_count": 142,
            "account_age_days": 12,
            "verdict": "High Risk Fake Account",
            "risk_rating": 94.5,
            "phash": "a1b2c3d4e5f67890",
            "dhash": "1029384756afbecd",
            "logo_similarity": 92.0,
            "intent_label": "Counterfeit or impersonation",
            "intent_confidence": 96.5,
            "is_legitimate": False,
            "is_verified_official": False,
            "age_penalty": True,
            "follower_penalty": True,
            "handle_spoof_penalty": False
        },
        {
            "profile_id": "DEMO-SOC-002",
            "platform": "X (Twitter)",
            "handle": "@AppleSupport_Helpline",
            "display_name": "Apple Care Customer Service Bot",
            "target_brand": "Apple",
            "protected_entity": "Apple",
            "entity_type": "brand",
            "follower_count": 310,
            "account_age_days": 24,
            "verdict": "High Risk Fake Account",
            "risk_rating": 89.0,
            "phash": "f9e8d7c6b5a43210",
            "dhash": "0102030405060708",
            "logo_similarity": 85.0,
            "intent_label": "Phishing/credential harvesting",
            "intent_confidence": 92.0,
            "is_legitimate": False,
            "is_verified_official": False,
            "age_penalty": True,
            "follower_penalty": True,
            "handle_spoof_penalty": False
        },
        # Public Figure / Creator Impersonation Examples (Demo / Fictional Creators)
        {
            "profile_id": "DEMO-SOC-006",
            "platform": "X (Twitter)",
            "handle": "@alexrivers_tech_giveaway",
            "display_name": "Alex Rivers — Tech Giveaway & Airdrop [Official]",
            "target_brand": "Alex Rivers (Tech Creator - Demo)",
            "protected_entity": "Alex Rivers (Tech Creator - Demo)",
            "entity_type": "individual",
            "official_handle": "@alexrivers_tech",
            "follower_count": 1250,
            "account_age_days": 8,
            "verdict": "High Risk Creator Impersonator / Scam",
            "risk_rating": 96.5,
            "phash": "b8a7c6d5e4f32109",
            "dhash": "0192837465abc123",
            "logo_similarity": 88.0,
            "intent_label": "Scam/giveaway impersonation",
            "intent_confidence": 98.0,
            "is_legitimate": False,
            "is_verified_official": False,
            "age_penalty": True,
            "follower_penalty": True,
            "handle_spoof_penalty": True
        },
        {
            "profile_id": "DEMO-SOC-007",
            "platform": "Instagram",
            "handle": "@marcuschen_crypto_vip",
            "display_name": "Marcus Chen Crypto Mentorship & Signal Club",
            "target_brand": "Marcus Chen (Crypto Educator - Demo)",
            "protected_entity": "Marcus Chen (Crypto Educator - Demo)",
            "entity_type": "individual",
            "official_handle": "@marcuschen_crypto",
            "follower_count": 480,
            "account_age_days": 15,
            "verdict": "High Risk Creator Impersonator / Scam",
            "risk_rating": 92.0,
            "phash": "1234567890abcdef",
            "dhash": "fedcba9876543210",
            "logo_similarity": 86.0,
            "intent_label": "Scam/giveaway impersonation",
            "intent_confidence": 95.0,
            "is_legitimate": False,
            "is_verified_official": False,
            "age_penalty": True,
            "follower_penalty": True,
            "handle_spoof_penalty": True
        },
        {
            "profile_id": "DEMO-SOC-008",
            "platform": "YouTube",
            "handle": "@samanthavance_clips",
            "display_name": "Samantha Vance Daily Stream Highlights & Edits",
            "target_brand": "Samantha Vance (Gaming Streamer - Demo)",
            "protected_entity": "Samantha Vance (Gaming Streamer - Demo)",
            "entity_type": "individual",
            "official_handle": "@samanthavance_live",
            "follower_count": 85000,
            "account_age_days": 420,
            "verdict": "Fan / Non-Deceptive Account",
            "risk_rating": 15.0,
            "phash": "9988776655443322",
            "dhash": "2233445566778899",
            "logo_similarity": 60.0,
            "intent_label": "Fan account (non-deceptive)",
            "intent_confidence": 94.0,
            "is_legitimate": True,
            "is_verified_official": False,
            "age_penalty": False,
            "follower_penalty": False,
            "handle_spoof_penalty": False
        },
        {
            "profile_id": "DEMO-SOC-003",
            "platform": "Instagram",
            "handle": "@nike",
            "display_name": "Nike",
            "target_brand": "Nike",
            "protected_entity": "Nike",
            "entity_type": "brand",
            "follower_count": 305000000,
            "account_age_days": 4800,
            "verdict": "Verified Official Account",
            "risk_rating": 0.0,
            "phash": "1122334455667788",
            "dhash": "8877665544332211",
            "logo_similarity": 100.0,
            "intent_label": "Official/verified brand presence",
            "intent_confidence": 100.0,
            "is_legitimate": True,
            "is_verified_official": True,
            "age_penalty": False,
            "follower_penalty": False,
            "handle_spoof_penalty": False
        }
    ]
