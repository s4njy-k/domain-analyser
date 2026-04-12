from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import google.generativeai as genai

from pipeline.utils import env, extract_json_payload, gemini_limiter

GEMINI_API_KEY = env("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(
        "gemini-1.5-flash",
        generation_config={"response_mime_type": "application/json"},
    )
else:
    model = None

SYSTEM_PROMPT = """
You are a cybercrime analyst for the Indian Cyber Crime Coordination Centre (I4C),
Ministry of Home Affairs, Government of India. Analyse website evidence and return
ONLY valid JSON matching the schema below. Do not add any text outside the JSON.

JSON SCHEMA:
{
  "threat_category": string,  // One of: PHISHING | FINANCIAL_FRAUD | ILLEGAL_BETTING |
                                //   MALWARE_DISTRIBUTION | JOB_SCAM | INVESTMENT_FRAUD |
                                //   SEXTORTION | FAKE_GOVERNMENT | COUNTERFEIT_GOODS |
                                //   ROMANCE_SCAM | CRYPTO_FRAUD | BENIGN | UNKNOWN
  "brand_impersonated": string | null,  // Specific brand name or null
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INACTIVE",
  "fraud_mechanism": string,  // How victims are defrauded (1-2 sentences)
  "victim_profile": string,   // Who is targeted (language, geography, demographic)
  "illegal_activity_description": string,  // Official language description (3-5 sentences)
  "applicable_laws": [
    {
      "statute": string,  // e.g. 'IT Act 2000, Section 66D'
      "offence": string,  // Short description of offence
      "evidence": string, // What in the page content satisfies this provision
      "confidence": "CLEAR" | "PROBABLE" | "POSSIBLE"
    }
  ],
  "recommended_action": string,  // e.g. 'Immediate blocking under IT Act S.69A'
  "priority_score": integer  // 0-100
}
"""

INDIA_LAW_REFERENCE = """
APPLICABLE INDIAN LEGAL PROVISIONS (use ONLY these; do not invent section numbers):

IT Act 2000 (Information Technology Act, as amended 2008):
- S.43(c): Introducing computer contaminant/virus. Trigger: malware download prompts.
- S.66: Dishonest/fraudulent computer acts (general cyber offence). Up to 3 yr + 5L fine.
- S.66C: Identity theft - fraudulent use of electronic signature/password/unique ID.
- S.66D: Cheating by personation using computer resource. Trigger: impersonating bank/govt.
- S.67: Publishing obscene material electronically.
- S.67A: Publishing sexually explicit material electronically.
- S.67B: Child sexual abuse material (CSAM) in electronic form.
- S.69A: Government direction to block public access to information.

Bharatiya Nyaya Sanhita 2023 (BNS) [In force from 01 July 2024]:
- S.111: Organised crime - continuing unlawful activity by organised crime syndicate.
- S.112: Petty organised crime (includes cyber-crimes by groups). 1-7 years.
- S.316(5): Cheating by personation (digital). 3 years for identity theft.
- S.318: Cheating - dishonestly inducing delivery of property by deception. Up to 7 years.
- S.338/340: Forgery / use of forged documents. Covers fake govt order images.

Other:
- Public Gambling Act 1867: Online betting platforms accepting bets from India.
- FEMA 1999 S.3/4: Foreign exchange violations. Offshore betting platforms violate FEMA.
- PMLA 2002: Money laundering via cyber fraud proceeds (scheduled offences).
- POCSO Act 2012: Sexual offences against minors (read with IT Act S.67B).
"""


def _default_response() -> dict[str, Any]:
    return {
        "threat_category": "UNKNOWN",
        "brand_impersonated": None,
        "confidence": "LOW",
        "severity": "LOW",
        "fraud_mechanism": "Insufficient evidence was available to assign a definitive malicious workflow.",
        "victim_profile": "Unknown.",
        "illegal_activity_description": "The collected evidence was insufficient to classify the website with confidence.",
        "applicable_laws": [],
        "recommended_action": "Retain evidence and review manually.",
        "priority_score": 0,
    }


def _law_entry(statute: str, offence: str, evidence: str, confidence: str = "PROBABLE") -> dict[str, str]:
    return {
        "statute": statute,
        "offence": offence,
        "evidence": evidence,
        "confidence": confidence,
    }


def _has_phrase(text: str, phrases: tuple[str, ...]) -> bool:
    return any(phrase in text for phrase in phrases)


def _has_word(text: str, words: tuple[str, ...]) -> bool:
    return any(re.search(rf"\b{re.escape(word)}\b", text) for word in words)


def _heuristic_analysis(domain_data: dict) -> dict[str, Any]:
    result = _default_response()
    payment_methods = domain_data.get("payment_methods") or []
    payment_labels = ", ".join(sorted({entry.get("method", "") for entry in payment_methods if entry.get("method")}))
    text = " ".join(
        filter(
            None,
            [
                domain_data.get("title"),
                domain_data.get("meta_desc"),
                domain_data.get("page_text"),
                domain_data.get("final_url"),
                domain_data.get("domain"),
                payment_labels,
            ],
        )
    ).lower()
    vt_hits = int(domain_data.get("vt_malicious", 0) or 0) + int(domain_data.get("vt_suspicious", 0) or 0)
    gsb_threats = domain_data.get("gsb_threats") or []
    urlhaus_listed = bool(domain_data.get("urlhaus_listed"))
    phishtank_verified = bool(domain_data.get("phishtank_verified"))
    otx_pulses = int(domain_data.get("otx_pulse_count", 0) or 0)
    abuse_score = int(domain_data.get("abuseipdb_score", 0) or 0)
    http_status = domain_data.get("http_status")
    urlscan_verdict = str(domain_data.get("urlscan_verdict") or "").lower()

    if http_status is None:
        result["severity"] = "INACTIVE"
        result["recommended_action"] = "Preserve existing evidence and corroborate with historical sources."

    category = "BENIGN"
    laws: list[dict[str, str]] = []
    brand = None

    threat_intel_confirmed = any(
        [
            phishtank_verified,
            urlhaus_listed,
            vt_hits >= 2,
            "SOCIAL_ENGINEERING" in gsb_threats,
            "MALWARE" in gsb_threats,
            otx_pulses >= 2,
            abuse_score >= 75,
            urlscan_verdict == "malicious",
        ]
    )
    brand_terms = ("sbi", "hdfc", "icici", "paytm", "aadhaar", "epfo", "upi", "bank", "gov", "government")
    credential_terms = ("otp", "login", "signin", "sign in", "verify", "verification", "password", "account", "kyc")
    phishing_page = (
        phishtank_verified
        or "SOCIAL_ENGINEERING" in gsb_threats
        or (_has_word(text, brand_terms) and _has_word(text, credential_terms))
    )
    malware_page = (
        urlhaus_listed
        or "MALWARE" in gsb_threats
        or (
            threat_intel_confirmed
            and (
                _has_phrase(text, ("download apk", "install apk", "update your browser", "download for android"))
                or (_has_word(text, ("apk", "exe")) and _has_word(text, ("download", "install", "update")))
            )
        )
    )
    betting_page = threat_intel_confirmed and (
        _has_word(text, ("casino", "sportsbook", "rummy", "teen", "patti"))
        or _has_phrase(text, ("ipl betting", "bet now", "live odds", "sports betting", "teen patti"))
    )
    investment_page = threat_intel_confirmed and (
        _has_phrase(text, ("guaranteed return", "double your money", "daily profit", "trading signal", "crypto signal"))
        or (
            _has_word(text, ("invest", "investment", "crypto", "trading", "profit"))
            and _has_word(text, ("guaranteed", "assured", "daily", "return", "returns"))
        )
    )

    if phishing_page:
        category = "PHISHING"
        brand = next((brand_name for brand_name in ("SBI", "HDFC", "ICICI", "Paytm", "Aadhaar", "EPFO") if brand_name.lower() in text), None)
        laws = [
            _law_entry("IT Act 2000, Section 66D", "Cheating by personation using computer resource", "The page appears to solicit credentials or impersonate a legitimate service.", "CLEAR"),
            _law_entry("BNS 2023, Section 318", "Cheating by deception", "The site content suggests inducement of victims to disclose information or transfer value.", "PROBABLE"),
        ]
        result["fraud_mechanism"] = "The website appears to impersonate a legitimate brand or service to obtain credentials, OTPs, or payment details."
        result["victim_profile"] = "Indian consumers and account holders targeted through digital impersonation."
        result["illegal_activity_description"] = "The collected evidence is consistent with a phishing workflow that impersonates a legitimate service and induces victims to submit sensitive information. Such conduct supports digital personation and deception-based cheating provisions under Indian cybercrime law."
        result["recommended_action"] = "Immediate blocking review under IT Act S.69A and referral for takedown/IOC dissemination."
    elif malware_page:
        category = "MALWARE_DISTRIBUTION"
        laws = [
            _law_entry("IT Act 2000, Section 43(c)", "Introducing computer contaminant/virus", "The site appears to distribute or prompt execution of potentially malicious software.", "CLEAR"),
            _law_entry("IT Act 2000, Section 66", "Dishonest/fraudulent computer acts", "Malware distribution through deceptive delivery indicates dishonest use of computer resources.", "PROBABLE"),
        ]
        result["fraud_mechanism"] = "The website appears to distribute malicious software or deceptive application packages to compromise victim devices."
        result["victim_profile"] = "General internet users, often mobile users persuaded to install software."
        result["illegal_activity_description"] = "The available evidence indicates malicious software delivery or staged malware download behaviour. This is consistent with computer contaminant distribution and other dishonest cyber acts under the IT Act."
        result["recommended_action"] = "Immediate IOC dissemination and blocking escalation under IT Act S.69A."
    elif betting_page:
        category = "ILLEGAL_BETTING"
        laws = [
            _law_entry("Public Gambling Act 1867", "Operating an online betting platform", "The site content advertises wagering or games of chance to Indian users.", "CLEAR"),
            _law_entry("FEMA 1999, Sections 3/4", "Foreign exchange violations linked to offshore betting flows", "The platform appears to facilitate offshore betting transactions for Indian users.", "PROBABLE"),
        ]
        result["fraud_mechanism"] = "The platform appears to solicit gambling activity or offshore betting participation."
        result["victim_profile"] = "Indian bettors targeted through online gambling promotions."
        result["illegal_activity_description"] = "The evidence suggests the website promotes or enables online betting activity directed at Indian users. Depending on payment flows and hosting model, associated foreign exchange and laundering offences may also arise."
        if payment_labels:
            result["recommended_action"] = f"Escalate for gambling-law review, preserve payment-rail evidence ({payment_labels}), and consider blocking."
        else:
            result["recommended_action"] = "Escalate for gambling-law review and blocking consideration."
    elif investment_page:
        category = "INVESTMENT_FRAUD" if "crypto" not in text else "CRYPTO_FRAUD"
        laws = [
            _law_entry("BNS 2023, Section 318", "Cheating by deception", "The site appears to induce victims to transfer funds on false assurances of returns.", "PROBABLE"),
            _law_entry("PMLA 2002", "Money laundering exposure from cyber-fraud proceeds", "If proceeds are routed through layered channels, laundering risk arises.", "POSSIBLE"),
        ]
        result["fraud_mechanism"] = "Victims appear to be induced to transfer funds using false investment or crypto return claims."
        result["victim_profile"] = "Retail investors and social-media referred victims."
        result["illegal_activity_description"] = "The website content indicates an investment-style fraud mechanism promising returns or trading gains without credible regulatory or operational indicators. This is consistent with deception-based inducement to transfer property."
        result["recommended_action"] = "Preserve evidence, trace payment rails, and consider blocking after legal review."
    else:
        if threat_intel_confirmed or vt_hits or otx_pulses or abuse_score >= 50:
            category = "UNKNOWN"
            result["severity"] = "MEDIUM"
            result["recommended_action"] = "Preserve evidence and prioritise manual analyst review."
            result["illegal_activity_description"] = "Threat intelligence sources indicate elevated risk, but the captured content does not conclusively establish a specific criminal workflow."
        else:
            category = "BENIGN"
            result["severity"] = "LOW" if http_status else "INACTIVE"
            result["fraud_mechanism"] = "No active fraud mechanism was evident in the captured content."
            result["victim_profile"] = "No specific victim group identified."
            result["illegal_activity_description"] = "The collected evidence does not presently indicate a clear malicious workflow. The domain should be retained only for reference unless new indicators emerge."
            result["recommended_action"] = "No immediate enforcement action recommended; retain for watchlist comparison."

    if category != "BENIGN" and result["severity"] != "INACTIVE":
        if vt_hits >= 5 or phishtank_verified or urlhaus_listed or "SOCIAL_ENGINEERING" in gsb_threats:
            result["severity"] = "CRITICAL"
            result["confidence"] = "HIGH"
        elif vt_hits >= 2 or otx_pulses >= 2 or abuse_score >= 75:
            result["severity"] = "HIGH"
            result["confidence"] = "HIGH"
        else:
            result["severity"] = "MEDIUM"
            result["confidence"] = "MEDIUM"
    elif category == "BENIGN":
        result["confidence"] = "MEDIUM"

    result["threat_category"] = category
    result["brand_impersonated"] = brand
    result["applicable_laws"] = laws
    priority = min(
        100,
        (
            (25 if phishtank_verified else 0)
            + (25 if urlhaus_listed else 0)
            + min(vt_hits * 10, 30)
            + min(otx_pulses * 5, 10)
            + (10 if "SOCIAL_ENGINEERING" in gsb_threats or "MALWARE" in gsb_threats else 0)
        ),
    )
    if category == "BENIGN":
        priority = 5 if http_status else 0
    result["priority_score"] = priority
    return result


def _normalise_ai_response(payload: dict[str, Any]) -> dict[str, Any]:
    result = _default_response()
    result.update(payload or {})
    result["applicable_laws"] = payload.get("applicable_laws", []) if isinstance(payload, dict) else []
    if not isinstance(result["priority_score"], int):
        try:
            result["priority_score"] = int(result["priority_score"])
        except Exception:
            result["priority_score"] = 0
    return result


async def analyse_domain(domain_data: dict) -> dict:
    # Assemble analysis prompt from collected evidence
    user_prompt = f"""
DOMAIN: {domain_data['domain']}
CAPTURE DATE/TIME (IST): {domain_data.get('capture_ts')}
HTTP STATUS: {domain_data.get('http_status', 'Unknown')}
FINAL URL (after redirects): {domain_data.get('final_url', '')}
PAGE TITLE: {domain_data.get('title', '')}
META DESCRIPTION: {domain_data.get('meta_desc', '')}
CAPTURE QUALITY SCORE: {domain_data.get('capture_quality_score', 0)}

PAGE TEXT (first 3000 chars):
{(domain_data.get('page_text') or '')[:3000]}

DETECTED PAYMENT METHODS:
{json.dumps(domain_data.get('payment_methods', []), ensure_ascii=False)}

THREAT INTELLIGENCE VERDICTS:
- VirusTotal: {domain_data.get('vt_malicious', 0)}/{domain_data.get('vt_total', 0)} engines flagged
- URLScan verdict: {domain_data.get('urlscan_verdict', 'N/A')}
- URLhaus listed: {domain_data.get('urlhaus_listed', 'N/A')}
- Google Safe Browsing: {domain_data.get('gsb_threats', 'CLEAN')}
- OTX pulses: {domain_data.get('otx_pulse_count', 0)} threat pulses
- PhishTank verified: {domain_data.get('phishtank_verified', False)}

REGISTRATION DATA:
- Registrar: {domain_data.get('registrar', 'Unknown')}
- Registration date: {domain_data.get('registered', 'Unknown')}
- Country: {domain_data.get('country', 'Unknown')}

{INDIA_LAW_REFERENCE}

Analyse this website and return JSON matching the schema in your system instructions.
"""

    if model is None:
        return _heuristic_analysis(domain_data)

    await gemini_limiter.acquire()
    try:
        response = await asyncio.to_thread(model.generate_content, SYSTEM_PROMPT + "\n\n" + user_prompt)
        payload = json.loads(extract_json_payload(getattr(response, "text", "")))
        return _normalise_ai_response(payload)
    except Exception:
        return _heuristic_analysis(domain_data)
