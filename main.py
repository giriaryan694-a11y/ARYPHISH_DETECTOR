import os
import asyncio
import httpx
import whois
import re
import json
from datetime import datetime
from urllib.parse import urlparse
from duckduckgo_search import DDGS

import google.generativeai as genai
import openai
from flask import Flask, request, jsonify, render_template_string

import pyfiglet
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

AI_SYSTEM_PROMPT = """
You are an expert cybersecurity analyst specializing in phishing and domain spoofing detection.
Your task is to analyze a given URL, its HTML source code, WHOIS registration data, 
DuckDuckGo search intelligence, and a combo-squatting brand match report.

Use ALL provided context to determine if the site is:
- 'Safe'   : Legitimate, well-established domain with no deception signals
- 'Phishing': Impersonating a brand, using suspicious domain tricks, or showing deceptive behavior
- 'Suspicious': Ambiguous signals — possible risk but not confirmed phishing

Detection focus areas:
1. Combo-squatting: e.g., 'google-security.com', 'paypal-login.net' — legitimate brand + action word
2. Typosquatting: e.g., 'gooogle.com', 'rnyspace.com' — character substitution/omission
3. Homograph attacks: Unicode lookalikes
4. Domain age: Very new domains (<6 months) are higher risk
5. Search intelligence: Does the web know this domain as legitimate?
6. Brand mismatch: Does page content claim to be a brand the domain doesn't belong to?

Format your response EXACTLY as:
Verdict: [Safe/Phishing/Suspicious]
Reasoning: [Your one-paragraph explanation covering domain analysis, brand signals, WHOIS age, and search context]
"""

# ==============================================================================
# KNOWN BRANDS FOR COMBO-SQUATTING DETECTION
# ==============================================================================

KNOWN_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp", "meta",
    "microsoft", "windows", "outlook", "office", "azure", "xbox",
    "apple", "icloud", "itunes", "iphone",
    "amazon", "aws", "prime",
    "paypal", "stripe", "visa", "mastercard", "amex",
    "netflix", "spotify", "twitch",
    "twitter", "x", "linkedin", "tiktok", "snapchat", "reddit",
    "github", "gitlab", "bitbucket",
    "dropbox", "onedrive", "gdrive",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
    "yahoo", "bing", "duckduckgo",
    "steam", "epicgames", "roblox",
    "cloudflare", "godaddy", "namecheap",
    "telegram", "discord", "zoom", "teams",
    "ebay", "aliexpress", "alibaba", "shopify",
    "coinbase", "binance", "kraken", "blockchain",
]

SQUATTING_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "security", "secure", "verify", "verification",
    "account", "accounts", "billing", "payment", "pay",
    "update", "upgrade", "confirm", "confirmation",
    "support", "help", "service", "services",
    "official", "portal", "access", "auth", "authenticate",
    "recover", "recovery", "reset", "password",
    "alert", "notice", "notification", "warning",
    "prize", "winner", "reward", "free", "gift",
]

# ==============================================================================
# API KEY LOADING
# ==============================================================================

def load_api_keys(filepath="keys.txt"):
    keys = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    key, value = line.split('=', 1)
                    keys[key.strip()] = value.strip()
                except ValueError:
                    print(f"Warning: Skipping malformed line: {line}")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: {filepath} not found.")
        return None
    except Exception as e:
        print(f"{Fore.RED}Error reading {filepath}: {e}")
        return None

    if 'GEMINI_API' not in keys and 'CHATGPT_API' not in keys and 'OPENROUTER_API' not in keys:
        print(f"{Fore.RED}Error: At least one API key required in keys.txt")
        print(f"{Fore.YELLOW}  Options: GEMINI_API, CHATGPT_API, or OPENROUTER_API (free tier available)")
        return None
    return keys


api_keys = load_api_keys()
if api_keys:
    try:
        if 'GEMINI_API' in api_keys:
            genai.configure(api_key=api_keys.get('GEMINI_API'))
            gemini_model = genai.GenerativeModel('gemini-2.5-flash-preview-09-2025')
        else:
            gemini_model = None
    except Exception as e:
        print(f"{Fore.RED}Gemini config error: {e}")
        gemini_model = None

    try:
        if 'CHATGPT_API' in api_keys:
            openai_client = openai.AsyncOpenAI(api_key=api_keys.get('CHATGPT_API'))
        else:
            openai_client = None
    except Exception as e:
        print(f"{Fore.RED}OpenAI config error: {e}")
        openai_client = None

    # OpenRouter — free tier, OpenAI-compatible endpoint
    # Free models: meta-llama/llama-3.3-70b-instruct:free
    #              google/gemma-3-27b-it:free
    #              deepseek/deepseek-r1:free
    #              mistralai/mistral-7b-instruct:free
    try:
        if 'OPENROUTER_API' in api_keys:
            openrouter_client = openai.AsyncOpenAI(
                api_key=api_keys.get('OPENROUTER_API'),
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "http://localhost:5000",
                    "X-Title": "ARYPHISH_DETECTOR",
                }
            )
            openrouter_model = api_keys.get('OPENROUTER_MODEL', 'meta-llama/llama-3.3-70b-instruct:free')
        else:
            openrouter_client = None
            openrouter_model = None
    except Exception as e:
        print(f"{Fore.RED}OpenRouter config error: {e}")
        openrouter_client = None
        openrouter_model = None
else:
    gemini_model = None
    openai_client = None
    openrouter_client = None
    openrouter_model = None

# ==============================================================================
# MODULE 1 — COMBO-SQUATTING & TYPOSQUATTING DETECTOR
# ==============================================================================

def analyze_domain_squatting(domain: str) -> dict:
    """
    Analyzes a domain for combo-squatting and typosquatting signals.
    Returns a structured report dict.
    """
    domain = domain.lower().strip()
    # Strip TLD for analysis
    domain_base = re.sub(r'\.(com|net|org|io|co|info|biz|xyz|club|online|site|live|app|dev|me|us|uk|ca|de|fr|ru|cn|tk|ml|ga|cf|gq)(\.[a-z]{2})?$', '', domain)

    report = {
        "domain": domain,
        "domain_base": domain_base,
        "matched_brands": [],
        "matched_keywords": [],
        "combo_squatting_score": 0,
        "flags": [],
        "is_suspicious": False,
    }

    # Check brand matches
    for brand in KNOWN_BRANDS:
        if brand in domain_base:
            report["matched_brands"].append(brand)

    # Check squatting keywords
    for kw in SQUATTING_KEYWORDS:
        if kw in domain_base:
            report["matched_keywords"].append(kw)

    # Scoring
    score = 0
    if report["matched_brands"]:
        score += 40
        report["flags"].append(f"Brand name(s) found in domain: {report['matched_brands']}")
    if report["matched_keywords"]:
        score += 30
        report["flags"].append(f"Suspicious keyword(s) found: {report['matched_keywords']}")

    # Hyphen check (google-security, paypal-login pattern)
    if '-' in domain_base:
        score += 15
        report["flags"].append("Hyphen separator detected (common in combo-squatting)")

    # Subdomain abuse (login.google.com.somesite.com)
    parts = domain.split('.')
    if len(parts) > 3:
        score += 10
        report["flags"].append(f"Deep subdomain structure ({len(parts)} levels) — possible subdomain abuse")

    # Numeric injection (g00gle, paypa1)
    if re.search(r'\d', domain_base):
        score += 10
        report["flags"].append("Numeric characters in domain base — possible typosquatting")

    # Unicode homograph detection
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        score += 25
        report["flags"].append("Non-ASCII characters detected — possible homograph/IDN attack")

    report["combo_squatting_score"] = min(score, 100)
    report["is_suspicious"] = score >= 30

    return report


# ==============================================================================
# MODULE 2 — WHOIS LOOKUP
# ==============================================================================

def get_whois_data(domain: str) -> dict:
    """
    Performs WHOIS lookup and extracts key registration signals.
    """
    result = {
        "domain": domain,
        "registrar": "Unknown",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "domain_age_days": None,
        "registrant_country": "Unknown",
        "is_new_domain": False,
        "error": None,
    }
    try:
        w = whois.whois(domain)

        result["registrar"] = str(w.registrar) if w.registrar else "Unknown"
        result["registrant_country"] = str(w.country) if hasattr(w, 'country') and w.country else "Unknown"

        # Handle list or single date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            age = (datetime.now() - creation).days
            result["domain_age_days"] = age
            result["is_new_domain"] = age < 180  # <6 months = high risk

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime):
            result["expiration_date"] = expiry.strftime("%Y-%m-%d")

    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {str(e)}"

    return result


# ==============================================================================
# MODULE 3 — DUCKDUCKGO SEARCH INTELLIGENCE
# ==============================================================================

def search_domain_intelligence(domain: str, brand_matches: list) -> dict:
    """
    Uses DuckDuckGo to gather web intelligence about the domain.
    Searches for:
    1. Is this domain known/legitimate?
    2. Are there phishing reports for it?
    3. Brand validation (if brand match found)
    """
    intel = {
        "domain_search_snippets": [],
        "phishing_report_snippets": [],
        "brand_official_domain": None,
        "brand_search_snippets": [],
        "search_error": None,
    }

    try:
        ddgs = DDGS()

        # Search 1: General domain reputation
        domain_results = ddgs.text(
            f'"{domain}" site reputation review',
            max_results=4
        )
        if domain_results:
            intel["domain_search_snippets"] = [
                {"title": r.get("title", ""), "snippet": r.get("body", ""), "url": r.get("href", "")}
                for r in domain_results
            ]

        # Search 2: Phishing/scam reports
        phish_results = ddgs.text(
            f'"{domain}" phishing scam fraud report',
            max_results=3
        )
        if phish_results:
            intel["phishing_report_snippets"] = [
                {"title": r.get("title", ""), "snippet": r.get("body", ""), "url": r.get("href", "")}
                for r in phish_results
            ]

        # Search 3: Brand official domain (for combo-squatting validation)
        if brand_matches:
            for brand in brand_matches[:2]:  # Check top 2 matched brands
                brand_results = ddgs.text(
                    f'{brand} official website domain',
                    max_results=2
                )
                if brand_results:
                    intel["brand_search_snippets"].extend([
                        {"brand": brand, "title": r.get("title", ""), "snippet": r.get("body", ""), "url": r.get("href", "")}
                        for r in brand_results
                    ])

    except Exception as e:
        intel["search_error"] = f"DuckDuckGo search failed: {str(e)}"

    return intel


# ==============================================================================
# MODULE 4 — WEBSITE CONTENT FETCHER
# ==============================================================================

async def fetch_website_content(url: str) -> str:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.text
    except httpx.HTTPStatusError as e:
        raise Exception(f"Failed to fetch content (Status: {e.response.status_code}).")
    except httpx.RequestError:
        raise Exception("Could not retrieve website content. Site may be offline or unreachable.")


# ==============================================================================
# MODULE 5 — AI ANALYSIS FUNCTIONS
# ==============================================================================

async def analyze_with_gemini(user_prompt: str, system_prompt: str) -> str:
    if not gemini_model:
        return "Error: Gemini model is not configured."
    try:
        full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
        response = await gemini_model.generate_content_async(full_prompt)
        return response.text
    except Exception as e:
        return f"Error during Gemini analysis: {e}"


async def analyze_with_openai(user_prompt: str, system_prompt: str) -> str:
    if not openai_client:
        return "Error: OpenAI client is not configured."
    try:
        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error during OpenAI analysis: {e}"


async def analyze_with_openrouter(user_prompt: str, system_prompt: str) -> str:
    """
    Free-tier LLM via OpenRouter (no credit card needed).
    Get your free key at: https://openrouter.ai/
    Default model: meta-llama/llama-3.3-70b-instruct:free

    Other free models you can set via OPENROUTER_MODEL= in keys.txt:
      google/gemma-3-27b-it:free
      deepseek/deepseek-r1:free
      mistralai/mistral-7b-instruct:free
      nousresearch/hermes-3-llama-3.1-405b:free
    """
    if not openrouter_client:
        return "Error: OpenRouter client is not configured. Add OPENROUTER_API=your_key to keys.txt"
    try:
        response = await openrouter_client.chat.completions.create(
            model=openrouter_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error during OpenRouter ({openrouter_model}) analysis: {e}"


# ==============================================================================
# CORE ORCHESTRATOR — Assembles all modules into one enriched prompt
# ==============================================================================

async def perform_analysis(url: str, ai_choice: str, system_prompt: str):
    """
    Orchestrates all detection modules and sends enriched context to LLMs.
    """
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace("www.", "").split(":")[0]  # strip port/www

    # --- Run synchronous modules (WHOIS, squatting, DDG search) in thread pool ---
    loop = asyncio.get_event_loop()

    squatting_report = await loop.run_in_executor(None, analyze_domain_squatting, domain)
    whois_report     = await loop.run_in_executor(None, get_whois_data, domain)
    search_intel     = await loop.run_in_executor(
        None, search_domain_intelligence, domain, squatting_report["matched_brands"]
    )

    # --- Fetch HTML source ---
    try:
        source_code = await fetch_website_content(url)
        truncated_source = source_code[:12000]
    except Exception as e:
        truncated_source = f"[Could not fetch HTML: {e}]"

    # --- Build enriched prompt for LLMs ---
    user_prompt = f"""
=== TARGET URL ===
{url}

=== PARSED DOMAIN ===
{domain}

=== COMBO-SQUATTING / TYPOSQUATTING ANALYSIS ===
Suspicious Score: {squatting_report['combo_squatting_score']}/100
Is Suspicious: {squatting_report['is_suspicious']}
Matched Known Brands: {squatting_report['matched_brands'] or 'None'}
Matched Suspicious Keywords: {squatting_report['matched_keywords'] or 'None'}
Flags:
{chr(10).join(['  - ' + f for f in squatting_report['flags']]) or '  None'}

=== WHOIS REGISTRATION DATA ===
Registrar: {whois_report['registrar']}
Registration Date: {whois_report['creation_date']}
Expiration Date: {whois_report['expiration_date']}
Domain Age: {f"{whois_report['domain_age_days']} days" if whois_report['domain_age_days'] is not None else 'Unknown'}
Is New Domain (<6 months): {whois_report['is_new_domain']}
Registrant Country: {whois_report['registrant_country']}
{f"WHOIS Error: {whois_report['error']}" if whois_report['error'] else ''}

=== DUCKDUCKGO SEARCH INTELLIGENCE ===
-- Domain Reputation Snippets --
{json.dumps(search_intel['domain_search_snippets'], indent=2) if search_intel['domain_search_snippets'] else 'No results found.'}

-- Phishing / Fraud Report Snippets --
{json.dumps(search_intel['phishing_report_snippets'], indent=2) if search_intel['phishing_report_snippets'] else 'No reports found.'}

-- Brand Validation Snippets --
{json.dumps(search_intel['brand_search_snippets'], indent=2) if search_intel['brand_search_snippets'] else 'No brand data found.'}

{f"Search Error: {search_intel['search_error']}" if search_intel['search_error'] else ''}

=== HTML SOURCE CODE (first 12,000 chars) ===
{truncated_source}
"""

    # --- Run LLM analyses in parallel ---
    # ai_choice values: gemini | chatgpt | openrouter | all | both (legacy)
    tasks = []
    task_keys = []

    if ai_choice in ['gemini', 'both', 'all']:
        tasks.append(analyze_with_gemini(user_prompt, system_prompt))
        task_keys.append('gemini')
    if ai_choice in ['chatgpt', 'both', 'all']:
        tasks.append(analyze_with_openai(user_prompt, system_prompt))
        task_keys.append('chatgpt')
    if ai_choice in ['openrouter', 'all']:
        tasks.append(analyze_with_openrouter(user_prompt, system_prompt))
        task_keys.append('openrouter')

    results = await asyncio.gather(*tasks, return_exceptions=True)

    response_data = {
        "squatting_report": squatting_report,
        "whois_report": whois_report,
        "openrouter_model": openrouter_model,
    }

    for key, result in zip(task_keys, results):
        response_data[key] = str(result) if isinstance(result, Exception) else result

    return response_data, 200


# ==============================================================================
# FLASK APP
# ==============================================================================

app = Flask(__name__)

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARYPHISH_DETECTOR</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --green: #00ff88;
            --red: #ff4455;
            --yellow: #ffd700;
            --cyan: #00d4ff;
            --bg: #0a0e14;
            --panel: #0f1520;
            --border: #1e2d40;
            --text: #c8d8e8;
            --dim: #4a6070;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Rajdhani', sans-serif;
            min-height: 100vh;
            padding: 2rem 1rem;
            position: relative;
            overflow-x: hidden;
        }

        /* Scanline overlay */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0,255,136,0.015) 2px,
                rgba(0,255,136,0.015) 4px
            );
            pointer-events: none;
            z-index: 999;
        }

        .container { max-width: 860px; margin: 0 auto; }

        /* Header */
        .header { text-align: center; margin-bottom: 2.5rem; }
        .header h1 {
            font-family: 'Share Tech Mono', monospace;
            font-size: clamp(1.6rem, 5vw, 2.8rem);
            color: var(--green);
            letter-spacing: 0.12em;
            text-shadow: 0 0 20px rgba(0,255,136,0.4), 0 0 40px rgba(0,255,136,0.15);
            animation: flicker 6s infinite;
        }
        .header .sub {
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            color: var(--dim);
            letter-spacing: 0.3em;
            margin-top: 0.4rem;
        }

        @keyframes flicker {
            0%,95%,100% { opacity: 1; }
            96% { opacity: 0.85; }
            97% { opacity: 1; }
            98% { opacity: 0.9; }
        }

        /* Panel */
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1.8rem;
            position: relative;
        }
        .panel::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--cyan), transparent);
        }

        /* Form */
        label {
            display: block;
            font-size: 0.72rem;
            letter-spacing: 0.2em;
            color: var(--dim);
            margin-bottom: 0.5rem;
        }
        input[type="url"], select {
            width: 100%;
            background: rgba(0,212,255,0.04);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.75rem 1rem;
            border-radius: 3px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input[type="url"]:focus, select:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 0 2px rgba(0,212,255,0.1);
        }
        select option { background: #0f1520; }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem; }
        @media(max-width:580px){ .form-row { grid-template-columns: 1fr; } }

        .btn {
            width: 100%;
            margin-top: 1.4rem;
            padding: 0.85rem;
            background: transparent;
            border: 1px solid var(--green);
            color: var(--green);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95rem;
            letter-spacing: 0.2em;
            cursor: pointer;
            border-radius: 3px;
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
        }
        .btn::after {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--green);
            opacity: 0;
            transition: opacity 0.2s;
        }
        .btn:hover::after { opacity: 0.08; }
        .btn:hover { box-shadow: 0 0 16px rgba(0,255,136,0.25); }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }

        /* Loader */
        .loader-wrap {
            display: none;
            flex-direction: column;
            align-items: center;
            padding: 2.5rem 0;
            gap: 1rem;
        }
        .loader-wrap.active { display: flex; }
        .loader-bar {
            width: 200px;
            height: 2px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
        }
        .loader-bar::after {
            content: '';
            display: block;
            height: 100%;
            width: 40%;
            background: var(--cyan);
            box-shadow: 0 0 8px var(--cyan);
            animation: scan 1.2s ease-in-out infinite;
        }
        @keyframes scan {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(350%); }
        }
        .loader-text {
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.75rem;
            color: var(--cyan);
            letter-spacing: 0.2em;
            animation: blink 1.2s step-end infinite;
        }
        @keyframes blink { 50% { opacity: 0; } }

        /* Error */
        .error-box {
            display: none;
            margin-top: 1.2rem;
            padding: 0.9rem 1rem;
            background: rgba(255,68,85,0.08);
            border: 1px solid rgba(255,68,85,0.4);
            border-radius: 3px;
            color: var(--red);
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.82rem;
        }
        .error-box.active { display: block; }

        /* Intelligence Cards */
        .intel-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1.4rem;
        }
        @media(max-width:580px){ .intel-grid { grid-template-columns: 1fr; } }

        .intel-card {
            background: rgba(0,212,255,0.03);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 1rem;
        }
        .intel-card h4 {
            font-size: 0.68rem;
            letter-spacing: 0.2em;
            color: var(--dim);
            margin-bottom: 0.7rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }
        .tag {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 2px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.72rem;
            margin: 0.15rem;
        }
        .tag-brand { background: rgba(255,215,0,0.1); color: var(--yellow); border: 1px solid rgba(255,215,0,0.3); }
        .tag-kw { background: rgba(255,68,85,0.1); color: var(--red); border: 1px solid rgba(255,68,85,0.3); }
        .tag-ok { background: rgba(0,255,136,0.08); color: var(--green); border: 1px solid rgba(0,255,136,0.3); }
        .score-bar-wrap { margin-top: 0.5rem; }
        .score-bar {
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            overflow: hidden;
            margin-top: 0.3rem;
        }
        .score-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.8s ease;
        }
        .mono { font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; }
        .dim { color: var(--dim); }
        .val { color: var(--text); }

        /* AI Results */
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-top: 1.4rem;
        }
        @media(max-width:580px){ .results-grid { grid-template-columns: 1fr; } }

        .result-card {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
        }
        .result-card .card-header {
            padding: 0.7rem 1rem;
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid var(--border);
            font-size: 0.7rem;
            letter-spacing: 0.2em;
            color: var(--dim);
            font-family: 'Share Tech Mono', monospace;
        }
        .result-card .card-body { padding: 1rem; }

        .verdict-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 2px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.95rem;
            font-weight: bold;
            letter-spacing: 0.1em;
            margin-bottom: 0.75rem;
        }
        .verdict-safe { background: rgba(0,255,136,0.1); color: var(--green); border: 1px solid rgba(0,255,136,0.4); }
        .verdict-phishing { background: rgba(255,68,85,0.1); color: var(--red); border: 1px solid rgba(255,68,85,0.4); }
        .verdict-suspicious { background: rgba(255,215,0,0.1); color: var(--yellow); border: 1px solid rgba(255,215,0,0.4); }
        .verdict-unknown { background: rgba(74,96,112,0.2); color: var(--dim); border: 1px solid var(--border); }

        .reasoning {
            font-size: 0.88rem;
            line-height: 1.6;
            color: var(--text);
        }

        /* Footer */
        footer {
            text-align: center;
            margin-top: 2.5rem;
            font-family: 'Share Tech Mono', monospace;
            font-size: 0.7rem;
            color: var(--dim);
            letter-spacing: 0.15em;
        }
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>ARYPHISH_DETECTOR</h1>
        <p class="sub">// AI-POWERED PHISHING & DOMAIN SPOOFING DETECTION //</p>
    </div>

    <div class="panel">
        <div style="margin-bottom:1rem">
            <label>TARGET URL</label>
            <input type="url" id="urlInput" placeholder="https://example.com" />
        </div>
        <div class="form-row">
            <div>
                <label>AI ENGINE</label>
                <select id="aiChoice">
                    <option value="all">All Three AIs</option>
                    <option value="both" selected>Gemini + ChatGPT</option>
                    <option value="gemini">Gemini Only</option>
                    <option value="chatgpt">ChatGPT Only</option>
                    <option value="openrouter">OpenRouter (Free 🆓)</option>
                </select>
            </div>
            <div style="display:flex;align-items:flex-end;">
                <button class="btn" id="checkButton" onclick="runAnalysis()">[ ANALYZE TARGET ]</button>
            </div>
        </div>
    </div>

    <div class="loader-wrap" id="loader">
        <div class="loader-bar"></div>
        <div class="loader-text" id="loaderText">SCANNING...</div>
    </div>

    <div class="error-box" id="errorBox"></div>

    <!-- Intelligence Summary -->
    <div id="intelSection" style="display:none">
        <div class="intel-grid">

            <div class="intel-card">
                <h4>// SQUATTING ANALYSIS</h4>
                <div class="score-bar-wrap">
                    <div class="mono"><span class="dim">RISK SCORE: </span><span id="sqScore" class="val">—</span></div>
                    <div class="score-bar"><div class="score-fill" id="sqBar" style="width:0%"></div></div>
                </div>
                <div style="margin-top:0.75rem" id="sqFlags"></div>
                <div style="margin-top:0.5rem" id="sqTags"></div>
            </div>

            <div class="intel-card">
                <h4>// WHOIS REGISTRATION</h4>
                <div id="whoisData" class="mono" style="line-height:1.8;font-size:0.78rem"></div>
            </div>

        </div>
    </div>

    <!-- AI Results -->
    <div id="resultsSection" style="display:none">
        <div class="results-grid">
            <div class="result-card" id="geminiCard" style="display:none">
                <div class="card-header">// GEMINI ANALYSIS</div>
                <div class="card-body" id="geminiBody"></div>
            </div>
            <div class="result-card" id="chatgptCard" style="display:none">
                <div class="card-header">// CHATGPT ANALYSIS</div>
                <div class="card-body" id="chatgptBody"></div>
            </div>
            <div class="result-card" id="openrouterCard" style="display:none">
                <div class="card-header" id="openrouterHeader">// OPENROUTER — FREE TIER</div>
                <div class="card-body" id="openrouterBody"></div>
            </div>
        </div>
    </div>

    <footer>Made By Aryan Giri &nbsp;|&nbsp; ARYPHISH_DETECTOR v2.0</footer>
</div>

<script>
const loaderMessages = [
    "FETCHING HTML SOURCE...",
    "RUNNING WHOIS LOOKUP...",
    "QUERYING DUCKDUCKGO INTEL...",
    "ANALYZING DOMAIN PATTERNS...",
    "CONSULTING AI ENGINES...",
    "CROSS-REFERENCING BRANDS...",
    "COMPILING THREAT REPORT..."
];
let loaderInterval;

function startLoader() {
    let i = 0;
    document.getElementById('loaderText').textContent = loaderMessages[0];
    loaderInterval = setInterval(() => {
        i = (i + 1) % loaderMessages.length;
        document.getElementById('loaderText').textContent = loaderMessages[i];
    }, 1800);
}
function stopLoader() { clearInterval(loaderInterval); }

async function runAnalysis() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) { showError("Please enter a URL."); return; }

    const btn = document.getElementById('checkButton');
    btn.disabled = true;
    document.getElementById('loader').classList.add('active');
    document.getElementById('errorBox').classList.remove('active');
    document.getElementById('intelSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('geminiCard').style.display = 'none';
    document.getElementById('chatgptCard').style.display = 'none';
    document.getElementById('openrouterCard').style.display = 'none';
    startLoader();

    try {
        const res = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, ai_choice: document.getElementById('aiChoice').value })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Server error');

        renderIntel(data);
        renderResults(data);

    } catch(e) {
        showError(e.message);
    } finally {
        stopLoader();
        document.getElementById('loader').classList.remove('active');
        btn.disabled = false;
    }
}

function showError(msg) {
    const el = document.getElementById('errorBox');
    el.textContent = '// ERROR: ' + msg;
    el.classList.add('active');
}

function renderIntel(data) {
    const sq = data.squatting_report;
    const wh = data.whois_report;

    // Squatting score bar color
    const score = sq.combo_squatting_score;
    const color = score >= 60 ? 'var(--red)' : score >= 30 ? 'var(--yellow)' : 'var(--green)';
    document.getElementById('sqScore').textContent = score + '/100';
    document.getElementById('sqScore').style.color = color;
    const bar = document.getElementById('sqBar');
    bar.style.width = score + '%';
    bar.style.background = color;
    bar.style.boxShadow = `0 0 6px ${color}`;

    // Flags
    const flagsEl = document.getElementById('sqFlags');
    if (sq.flags && sq.flags.length) {
        flagsEl.innerHTML = sq.flags.map(f =>
            `<div class="mono dim" style="font-size:0.72rem;margin-bottom:0.25rem">⚑ ${f}</div>`
        ).join('');
    } else {
        flagsEl.innerHTML = '<div class="mono" style="color:var(--green);font-size:0.72rem">✓ No suspicious patterns detected</div>';
    }

    // Brand/keyword tags
    const tagsEl = document.getElementById('sqTags');
    let tags = '';
    (sq.matched_brands || []).forEach(b => { tags += `<span class="tag tag-brand">${b}</span>`; });
    (sq.matched_keywords || []).forEach(k => { tags += `<span class="tag tag-kw">${k}</span>`; });
    tagsEl.innerHTML = tags;

    // WHOIS
    const ageDays = wh.domain_age_days;
    const ageStr = ageDays !== null ? ageDays + ' days' + (wh.is_new_domain ? ' ⚠' : '') : 'Unknown';
    const ageColor = wh.is_new_domain ? 'var(--yellow)' : 'var(--text)';
    document.getElementById('whoisData').innerHTML = `
        <div><span class="dim">REGISTRAR: </span><span class="val">${wh.registrar}</span></div>
        <div><span class="dim">CREATED:   </span><span class="val">${wh.creation_date}</span></div>
        <div><span class="dim">EXPIRES:   </span><span class="val">${wh.expiration_date}</span></div>
        <div><span class="dim">AGE:       </span><span style="color:${ageColor}">${ageStr}</span></div>
        <div><span class="dim">COUNTRY:   </span><span class="val">${wh.registrant_country}</span></div>
        ${wh.error ? `<div style="color:var(--dim);margin-top:0.3rem;font-size:0.7rem">${wh.error}</div>` : ''}
    `;

    document.getElementById('intelSection').style.display = 'block';
}

function renderResults(data) {
    if (data.gemini) {
        document.getElementById('geminiBody').innerHTML = formatAIResult(data.gemini);
        document.getElementById('geminiCard').style.display = 'block';
    }
    if (data.chatgpt) {
        document.getElementById('chatgptBody').innerHTML = formatAIResult(data.chatgpt);
        document.getElementById('chatgptCard').style.display = 'block';
    }
    if (data.openrouter) {
        const modelLabel = data.openrouter_model ? data.openrouter_model.split('/').pop().toUpperCase() : 'FREE MODEL';
        document.getElementById('openrouterHeader').textContent = '// OPENROUTER — ' + modelLabel;
        document.getElementById('openrouterBody').innerHTML = formatAIResult(data.openrouter);
        document.getElementById('openrouterCard').style.display = 'block';
    }
    document.getElementById('resultsSection').style.display = 'block';
}

function formatAIResult(text) {
    if (text.startsWith('Error:')) {
        return `<div style="color:var(--red);font-family:'Share Tech Mono',monospace;font-size:0.8rem">${text}</div>`;
    }
    const verdictMatch = text.match(/Verdict:\s*(Safe|Phishing|Suspicious)/i);
    const reasoningMatch = text.match(/Reasoning:\s*([\s\S]*)/i);

    const verdict = verdictMatch ? verdictMatch[1] : 'Unknown';
    const reasoning = reasoningMatch ? reasoningMatch[1].trim() : text;

    const cls = {
        'safe': 'verdict-safe',
        'phishing': 'verdict-phishing',
        'suspicious': 'verdict-suspicious',
    }[verdict.toLowerCase()] || 'verdict-unknown';

    return `
        <div class="verdict-badge ${cls}">${verdict.toUpperCase()}</div>
        <div class="reasoning">${reasoning}</div>
    `;
}

// Enter key trigger
document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && document.activeElement === document.getElementById('urlInput')) runAnalysis();
});
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    if not api_keys or (not gemini_model and not openai_client and not openrouter_client):
        return jsonify({"error": "Server not configured with a valid API key."}), 500
    try:
        data = request.get_json()
        url = data.get('url')
        ai_choice = data.get('ai_choice', 'both')
        if not url:
            return jsonify({"error": "URL is required."}), 400
        response_data, status_code = asyncio.run(perform_analysis(url, ai_choice, AI_SYSTEM_PROMPT))
        return jsonify(response_data), status_code
    except Exception as e:
        print(f"{Fore.RED}Server error: {e}")
        return jsonify({"error": "Internal server error."}), 500


# ==============================================================================
# CLI BANNER + STARTUP
# ==============================================================================

def print_cli_banner():
    print(Style.BRIGHT)
    banner_text = pyfiglet.figlet_format("ARYPHISH_DETECTOR", font="slant")
    print(f"{Fore.CYAN}{banner_text}")
    print(f"{Fore.YELLOW}Made By Aryan Giri — v2.0 (Web Search Edition)\n{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[ MODULES LOADED ]{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}✓ Combo-Squatting & Typosquatting Detector")
    print(f"  {Fore.GREEN}✓ WHOIS Domain Registration Lookup")
    print(f"  {Fore.GREEN}✓ DuckDuckGo Search Intelligence (free, no key)")
    print(f"  {Fore.GREEN}✓ Brand Validation Cross-Reference")
    print(f"  {Fore.GREEN}✓ Async Dual-AI Analysis (Gemini + ChatGPT)")
    print()
    if not api_keys or (not gemini_model and not openai_client and not openrouter_client):
        print(f"{Fore.RED}Error: At least one API key required in keys.txt")
        return False
    if gemini_model:
        print(f"  {Fore.GREEN}✓ Gemini Model Configured")
    else:
        print(f"  {Fore.YELLOW}✗ Gemini not configured")
    if openai_client:
        print(f"  {Fore.GREEN}✓ OpenAI Client Configured")
    else:
        print(f"  {Fore.YELLOW}✗ OpenAI not configured")
    if openrouter_client:
        print(f"  {Fore.GREEN}✓ OpenRouter Configured → {Fore.CYAN}{openrouter_model}")
    else:
        print(f"  {Fore.YELLOW}✗ OpenRouter not configured (free tier — add OPENROUTER_API to keys.txt)")
    print()
    print(f"{Fore.GREEN}Flask server starting → {Fore.WHITE}http://127.0.0.1:5000")
    print("---")
    return True


if __name__ == '__main__':
    if print_cli_banner():
        app.run(debug=True, host='127.0.0.1', port=5000)
