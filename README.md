<div align="center">

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██████╗  █████╗ ████████╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██████╔╝███████║   ██║   ███████║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔═══╝ ██╔══██║   ██║   ██╔══██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║     ██║  ██║   ██║   ██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
```

**Advanced URL Obfuscation Tool for Cybersecurity Research**

[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)](https://giriaryan694-a11y.github.io/PhantomPath/)
[![Client-Side](https://img.shields.io/badge/client--side-100%25-blue?style=flat-square)](#)
[![Techniques](https://img.shields.io/badge/techniques-9-purple?style=flat-square)](#-features)
[![Companion](https://img.shields.io/badge/companion-ARYPHISH__DETECTOR-teal?style=flat-square)](https://github.com/giriaryan694-a11y/ARYPHISH_DETECTOR)
[![License](https://img.shields.io/badge/license-MIT-orange?style=flat-square)](#)
[![Research](https://img.shields.io/badge/use-research%20only-red?style=flat-square)](#%EF%B8%8F-ethical-disclaimer)

*Developed by **Aryan Giri***

[🌐 Live Demo](https://giriaryan694-a11y.github.io/PhantomPath/) · [🛡️ Detection Tool](https://github.com/giriaryan694-a11y/ARYPHISH_DETECTOR) · [📖 How It Works](#-how-it-works) · [🧪 Local Testing](#-local-testing-guide) · [⚠️ Disclaimer](#%EF%B8%8F-ethical-disclaimer)

</div>

---

## 📄 Overview

**PhantomPath** is a client-side, browser-based utility that demonstrates the full spectrum of URL obfuscation techniques employed by real-world attackers in phishing campaigns, malware delivery, and social engineering attacks.

Understanding how a malicious destination can be structurally disguised is foundational to building robust defenses — from training security analysts to evaluate suspicious links, to developing smarter detection rules in firewalls and email gateways.

Every transformation PhantomPath generates is **functionally valid** in modern browsers, yet visually deceptive to an untrained eye. All processing happens **locally in your browser** — no data ever leaves your machine.

---

## 🌐 Live Tool

> Try PhantomPath directly — no install, no server, no tracking.

**[https://giriaryan694-a11y.github.io/PhantomPath/](https://giriaryan694-a11y.github.io/PhantomPath/)**

---

## ✨ Features

PhantomPath implements **9 distinct obfuscation techniques**, each targeting a different layer of human perception or browser parsing behaviour.

### 🎭 Credential Padding
Exploits the `@` symbol in URL syntax to position a trusted decoy domain visually before the real destination. Browsers interpret everything before `@` as credentials — not a hostname.

```
https://google.com@192.168.1.1
         ↑ what victim reads    ↑ where browser actually goes
```

### 🔢 IPv4 → Hexadecimal
Converts dotted-decimal IPv4 into its 32-bit hex equivalent. Browsers silently resolve hex-encoded IPs, bypassing filters that scan for decimal IP patterns.

```
142.250.190.46  →  http://0x8EFABE2E
```

### 🔢 IPv4 → Dword (32-bit Integer)
Transforms an IP address into a single unsigned 32-bit integer. Natively supported by browsers, unrecognisable to casual inspection.

```
142.250.190.46  →  http://2398854702
```

### 🔢 IPv4 → Octal
Encodes each octet in octal (base-8) notation. Ancient but still browser-resolved.

```
142.250.190.46  →  http://0216.0372.0276.0056
```

### 🔀 Mixed Encoding
Combines hex, decimal, and octal across the four octets to defeat most pattern-based scanners.

```
142.250.190.46  →  http://0x8E.250.0276.46
```

### 🔡 Full URL Encoding
Percent-encodes every character into `%HH` ASCII hex. Turns any URL into percent signs and hex digits that bypass naive keyword matching.

```
google.com  →  https://%67%6F%6F%67%6C%65%2E%63%6F%6D
```

### 🔠 Character Substitution (Visual Trick)
Replaces characters with same-alphabet visual lookalikes — all pure ASCII, typeable on any keyboard, yet indistinguishable from the real domain in common fonts.

PhantomPath generates **every possible individual variant** — one substitution per result:

```
google.com  →  g0ogle.com    (first o → 0)
               go0gle.com    (second o → 0)
               googIe.com    (l → I)
               google.c0m    (o in TLD → 0)
               g009le.com    (g → 9)
               googl3.com    (e → 3)  ... and more
```

**Complete substitution map (27 pairs):**

| Category | Substitutions |
|---|---|
| Letter → Number | `l→I`, `l→1`, `i→1`, `o→0`, `e→3`, `a→4`, `s→5`, `b→6`, `t→7`, `z→2`, `g→9` |
| Number → Letter | `0→o` |
| Digraph (2→1 char) | `rn→m`, `nn→m`, `cl→d`, `vv→w`, `ii→n`, `li→h`, `ri→n`, `lI→H` |
| Reverse Digraph (1→2 chars) | `m→rn`, `m→nn`, `d→cl`, `w→vv` |
| Case swap | `s→S`, `o→O`, `I→l` |

### 🌐 Combo Squatting
The attacker registers a domain containing the brand name combined with a trust-triggering keyword. Victim reads a familiar word and assumes legitimacy — but the entire domain is attacker-controlled.

```
Real:    google.com

Fakes:   google-security.com       google-login.com
         google-verify.com         secure-google.com
         googlesupport.com         google.com.secure.com
         google.net                google.io
         ... 150+ variants generated
```

**5 pattern types:**

| Pattern | Example |
|---|---|
| `brand-keyword.tld` | `paypal-security.com` |
| `keyword-brand.tld` | `secure-paypal.com` |
| `brandkeyword.tld` | `paypallogin.com` |
| Level squatting | `paypal.com.verify.com` |
| TLD variation | `paypal.net`, `paypal.io`, `paypal.xyz` |

Most-abused keywords in real campaigns: `support`, `security`, `login`, `verify`, `account`, `update`, `payment`, `recover`.

### 🔤 IDN Homograph Attack
Replaces Latin characters with visually identical Unicode (Cyrillic) lookalikes, then converts to punycode `xn--` — the actual DNS-resolvable address.

```
Target spoof:    google.com
Unicode fake:    gооglе.com          ← what victim copies & sees
Real DNS form:   xn--gle-7cdaaa.com  ← what you register & host
```

> **Spoofable characters:** `a → а` `c → с` `e → е` `o → о` `p → р` `x → х` `y → у`

---

## 🖥️ Interface

- **9 method badges** — click to switch techniques; only relevant fields appear
- **Protocol toggle** — choose HTTP or HTTPS for every technique
- **Multi-variant output** — Char Substitution and Combo Squatting show every variant as scrollable, clickable rows
- **Research popup** — auto-displays local testing guide on first use; "Do not show again" stored in cookie
- **One-click copy** — copies the URL or last-clicked variant instantly
- **Dark / Light theme** — toggle with persistent cookie preference
- **100% client-side** — zero server calls, zero telemetry

---

## 🔬 How It Works

| Technique | Layer Exploited |
|---|---|
| Credential Padding | Browser URL parser — `user@host` syntax |
| Hex / Dword / Octal | Legacy numeral base support in IP resolution (RFC 3986) |
| Mixed Encoding | Per-octet mixed numeral system tolerance |
| URL Encoding | `%HH` transparently decoded before DNS lookup |
| Char Substitution | Human visual perception — same-alphabet lookalikes |
| Combo Squatting | Human pattern recognition — brand anchoring |
| IDN Homograph | Unicode → punycode conversion (IDNA 2008 / RFC 5891) |

---

## 🧪 Local Testing Guide

> All three domain-based techniques can be fully demonstrated **without purchasing a domain** by mapping the generated domain to your local machine.

### 🔠 Char Substitution & 🌐 Combo Squatting

These generate standard ASCII domains (e.g. `googIe.com`, `google-security.com`). Add them to your hosts file and serve a page on localhost.

**Linux / macOS**
```bash
sudo nano /etc/hosts
# Add:
127.0.0.1    googIe.com
127.0.0.1    google-security.com
# Save with Ctrl+X, then start a local server:
python3 -m http.server 80
```

**Windows** *(open Notepad as Administrator)*
```
C:\Windows\System32\drivers\etc\hosts
# Add:
127.0.0.1    googIe.com
127.0.0.1    google-security.com
# Flush DNS:
ipconfig /flushdns
```

**Check if a combo-squatted domain is already registered:**
```bash
# Linux/macOS:
whois google-security.com

# Windows:
nslookup google-security.com
# NXDOMAIN = available to register
```

---

### 🔤 IDN Homograph

The generated `xn--` punycode domain must be mapped — browsers resolve the Unicode display version to its punycode form automatically.

**Linux / macOS**
```bash
sudo nano /etc/hosts
# Add (use your actual generated xn-- domain):
127.0.0.1    xn--gle-7cdaaa.com
# Serve:
python3 -m http.server 80
```

**Windows** *(Notepad as Administrator)*
```
C:\Windows\System32\drivers\etc\hosts
127.0.0.1    xn--gle-7cdaaa.com
# Flush:
ipconfig /flushdns
```

**Local Network (Pi-hole / dnsmasq)** — resolves for all LAN devices:
```
address=/xn--gle-7cdaaa.com/192.168.1.100
```

**Real-world case:** In 2017, researcher Xudong Zheng registered `xn--80ak6aa92e.com` which displayed as `apple.com` in Chrome and Firefox. Both browsers were patched — modern browsers now show punycode if all/mixed Cyrillic is detected.

---

## 🧪 Educational Use Cases

### 🛡️ Security Awareness Training
Show non-technical users how a URL reading "google.com" silently redirects to an attacker's server. Ideal for corporate phishing simulation and awareness workshops.

### 🔎 SOC Analyst Skill Building
Train analysts to recognise obfuscated IOCs in proxy logs, email headers, and SIEM alerts — hex IPs, dword addresses, `xn--` domains, and combo-squatted URLs appear regularly in real C2 infrastructure.

### 🧱 WAF & Filter Evasion Research
Test whether your WAF, email gateway, or DNS filter catches alternate IP representations, character-substituted domains, and combo-squatted variants before an attacker finds the gap.

### 🔴 Red Team & Phishing Simulation
Generate realistic phishing infrastructure candidates for authorised red team engagements and simulation platforms.

### 📚 Academic / CTF
A live, reproducible reference covering techniques in OWASP, CEH, OSCP, and academic cybersecurity curricula.

---

## 🛡️ Mitigation & Detection — ARYPHISH_DETECTOR

> PhantomPath shows you how attacks are crafted. **ARYPHISH_DETECTOR** shows you how to catch them.

**[🔗 github.com/giriaryan694-a11y/ARYPHISH_DETECTOR](https://github.com/giriaryan694-a11y/ARYPHISH_DETECTOR)**

ARYPHISH_DETECTOR is a **multi-engine AI phishing detection tool** — also built by Aryan Giri — that analyzes URLs for domain spoofing, combo-squatting, typosquatting, and phishing signals. It combines static domain analysis, live WHOIS lookups, DuckDuckGo search intelligence, and parallel AI verdict generation — all through a sleek terminal-styled web UI.

Unlike static blocklist tools, ARYPHISH_DETECTOR fetches and analyzes the live page in real time, giving AI models full context: HTML source, domain registration data, and web search intelligence — all in one enriched prompt.

### How it detects
- **Combo-squatted & typosquatted domains** — catches `google-security.com`, `paypa1.com` style fakes
- **IDN homograph lookalikes** — detects `xn--` punycode domains spoofing real brands
- **Obfuscated URLs** — hex IPs, dword addresses, percent-encoded destinations
- **Deceptive login forms** — credential harvesting page structure analysis
- **Urgency/threatening language** — social engineering signal detection
- **WHOIS anomalies** — newly registered domains, privacy-masked registrants
- **Search intelligence** — DuckDuckGo cross-reference to verify domain legitimacy

### The red team / blue team loop

```
PhantomPath  (offensive)            ARYPHISH_DETECTOR  (defensive)
────────────────────────────────    ─────────────────────────────────────────
Generate:  google-security.com  →   Verdict: PHISHING
           xn--gle-7cdaaa.com       Reason:  IDN homograph, newly registered,
           googIe.com                        fake login form detected
           %67%6F%6F%67%6C%65.com   Source:  Gemini + ChatGPT parallel verdict
```

Use both tools together for a complete **offensive + defensive research loop** — generate the full attack surface with PhantomPath, then validate your detection coverage with ARYPHISH_DETECTOR.

### Tech stack
`Python` · `Flask` · `httpx` · `Google Gemini API` · `OpenAI ChatGPT API` · `WHOIS` · `DuckDuckGo Search` · `Tailwind CSS`

---

## 🗂️ Project Structure

```
PhantomPath/
├── index.html        # Entire tool — single self-contained file
└── README.md         # This document
```

No build step. No dependencies. No frameworks.

---

## 🔒 Privacy & Security

- **Zero network requests** — all logic runs in-browser JavaScript
- **No analytics, no tracking** — cookies only for UI preferences (theme, popup state)
- **No input data stored or transmitted**
- Safe on air-gapped or restricted lab networks

---

## ⚠️ Ethical Disclaimer

> **For Educational and Security Research Purposes Only.**

PhantomPath was created to help students, researchers, and security professionals understand URL obfuscation techniques used in phishing, malware, and social engineering attacks.

**The creator does not support or encourage use of this tool for phishing, deception, unauthorised access, or any illegal activity.**

### 🌍 International Laws

Misuse of these techniques against real users or systems without explicit written authorisation is **illegal** worldwide. Key legislation includes:

| Jurisdiction | Law | Relevant Provisions |
|---|---|---|
| USA | Computer Fraud and Abuse Act (CFAA) | Unauthorised access, fraud via computer |
| UK | Computer Misuse Act 1990 | Unauthorised access with intent to commit offences |
| EU | Directive on Attacks Against Information Systems | Illegal interception, system interference |

### 🇮🇳 Indian Laws

India has specific and strict provisions covering all techniques demonstrated in this tool:

**Information Technology Act, 2000 (IT Act) — as amended by IT (Amendment) Act, 2008**

| Section | Offence | Punishment |
|---|---|---|
| **Section 43** | Unauthorised access to computer systems, downloading data, introducing malware | Compensation up to ₹1 crore (civil liability) |
| **Section 66** | Computer-related offences — hacking, data theft | Imprisonment up to **3 years** and/or fine up to ₹5 lakh |
| **Section 66C** | Identity theft — fraudulently using electronic signature, password, or unique identification | Imprisonment up to **3 years** + fine up to ₹1 lakh |
| **Section 66D** | Cheating by impersonation using computer resources (directly covers phishing & spoofed URLs) | Imprisonment up to **3 years** + fine up to ₹1 lakh |
| **Section 70** | Unauthorised access to protected systems (government / critical infrastructure) | Imprisonment up to **10 years** |

**Indian Penal Code (IPC) / Bharatiya Nyaya Sanhita (BNS), 2023**

| Section (IPC / BNS) | Offence | Punishment |
|---|---|---|
| Section 419 IPC / Section 319 BNS | Cheating by impersonation | Imprisonment up to **3 years** and/or fine |
| Section 420 IPC / Section 318 BNS | Cheating and dishonestly inducing delivery of property (financial phishing) | Imprisonment up to **7 years** + fine |
| Section 468 IPC / Section 336 BNS | Forgery for purpose of cheating | Imprisonment up to **7 years** + fine |

**Key point for Indian users:** Section 66D IT Act specifically criminalises *"cheating by personation by using computer resource"* — this directly covers creating phishing pages using spoofed URLs, combo-squatted domains, or homograph lookalikes targeting Indian users or entities. Complaints can be filed with the **Cyber Crime Cell** (`cybercrime.gov.in`) or local police under the IT Act.

---

## 👤 Author

**Aryan Giri**

| Project | Description |
|---|---|
| [PhantomPath](https://giriaryan694-a11y.github.io/PhantomPath/) | URL obfuscation research tool (this repo) |
| [ARYPHISH_DETECTOR](https://github.com/giriaryan694-a11y/ARYPHISH_DETECTOR) | Multi-engine AI phishing detection — Openrouters + Gemini + ChatGPT + WHOIS + DuckDuckGo |

---

<div align="center">

*PhantomPath — know the attack to build the defence.*

</div>
