# SafeSignal

**Understand a suspicious message before you act on it.** Paste an email or SMS and SafeSignal explains, in plain language, the specific scam warning signs it contains — and what to do. It runs **100% locally in your browser**: nothing you paste is sent anywhere, stored, or logged.

Built for **SafeSpace Hacks 2026** (online, Oct 17 – Nov 22 2026).

---

## The problem
The riskiest moment in everyday digital life is the message you *hesitate* to click — the "your account is suspended" email, the "I need gift cards" text from your "boss," the "parcel on hold, pay a fee" SMS. Non-experts often can't tell a scam from a real message, and the safety advice they find is either too vague ("be careful") or too technical. Pasting the message into an online "checker" can also leak private content.

## The solution
SafeSignal is a **local-only explainer**. For a pasted message (and optionally raw email headers), it:
- gives an honest verdict band — **Low signal / Caution / Likely scam** — with a heuristic signal score;
- lists the **specific** warning signs it found, each with *why it's suspicious* and *what to do*;
- shows the exact evidence (the urgency phrase, the disguised link, the gift-card request);
- is explicit about what it **cannot** do, so it never gives false confidence.

The intended user is an everyday person; the safer outcome is that they understand the risk and take a safe next step (don't click, verify through a trusted channel) instead of guessing.

## What it detects (heuristics, explained to the user)
- Urgency / pressure / account-threat language
- Requests to confirm passwords, cards, OTPs, PINs, or ID numbers
- **Link text that doesn't match its real destination** (HTML/markdown links)
- Disguised links: look-alike/typosquatted brand domains, link shorteners, raw-IP URLs, punycode, `@` tricks, abused TLDs, non-HTTPS
- **Homograph / internationalised look-alike domains** (non-Latin characters that imitate a real brand)
- **Disguised / defanged addresses** (`paypal[.]com`, `paypal dot com`, `hxxp://`) — de-obfuscated and flagged
- **Direct requests to send money / cash / a transfer** (even without a named method)
- Unusual payment demands (gift cards, wire, and crypto — BTC/ETH/USDT/etc. and "send X get Y back" giveaways)
- **"Guaranteed returns" investment fraud** ("double your money", "25% monthly", risk-free)
- **Threats of arrest, legal action, or fines** (tax/police/court impersonation)
- **Service-cutoff threats** (utility/telecom "pay or be disconnected")
- **"Our bank details have changed"** invoice / business-email-compromise
- **"Read back the code we sent you"** reverse-OTP account-takeover
- **QR-code "quishing"** (scan-to-verify / scan-to-pay)
- **"Call this number" vishing** (fake-charge / tech-support / refund / unauthorized-payment scams)
- Prize / refund / job / "held parcel" bait (weighted so a bare "congrats" doesn't over-flag)
- Risky attachments and "enable macros" requests
- **Hidden zero-width characters** used to split keywords and dodge filters
- Generic impersonal greetings
- (With headers) Reply-To vs From mismatch and SPF/DKIM/DMARC failures

Results lead with a plain **recommended action** keyed to the verdict, and signals are ordered most-serious first.

## Trust & responsible design
- **Private by design:** pure client-side JavaScript. No network requests, no analytics, no storage. You can verify this by reading `index.html` / `analyzer.js` or watching the network tab (it stays empty).
- **Honest, not alarmist:** a clean message returns "Low signal" with the explicit caveat that absence of signals is **not** proof of safety. The tool states its limits prominently.
- **No new risk:** it never asks you to log in, click out, or share anything.

## Run it
It's a static site — any static server works (local modules need an `http://` origin, not `file://`):

```bash
cd safespace
python -m http.server 8077
```

Then open `http://localhost:8077/`. Use the built-in example buttons, or paste your own message.

## Tests
Detection logic lives in `analyzer.js` (one source of truth, used by both the UI and the tests). Run:

```bash
cd safespace
node --test
```

42 tests pass. Synthetic scam samples cover phishing, gift-card, parcel, macro-malware, spoofed headers, link-mismatch, homograph and defanged/obfuscated domains, direct money requests, crypto giveaways, "guaranteed returns" investment fraud, arrest/fine threats, utility service-cutoff threats, BEC "bank details changed", reverse-OTP, QR quishing, vishing, and job/task bait — all rank Caution/High. Synthetic legitimate samples — order confirmation, appointment reminder, real-brand links, matching link text, password-reset to a real domain, a bank spend-alert, a real one-time-code message, "congratulations on your order", and an anti-scam PSA — stay Low and are explicitly guarded against false positives. Plus unit tests for URL extraction, brand look-alike detection, score bounds, and severity ordering. All samples are **synthetic / author-created** — no real personal data, per the event rules.

The tool was hardened across **two adversarial QA passes** (25 realistic scam archetypes + 13 legitimate messages); every case is now classified correctly.

## Limitations (honest)
- Heuristic, not a verdict engine: it can miss novel/well-crafted scams (false negatives) and occasionally flag legitimate messages (false positives).
- It cannot verify who really sent a message, scan live links, or open attachments — it only reads the text/headers you paste.
- It is a learning aid, **not** a replacement for your provider's security tools or for emergency services.

## Credits & AI-assistance disclosure
Original first-party work, created during the event window (Oct 17 – Nov 22 2026). Built **with AI assistance** (an AI coding assistant helped with design, implementation, and tests); all code was reviewed and is original to this project. No third-party code or datasets are bundled.

## License
MIT — see [LICENSE](LICENSE).
