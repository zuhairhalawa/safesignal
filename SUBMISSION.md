# SafeSpace Hacks — submission package (ready to paste)

Everything below is drafted for the Devpost project page. The **build is complete and tested**; what remains are owner-only steps (account + submit) and two eligibility confirmations. Submit deadline: **Nov 22, 2026, 5:00 PM US Eastern** (= Nov 23, 02:00 Asia/Dubai).

---

## ⚠ Before you submit — confirm these (I must not assume personal/legal facts)
1. **You are a current student** at a recognized educational institution (the rules require it). ✔ you're a CS student — just confirm still enrolled.
2. **You meet the legal age of majority in the UAE.** The rules require "above the legal age of majority in your country of residence." UAE majority can be read as 21 (Gregorian) under the Civil Transactions Law in some contexts; confirm you qualify before entering. *(Only you can attest to this — don't submit if unsure.)*
3. **Geographic eligibility:** the rules say eligibility is "under the geographic requirements shown on this site." Nothing I read excludes the UAE, but skim the Devpost rules once for any country list before submitting.
4. The submission attests the work is yours and the AI-assistance disclosure is accurate — both are true as written here. Don't alter them to hide assistance.

## Owner-only steps (I cannot create accounts or sign in)
- [ ] Create/sign in to your Devpost account; click **Join hackathon** on https://safespace-hacks.devpost.com/
- [ ] Create a project, paste the fields below, upload screenshots from `screenshots/`, add the demo + repo links.
- [ ] Push the `safespace/` folder to a public repo (GitHub) and paste the link, OR attach it as a downloadable build.
- [ ] Submit one final entry before the deadline; keep all links live through Nov 24.

---

## Devpost fields (copy-paste)

**Project name:** SafeSignal

**Elevator pitch (≤ 200 chars):**
> A 100%-local explainer for suspicious emails and texts. Paste a message; it names the scam warning signs in plain language and tells you what to do — without sending your message anywhere.

**Built with:** `javascript`, `html`, `css`, `node.js` (testing), `heuristics`, `privacy-by-design`, `no-backend`

**Try it out:**
- Repo: *(your public repo URL)*
- Run locally: `cd safespace && python -m http.server 8077` → open `http://localhost:8077/`

### About the project

**Inspiration**
The riskiest moment in everyday digital life is the message you hesitate to click. Non-experts can't easily tell a scam from a real message, generic advice ("be careful") doesn't help, and pasting private messages into online checkers leaks them. I wanted a tool that *teaches* the warning signs on the spot and keeps the message private.

**What it does**
Paste an email/SMS (and optionally raw headers). SafeSignal returns an honest band — Low signal / Caution / Likely scam — leads with a plain **recommended action**, and lists the specific signals it found (most serious first): urgency/threats, password/OTP/card requests, **link text that doesn't match its real destination**, disguised/look-alike and **homograph** links, gift-card/crypto demands, **"call this number" vishing**, prize/parcel bait, risky attachments, **hidden zero-width characters**, and (from headers) Reply-To mismatch and SPF/DKIM/DMARC failures. Each signal explains *why* it's suspicious and *what to do*, with the exact evidence shown.

**How I built it**
Pure client-side JavaScript. The detection engine (`analyzer.js`) is one source of truth used by both the UI (`index.html`) and an automated test suite (`node --test`, 12 tests). No frameworks, no backend, no network calls — privacy is enforced by architecture, not by a promise.

**Challenges**
Calibrating heuristics to be useful without crying wolf: a lone macro-malware attachment or a spoofed-header message must rank High, while a legitimate real-brand link must stay Low. I encoded that as a principled band rule (critical high-severity signals, or score threshold, or stacked signals) and pinned it with tests, including explicit no-false-positive cases for brand look-alike detection.

**Accomplishments**
A working, tested prototype that is genuinely private, explains its reasoning, and is honest about its limits — complexity kept low on purpose so the core workflow is reliable.

**What I learned**
How specific, explained signals beat a single "risk %"; and how much of trustworthy safety tooling is about *honest framing* (absence of signals ≠ safe) rather than detection cleverness.

**What's next**
More languages, a browser-extension packaging, and an optional offline model for nuance — kept local to preserve privacy.

### One safer outcome & one limitation (required by the rules)
- **Safer outcome:** A user who gets "Your PayPal account is suspended — verify within 24 hours: http://paypa1-secure.top/login" sees it flagged Likely scam, with the look-alike domain and credential-request named, and is told to reach PayPal through the official app instead of clicking.
- **Limitation:** It's a heuristic learning aid. It can miss a well-crafted scam and occasionally over-flag a legitimate message; it cannot verify a sender or scan a live link. It is not a replacement for your provider's security or for emergency services.

### Credits / AI disclosure (keep accurate)
Original first-party work built during the event window. Built with AI assistance (an AI coding assistant helped with design, implementation, and tests); all code was reviewed and is original to this project. No third-party code or datasets bundled. MIT-licensed.

### Screenshots to upload (in `screenshots/`)
- `01-input.jpg` — the private-by-design input screen
- `02-result-scam.jpg` — a phishing message explained (Likely scam)
- `03-result-low.jpg` — a normal message correctly kept Low signal
