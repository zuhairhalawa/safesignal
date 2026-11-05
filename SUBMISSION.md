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
Paste an email/SMS (and optionally raw headers). SafeSignal returns an honest band — Low signal / Caution / Likely scam — leads with a plain **recommended action**, and lists the specific signals it found (most serious first): urgency/threats, password/OTP/card requests, **link text that doesn't match its real destination**, disguised/look-alike and **homograph** links, direct money requests, gift-card/crypto demands, **arrest/fine threats**, **"bank details changed" (BEC)**, **"read back the code we sent" (reverse-OTP)**, **"call this number" vishing**, prize/job/parcel bait, risky attachments, **hidden zero-width characters**, and (from headers) Reply-To mismatch and SPF/DKIM/DMARC failures. Each signal explains *why* it's suspicious and *what to do*, with the exact evidence shown. The detector set was hardened across two adversarial QA passes over 25 realistic scam types (42 automated tests pass).

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

---

## Demo video script (~2–2.5 min, optional but encouraged)
Record your screen running the tool locally (`python -m http.server 8077` → `http://localhost:8077/`).

1. **(0:00–0:20) Problem.** "The riskiest moment online is the message you hesitate to click. SafeSignal explains what's suspicious — and keeps your message private." Show the input screen; point out the "Private by design: nothing leaves your browser" badge.
2. **(0:20–0:55) Scam demo.** Click **Account "suspended"**. Walk through the result: the **Likely scam** verdict, the red recommended-action box, then 2–3 signals — the disguised `paypa1-secure.top` link, the credential request, and (from the headers) the SPF/DKIM/DMARC failure. Stress each one says *why* and *what to do*.
3. **(0:55–1:25) It isn't just a filter.** Paste a realistic one that isn't an example — e.g. `Our bank account details have changed, please pay the invoice to the new account below.` Show it catches the **BEC** pattern. Then paste a reverse-OTP line (`read back the 6-digit code we just sent`) to show account-takeover detection.
4. **(1:25–1:50) Honest, not alarmist.** Click **A normal message**: **Low signal**, with the explicit "absence of signals is not proof it is safe" caveat. Mention it correctly leaves a legitimate "beware of scams" bank notice alone (no keyword-gaming).
5. **(1:50–2:20) Trust & limits.** Open the network tab briefly — no requests. Read the limitations panel. "It's a heuristic learning aid, not a guarantee — and it says so."
6. Close on the privacy point: everything ran locally; nothing was uploaded.

Keep it calm and concrete. Judges reward honest limitations over hype.

## Push the repo (owner steps — needs your GitHub account)
The project is already a local git repo with commits under your identity. To publish:

```bash
cd C:/Users/ZUHAIR/Projects/Bounty-CTF/safespace
gh repo create safesignal --public --source=. --remote=origin --push
```

Or without the `gh` CLI: create an empty public repo named `safesignal` on github.com, then:

```bash
cd C:/Users/ZUHAIR/Projects/Bounty-CTF/safespace
git remote add origin https://github.com/zuhairhalawa/safesignal.git
git branch -M main
git push -u origin main
```

Paste that repo URL into the Devpost "Try it out" field.

## Final pre-submit checklist
- [ ] Eligibility confirmed: current student + UAE legal age of majority + no geographic exclusion (see top of this file).
- [ ] `node --test` → **42 passing** on your machine.
- [ ] App opens at `http://localhost:8077/` and the three example buttons work.
- [ ] Repo pushed and public; URL added to Devpost.
- [ ] Project page filled from the fields above; `screenshots/01–03` uploaded.
- [ ] Credits section includes the AI-assistance disclosure (accurate — do not remove).
- [ ] Submitted before **Nov 22, 17:00 US-Eastern** (Nov 23, 02:00 Asia/Dubai); judging links stay live through Nov 24.
