// SafeSignal analyzer — heuristic, fully-local suspicious-message explainer.
// No network, no storage, no external calls. Pure functions only.
// Usable in the browser (ES module) and in Node (for tests).
//
// analyzeMessage(text, { headers }) -> {
//   band: 'low' | 'caution' | 'high',
//   score: number,                 // 0..100 (capped), heuristic only
//   signals: [{ id, label, severity, weight, explanation, advice, evidence[] }],
//   positives: [string],           // reassuring (not proof of safety)
//   summary: string,
//   limitations: string[]
// }
//
// Design principle: explain WHY, never promise certainty. Bands describe how
// many scam hallmarks are present, not a guarantee either way.

const SUSPICIOUS_TLDS = [
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'country', 'gq', 'cf', 'tk',
  'ml', 'work', 'rest', 'quest', 'cam', 'sbs', 'lol', 'icu', 'kozow', 'loan',
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 't.ly', 'tiny.cc',
];

// Brands commonly impersonated — used only for look-alike/typosquat hints.
const COMMON_BRANDS = [
  'paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'google',
  'gmail', 'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp', 'dhl',
  'fedex', 'ups', 'usps', 'hsbc', 'emiratesnbd', 'adcb', 'fab', 'etisalat',
  'du', 'coinbase', 'binance', 'metamask', 'linkedin', 'steam',
];

function clampScore(n) { return Math.max(0, Math.min(100, Math.round(n))); }

// Extract URL-ish tokens from free text (handles http(s), www., and bare hosts).
function extractUrls(text) {
  const out = [];
  const re = /\b((?:https?:\/\/|www\.)[^\s<>()"']+|[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s<>()"']*)?)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    let raw = m[1].replace(/[),.;:!?'"]+$/, '');
    if (!/\.[a-z]{2,}/i.test(raw)) continue; // must contain a dotted TLD-ish part
    out.push(raw);
  }
  return [...new Set(out)];
}

function hostOf(url) {
  let u = url;
  if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return url.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  }
}

function registrableTail(host) {
  const parts = host.split('.');
  return parts.slice(-2).join('.');
}

// crude homoglyph / typosquat distance against a brand token
function looksLikeBrand(host) {
  const labels = normalizeConfusables(host).split('.');
  for (const brand of COMMON_BRANDS) {
    for (const label of labels) {
      if (label === brand) continue; // exact brand label is not itself suspicious here
      // normalize common homoglyph substitutions
      const norm = label
        .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
        .replace(/5/g, 's').replace(/\$/g, 's').replace(/rn/g, 'm');
      if (norm === brand) return brand;
      if (norm.length >= 4 && Math.abs(norm.length - brand.length) <= 2 && levenshtein(norm, brand) === 1) {
        return brand;
      }
      // brand embedded as a token but registrable domain is different.
      // Require brand length >= 5 for substring matching to avoid noise from
      // short brand tokens (e.g. "du", "ups") appearing inside ordinary words.
      if (brand.length >= 5 && (label.includes(brand) || norm.includes(brand)) && label !== brand) {
        return brand;
      }
    }
  }
  return null;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

function anyMatch(text, patterns) {
  const hits = [];
  for (const p of patterns) {
    const m = text.match(p);
    if (m) hits.push(m[0].trim());
  }
  return hits;
}

// Map common look-alike (homoglyph/confusable) characters to their ASCII twin.
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'қ': 'k',
  'һ': 'h', 'ԁ': 'd', 'ο': 'o', 'ɡ': 'g', 'ɩ': 'i',
  'ӏ': 'l', 'ᴏ': 'o', 'ɑ': 'a', 'ո': 'n',
};
function normalizeConfusables(s) {
  return [...String(s)].map((ch) => CONFUSABLES[ch] || ch).join('');
}

// Pull (displayText, href) pairs out of HTML anchors and markdown links so we
// can detect when the visible text claims one site but the link goes elsewhere.
function extractLinkPairs(raw) {
  const pairs = [];
  let m;
  const md = /\[([^\]]+)\]\(\s*((?:https?:\/\/|www\.)[^\s)]+)\s*\)/gi;
  while ((m = md.exec(raw)) !== null) pairs.push({ display: m[1], href: m[2] });
  const a = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  while ((m = a.exec(raw)) !== null) pairs.push({ display: m[2].replace(/<[^>]+>/g, '').trim(), href: m[1] });
  return pairs;
}

export function analyzeMessage(text, opts = {}) {
  const headers = opts.headers || '';
  const raw = String(text || '');
  const lc = raw.toLowerCase();
  const signals = [];
  const positives = [];

  const add = (s) => signals.push(s);

  // 0) Hidden / zero-width characters (used to split keywords and dodge filters)
  if (/[​-‍⁠﻿]/.test(raw)) {
    add({
      id: 'hidden-characters', label: 'Hidden zero-width characters present', severity: 'medium', weight: 12,
      explanation: 'Invisible characters are inserted to break up scam keywords (e.g. "pass​word") so filters miss them, or to disguise a web address. Legitimate messages rarely contain them.',
      advice: 'Treat the message as deliberately evasive. Do not act on it without verifying through a trusted channel.',
      evidence: ['Zero-width or invisible characters detected in the text.'],
    });
  }

  // 1) Urgency / pressure / threats
  const urgency = anyMatch(lc, [
    /act now/, /immediately/, /within \d+ ?(hours|hrs|days|minutes)/, /final (notice|warning|reminder)/,
    /account (will be|has been) (suspended|locked|closed|disabled|terminated)/, /urgent/, /right away/,
    /avoid (suspension|closure|deactivation)/, /failure to (respond|comply|verify)/, /last chance/,
    /your account is on hold/, /unusual (activity|sign.?in|login)/,
  ]);
  if (urgency.length) {
    add({
      id: 'urgency', label: 'Pressure and urgency language', severity: 'medium', weight: 18,
      explanation: 'Scams rush you so you act before thinking. Real organisations rarely demand action in minutes/hours or threaten instant account loss.',
      advice: 'Slow down. Do not use links in the message — reach the organisation through a channel you already trust.',
      evidence: urgency.slice(0, 4),
    });
  }

  // 2) Credential / verification / payment requests
  const credReq = anyMatch(lc, [
    /verify your (account|identity|information|details)/, /confirm your (password|account|identity|details|payment)/,
    /update your (payment|billing|card|account)/, /re-?enter your (password|pin|card)/, /log ?in to (verify|confirm|restore)/,
    /provide your (password|pin|otp|one.?time|cvv|card number|ssn|emirates id)/, /enter your (password|pin|otp|card)/,
    /validate your account/, /confirm your billing/,
  ]);
  if (credReq.length) {
    add({
      id: 'credential-request', label: 'Asks you to confirm a password, card, OTP, or ID', severity: 'high', weight: 28,
      explanation: 'Legitimate providers do not ask you to confirm passwords, full card numbers, PINs, OTPs or ID numbers by email or SMS. This is how credentials get stolen.',
      advice: 'Never enter these from a message link. Type the official website address yourself, or use the official app.',
      evidence: credReq.slice(0, 4),
    });
  }

  // 2b) Link text vs real destination mismatch (HTML/markdown links)
  const mismatches = [];
  for (const { display, href } of extractLinkPairs(raw)) {
    const dMatch = display.match(/((?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
    if (!dMatch) continue;
    const dTail = registrableTail(hostOf(dMatch[1]));
    const hTail = registrableTail(hostOf(href));
    if (dTail && hTail && dTail !== hTail) {
      mismatches.push(`shows "${display.trim()}" but the link actually goes to ${hostOf(href)}`);
    }
  }
  if (mismatches.length) {
    add({
      id: 'link-mismatch', label: 'Link text does not match its real destination', severity: 'high', weight: 28,
      explanation: 'The clickable text shows one website while the link leads somewhere else. This is a classic trick to send you to a fake login page that looks official.',
      advice: 'Do not click. The visible name is not where the link leads. Open the real site yourself instead.',
      evidence: mismatches.slice(0, 4),
    });
  }

  // 3) URL risks
  const urls = extractUrls(raw);
  const urlEvidence = [];
  let urlWeight = 0;
  for (const url of urls) {
    const host = hostOf(url);
    const tail = registrableTail(host);
    const tld = host.split('.').pop();
    const notes = [];
    if (/^xn--/.test(host) || host.split('.').some((l) => l.startsWith('xn--'))) notes.push('uses punycode / an internationalised domain (can hide look-alike characters)');
    if (/[^\x00-\x7F]/.test(host)) notes.push('contains non-Latin look-alike characters (possible homograph spoof)');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) notes.push('is a raw IP address, not a named site');
    if (/@/.test(url.replace(/^https?:\/\//, ''))) notes.push('contains "@", which can disguise the real destination');
    if (URL_SHORTENERS.includes(tail)) notes.push('is a link shortener that hides the real destination');
    if (SUSPICIOUS_TLDS.includes(tld)) notes.push(`ends in ".${tld}", a domain ending frequently abused by scams (heuristic)`);
    if (host.split('.').length >= 5) notes.push('has an unusually long chain of subdomains');
    if (/^http:\/\//i.test(url)) notes.push('is not using HTTPS');
    const brand = looksLikeBrand(host);
    if (brand) notes.push(`resembles "${brand}" but is not that company’s real domain`);
    if (notes.length) {
      urlEvidence.push(`${url} — ${notes.join('; ')}`);
      urlWeight += Math.min(26, 8 + notes.length * 6 + (brand ? 10 : 0));
    }
  }
  if (urlEvidence.length) {
    add({
      id: 'risky-links', label: 'Link looks disguised or impersonating', severity: 'high', weight: Math.min(32, urlWeight),
      explanation: 'The destination of a link is the clearest tell. Look-alike domains, shorteners, raw IPs and punycode are used to send you to a fake login page.',
      advice: 'Hover to preview a link before clicking; better, do not click — navigate to the site yourself.',
      evidence: urlEvidence.slice(0, 5),
    });
  } else if (urls.length) {
    positives.push('Links present did not match common disguise patterns (not a guarantee they are safe).');
  }

  // 4) Gift-card / crypto / wire lures
  const payLure = anyMatch(lc, [
    /gift ?cards?/, /google play card/, /steam card/, /itunes card/, /bitcoin|btc|usdt|crypto(currency)?/,
    /wire transfer/, /western union/, /moneygram/, /send (money|payment) to/, /pay a (fee|fine) to release/,
  ]);
  if (payLure.length) {
    add({
      id: 'payment-lure', label: 'Unusual payment method (gift cards, crypto, wire)', severity: 'high', weight: 22,
      explanation: 'Requests to pay via gift cards, crypto or wire transfer are a hallmark of scams because these payments are hard to reverse or trace.',
      advice: 'No legitimate company, tax authority or boss collects payment in gift cards or crypto. Treat it as a scam.',
      evidence: payLure.slice(0, 4),
    });
  }

  // 4b) "Call this number" vishing (fake-charge / tech-support / refund scams)
  const phoneRe = /\+?\d[\d\s().-]{6,}\d/;
  const callbackCtx = /charged|subscription|renew(ed|al|s)?|auto-?renew|refund|invoice|to cancel|cancel (?:your|this|the)|call (?:this|the|our|us|now|immediately|toll)|support (?:team|line|number)|antivirus|norton|mcafee|geek squad/i;
  const phoneHit = raw.match(phoneRe);
  if (phoneHit && callbackCtx.test(lc)) {
    add({
      id: 'callback-scam', label: 'A phone number plus a charge / refund hook', severity: 'medium', weight: 18,
      explanation: 'Fake-charge, "your subscription renewed", and tech-support scams push you to phone a number so a person can pressure you in real time. The number belongs to the scammer, not the company.',
      advice: 'Do not call numbers from unexpected messages. If worried about a charge, use the official number on your card, app, or a receipt you already trust.',
      evidence: [phoneHit[0].trim(), (lc.match(callbackCtx) || [''])[0]].filter(Boolean),
    });
  }

  // 5) Prize / lottery / inheritance / job-bait
  const lure = anyMatch(lc, [
    /you(?:'| ha)?ve won/, /congratulations[.! ]/, /claim your (prize|reward|refund)/, /lottery/, /inheritance/,
    /beneficiary/, /you have been selected/, /work from home .*(\$|aed|usd)/, /earn \$?\d+ ?(per|a|\/) ?(day|week|hour)/,
    /tax refund/, /parcel (is )?(waiting|held|on hold)/, /delivery (failed|attempt)/, /customs (fee|charge)/,
  ]);
  if (lure.length) {
    add({
      id: 'too-good-or-bait', label: 'Prize, refund, or delivery bait', severity: 'medium', weight: 16,
      explanation: 'Unexpected winnings, refunds, or "held parcel" messages are classic hooks to get you to click or pay a small "fee".',
      advice: 'If you did not enter or order, you did not win or miss a delivery. Verify with the courier/retailer directly.',
      evidence: lure.slice(0, 4),
    });
  }

  // 6) Attachment risk (mentioned file types)
  const attach = anyMatch(lc, [
    /\.(exe|scr|js|jar|bat|cmd|msi|vbs|ps1)\b/, /\.(docm|xlsm|pptm)\b/, /enable (macros|editing|content)/,
    /\.(html?|svg) attachment/, /open the attached (invoice|document|file|receipt)/,
  ]);
  if (attach.length) {
    add({
      id: 'attachment-risk', label: 'Risky attachment or "enable macros" request', severity: 'high', weight: 22,
      explanation: 'Executable files (.exe, .scr, .js), macro-enabled Office docs, and HTML attachments are common malware carriers. "Enable macros/content" is a red flag.',
      advice: 'Do not open unexpected attachments or enable macros. Confirm with the sender through a separate channel.',
      evidence: attach.slice(0, 4),
    });
  }

  // 7) Generic / impersonal greeting
  const generic = anyMatch(lc, [/dear (customer|user|client|account holder|member|sir\/madam)/, /valued customer/]);
  if (generic.length) {
    add({
      id: 'generic-greeting', label: 'Generic, impersonal greeting', severity: 'low', weight: 6,
      explanation: 'Mass scam emails often cannot address you by name. On its own this is weak, but it adds up with other signs.',
      advice: 'Treat as a minor hint; weigh it with the stronger signals above.',
      evidence: generic.slice(0, 2),
    });
  }

  // 8) Header checks (only if raw headers pasted)
  if (headers) {
    const h = headers.toLowerCase();
    const from = (h.match(/^from:.*$/m) || [''])[0];
    const replyTo = (h.match(/^reply-to:.*$/m) || [''])[0];
    const fromDom = (from.match(/@([a-z0-9.-]+)/) || [,''])[1];
    const replyDom = (replyTo.match(/@([a-z0-9.-]+)/) || [,''])[1];
    if (fromDom && replyDom && registrableTail(fromDom) !== registrableTail(replyDom)) {
      add({
        id: 'replyto-mismatch', label: 'Reply-To domain differs from From domain', severity: 'medium', weight: 16,
        explanation: 'Replies would go to a different domain than the apparent sender — a common spoofing setup.',
        advice: 'Be cautious: the visible sender may be forged. Verify via a known-good contact.',
        evidence: [from.trim(), replyTo.trim()].filter(Boolean),
      });
    }
    if (/dmarc=fail|spf=fail|dkim=fail/.test(h)) {
      add({
        id: 'auth-fail', label: 'Email authentication failed (SPF/DKIM/DMARC)', severity: 'high', weight: 20,
        explanation: 'The message failed sender-authentication checks, meaning the "From" address may be forged.',
        advice: 'Do not trust the sender identity. Treat links and requests as hostile.',
        evidence: anyMatch(h, [/dmarc=fail/, /spf=fail/, /dkim=fail/]),
      });
    }
  }

  // ---- Scoring ----
  let score = signals.reduce((a, s) => a + s.weight, 0);
  // small synergy bump when a credential/link request co-occurs with urgency
  const ids = new Set(signals.map((s) => s.id));
  if ((ids.has('credential-request') || ids.has('risky-links')) && ids.has('urgency')) score += 8;
  score = clampScore(score);

  // Band logic: 'high' when the score is high, OR any single high-severity
  // signal from the critical set is present, OR two+ high-severity signals stack.
  const CRITICAL_HIGH = new Set([
    'credential-request', 'risky-links', 'payment-lure', 'attachment-risk', 'auth-fail', 'link-mismatch',
  ]);
  const highSev = signals.filter((s) => s.severity === 'high');
  let band = 'low';
  if (score >= 55 || highSev.some((s) => CRITICAL_HIGH.has(s.id)) || highSev.length >= 2) band = 'high';
  else if (score >= 20) band = 'caution';

  const summary = {
    low: 'No strong scam hallmarks detected. Stay cautious — absence of signals is not proof it is safe.',
    caution: 'Some warning signs are present. Treat requests and links with care and verify independently.',
    high: 'Multiple strong scam hallmarks detected. Treat this as likely malicious: do not click, reply, pay, or share any details.',
  }[band];

  const limitations = [
    'This is a heuristic explainer, not a verdict. It can miss novel or well-crafted scams (false negatives) and occasionally flag legitimate messages (false positives).',
    'It cannot verify who really sent a message, scan live links, or open attachments. It only reads the text/headers you paste.',
    'Everything runs locally in your browser: nothing you paste is sent anywhere, stored, or logged.',
    'When unsure, verify through a channel you already trust (official app, a number from the back of your card, the organisation’s known website typed by hand).',
  ];

  // Show the most serious signals first.
  const rank = { high: 3, medium: 2, low: 1 };
  signals.sort((a, b) => rank[b.severity] - rank[a.severity]);

  return { band, score, signals, positives, summary, limitations };
}

export const _internals = { extractUrls, hostOf, looksLikeBrand, levenshtein, SUSPICIOUS_TLDS, URL_SHORTENERS };
